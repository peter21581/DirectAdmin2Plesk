#!/bin/bash

[ $EUID -ne 0 ] && { echo "This script must be run as root. Exiting..."; exit 1; }
command -v plesk &>/dev/null || { echo "Plesk not found. Exiting..."; exit 1; }

command -v sshpass &>/dev/null || {
    echo "sshpass not found. Installing..."
    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y sshpass
    elif command -v yum &>/dev/null; then
        yum install -y sshpass
    elif command -v dnf &>/dev/null; then
        dnf install -y sshpass
    else
        echo "Please install sshpass manually. Exiting..."
        exit 1
    fi
}

echo "Preparing for DirectAdmin migration to Plesk."
read -p "Enter DirectAdmin SSH IP: " da_ip
read -p "Enter DirectAdmin SSH user: " da_user
read -sp "Enter DirectAdmin SSH password: " da_pass; echo
read -p "Enter DirectAdmin SSH port [22]: " da_port
da_port=${da_port:-22}
read -p "Is this a CloudLinux server? [y/n]: " da_cl

echo -e "\nConfirm Details:\nDirectAdmin SSH IP: $da_ip\nDirectAdmin SSH User: $da_user\nDirectAdmin SSH Port: $da_port\nIs this a CloudLinux server? $da_cl"
read -p "Are these correct? [y/n]: " da_confirm

[[ ! "$da_confirm" =~ ^[Yy]$ ]] && { echo "Please retry with correct details."; exit 1; }

# Test SSH login
echo "Testing SSH login to DirectAdmin server..."
sshpass -p "$da_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $da_port $da_user@$da_ip "echo 'SSH login successful.'"
if [ $? -ne 0 ]; then
    echo "Error: Unable to SSH into the DirectAdmin server. Please check the provided details and try again."
    exit 1
fi

sshpass -p "$da_pass" ssh -T -p $da_port $da_user@$da_ip <<EOF
echo -e "[client]\nuser=da_admin\npassword=\$(awk -F'=' '/^passwd/{print \$2}' /usr/local/directadmin/conf/mysql.conf)\nsocket=/var/lib/mysql/mysql.sock" > /root/.my.cnf;
innodb_mode=\$(mysql -e "SHOW VARIABLES LIKE 'innodb_strict_mode';" | grep -c "OFF")
[ "\$innodb_mode" -eq 0 ] && { echo "innodb_strict_mode=0" >> /etc/my.cnf || echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf && service mariadb restart; }
user=\$(awk -F= '/user=/ {print \$2}' /usr/local/directadmin/conf/my.cnf)
pass=\$(awk -F= '/password=/ {gsub(/"/,"",\$2); print \$2}' /usr/local/directadmin/conf/my.cnf)
mysql -e "GRANT ALL ON *.* TO '\$user'@'127.0.0.1' IDENTIFIED BY '\$pass' WITH GRANT OPTION; FLUSH PRIVILEGES;"
[[ "$da_cl" == "y" ]] && cat /etc/redhat-release
EOF

# Start the new integration
sshpass -p "$da_pass" ssh -T -p $da_port $da_user@$da_ip <<EOF
# Ensure directadmin command is available
if ! command -v /usr/local/directadmin/directadmin &>/dev/null; then
    echo "Error: DirectAdmin command not found."
    exit 1
fi

MYSQLCONF_VALUE=\$(/usr/local/directadmin/directadmin c | grep mysqlconf)

# Check if mysqlconf or mysql_conf exist in directadmin.conf
if ! grep -q "mysqlconf" /usr/local/directadmin/conf/directadmin.conf && \
   ! grep -q "mysql_conf" /usr/local/directadmin/conf/directadmin.conf; then
    echo "\$MYSQLCONF_VALUE" >> /usr/local/directadmin/conf/directadmin.conf
    MYSQL_CONF_VALUE="mysql_conf=\$(echo "\$MYSQLCONF_VALUE" | cut -d'=' -f2)"
    echo "\$MYSQL_CONF_VALUE" >> /usr/local/directadmin/conf/directadmin.conf
fi

# Extract path of mysql.conf from directadmin command output
MYSQL_CONF_PATH=\$(/usr/local/directadmin/directadmin c | awk -F'=' '/mysqlconf/{print \$2}')

# Extract password from the determined mysql.conf path
DA_ADMIN_PASSWD=\$(awk -F'=' '/^passwd/{print \$2}' "\$MYSQL_CONF_PATH")

# Grant permissions to da_admin for both localhost (IPv4) and ::1 (IPv6)
mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'da_admin'@'localhost' IDENTIFIED BY '\$DA_ADMIN_PASSWD'; FLUSH PRIVILEGES;"
mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'da_admin'@'::1' IDENTIFIED BY '\$DA_ADMIN_PASSWD'; FLUSH PRIVILEGES;"

# Testing if the da_admin user can log in using the extracted password and retrieve the innodb_strict_mode variable
TEST_RESULT=\$(mysql -h localhost -P 3306 -uda_admin -p"\$DA_ADMIN_PASSWD" --silent --skip-column-names -e 'SHOW VARIABLES LIKE "innodb_strict_mode"')

# Check and output the result
if [ -z "\$TEST_RESULT" ]; then
    echo "Error: Unable to retrieve innodb_strict_mode using the da_admin user and extracted password."
else
    echo "Successfully retrieved innodb_strict_mode: \$TEST_RESULT"
fi

# Add Plesk Migrator to SSHD
echo "AllowUsers plesk-migrator-*" >> /etc/ssh/sshd_config && service sshd restart;

EOF
# End the new integration

plesk bin extension --uninstall panel-migrator
plesk bin extension --install panel-migrator
echo -e "[client]\nuser=admin\npassword=$(cat /etc/psa/.psa.shadow)\nsocket=/var/lib/mysql/mysql.sock" > /root/.my.cnf

download_files() {
    base_url="https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source"
    wget -qO "$1/backend/lib/python/parallels/plesk/source/custom/connections.py" "$base_url/custom/connections.py"
    wget -qO "$1/backend/lib/python/parallels/plesk/source/custom/actions/deploy_migrator_python.py" "$base_url/custom/deploy_migrator_python.py"
    wget -qO "$1/backend/lib/python/parallels/plesk/source/directadmin/agent/dumper.py" "$base_url/directadmin/agent/dumper.py"
    wget -qO "$1/backend/lib/python/parallels/core/utils/os_version.py" "$base_url/os_version.py"
}

if [ -d "/usr/local/psa/admin/plib/modules/panel-migrator" ]; then
    path_migrator="/usr/local/psa/admin/plib/modules/panel-migrator"
    download_files "$path_migrator"
elif [ -d "/opt/psa/admin/plib/modules/panel-migrator" ]; then
    path_migrator="/opt/psa/admin/plib/modules/panel-migrator"
    download_files "$path_migrator"
fi

innodb_mode_check=$(plesk db "SHOW VARIABLES LIKE 'innodb_strict_mode';" | grep -c "OFF")
[ "$innodb_mode_check" -eq 0 ] && { echo "innodb_strict_mode=0" >> /etc/my.cnf || echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf && service mariadb restart; }

echo "Migration preparation is complete."