#!/bin/bash

# Check if sshpass is installed
if ! command -v sshpass &>/dev/null; then
    echo "sshpass not found. Trying to install it..."

    # Determine package manager and try to install sshpass
    if command -v apt-get &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y sshpass
    elif command -v yum &>/dev/null; then
        sudo yum install -y sshpass
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y sshpass
    else
        echo "Could not find a package manager to install sshpass. Please install it manually."
        exit 1
    fi
f

# 1. Inform the user about the impending migration
echo "Preparing for migration from DirectAdmin to Plesk..."

# 2. Prompt user for DirectAdmin SSH details
read -p "Enter DirectAdmin SSH Server IP: " da_ssh_ip
read -p "Enter DirectAdmin SSH User: " da_ssh_user
read -s -p "Enter DirectAdmin SSH Password: " da_ssh_pass
echo
read -p "Enter DirectAdmin SSH Port (default: 22): " da_ssh_port
da_ssh_port=${da_ssh_port:-22}

# 3. Execute the following commands on the DirectAdmin server via SSH
sshpass -p "$da_ssh_pass" ssh -p $da_ssh_port $da_ssh_user@$da_ssh_ip << EOF
echo -e "[client]\nuser=da_admin\npassword=\$(grep "^passwd=" /usr/local/directadmin/conf/mysql.conf | cut -d= -f2)\nsocket=/var/lib/mysql/mysql.sock" > /root/.my.cnf;
innodb_status=\$(mysql -NBe "SHOW VARIABLES LIKE 'innodb_strict_mode';" | awk '{print $2}')
if [[ "$innodb_status" != "OFF" && "$innodb_status" != "0" ]]; then
    (echo "innodb_strict_mode=0" >> /etc/my.cnf) || (echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf) && service mariadb restart;
fi
user=\$(awk -F= '/user=/ {print \$2}' /usr/local/directadmin/conf/my.cnf)
pass=\$(awk -F= '/password=/ {gsub(/"/,"",\$2); print \$2}' /usr/local/directadmin/conf/my.cnf)
mysql -e "GRANT ALL PRIVILEGES ON *.* TO '\$user'@'127.0.0.1' IDENTIFIED BY '\$pass' WITH GRANT OPTION; FLUSH PRIVILEGES;"
grep -q "mysqlconf" /usr/local/directadmin/conf/directadmin.conf || { [ -f /usr/local/directadmin/conf/mysql.conf ] && echo "mysqlconf=/usr/local/directadmin/conf/mysql.conf" >> /usr/local/directadmin/conf/directadmin.conf; }
EOF

# 4. Test if "mysqlconf" exists in the DirectAdmin configuration
sshpass -p "$da_ssh_pass" ssh -p $da_ssh_port $da_ssh_user@$da_ssh_ip grep "mysqlconf" /usr/local/directadmin/conf/directadmin.conf

# 5. Test MySQL login and check if innodb_strict_mode is off
sshpass -p "$da_ssh_pass" ssh -p $da_ssh_port $da_ssh_user@$da_ssh_ip << EOF
mysql -u\$user -p\$pass -h 127.0.0.1 -e "SHOW VARIABLES LIKE 'innodb_strict_mode';"
EOF

# 6. Exit from DirectAdmin server (this is implicitly handled by ending the SSH session)

# 7. Continue on the current server (localhost)
plesk bin extension --uninstall panel-migrator
plesk bin extension --install panel-migrator
echo -e "[client]\nuser=admin\npassword=\$(cat /etc/psa/.psa.shadow)\nsocket=/var/lib/mysql/mysql.sock" > /root/.my.cnf

if [ -d "/usr/local/psa/admin/plib/modules/panel-migrator" ]; then
    wget -O /usr/local/psa/admin/plib/modules/panel-migrator/backend/lib/python/parallels/plesk/source/custom/connections.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/custom/connections.py
    wget -O /usr/local/psa/admin/plib/modules/panel-migrator/backend/lib/python/parallels/plesk/source/directadmin/agent/dumper.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/directadmin/agent/dumper.py
elif [ -d "/opt/psa/admin/plib/modules/panel-migrator" ]; then
    wget -O /opt/psa/admin/plib/modules/panel-migrator/backend/lib/python/parallels/plesk/source/custom/connections.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/custom/connections.py
    wget -O /opt/psa/admin/plib/modules/panel-migrator/backend/lib/python/parallels/plesk/source/directadmin/agent/dumper.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/directadmin/agent/dumper.py
fi

innodb_status=$(plesk db -e "SHOW VARIABLES LIKE 'innodb_strict_mode';" | grep "innodb_strict_mode" | awk '{print $2}')
if [[ "$innodb_status" != "OFF" && "$innodb_status" != "0" ]]; then
    (echo "innodb_strict_mode=0" >> /etc/my.cnf) || (echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf) && service mariadb restart
fi

echo "Migration preparation is complete!"
