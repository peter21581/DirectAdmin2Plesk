#!/bin/bash

# Check if the user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Exiting..."
    exit 1
fi

# Check if Plesk exists
if ! command -v plesk &>/dev/null; then
    echo "Plesk not found. This script is meant to be run on a Plesk server. Exiting..."
    exit 1
fi

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
fi

# Inform user
echo "Getting things ready for directadmin migration to plesk."

# Prompt user for DirectAdmin details
read -p "Enter DirectAdmin SSH server IP: " da_ip
read -p "Enter DirectAdmin SSH user: " da_user
read -sp "Enter DirectAdmin SSH password: " da_pass; echo
read -p "Enter DirectAdmin SSH port [default: 22]: " da_port
read -p "Is this a CloudLinux server? [y/n]: " da_cl
da_port=${da_port:-22}  # Set default port to 22 if none specified

# Have the user confirm before proceed. show the details entered and ask for confirmation
echo -e "\nPlease confirm the following details are correct:"
echo "DirectAdmin SSH server IP: $da_ip"
echo "DirectAdmin SSH user: $da_user"
echo "DirectAdmin SSH port: $da_port"
echo "Is this a CloudLinux server? $da_cl"
read -p "Is this correct? [y/n]: " da_confirm

# if da_comfirm is not y/Y go back to the start
if [[ ! "$da_confirm" =~ ^[Yy]$ ]]; then
    echo "Please run the script again with the correct details."
    exit 1
fi

# Execute commands on the DirectAdmin server
sshpass -p "$da_pass" ssh -T -p $da_port $da_user@$da_ip <<EOF
echo -e "[client]\nuser=da_admin\npassword=\$(grep "^passwd=" /usr/local/directadmin/conf/mysql.conf | cut -d= -f2)\nsocket=/var/lib/mysql/mysql.sock" > /root/.my.cnf;

# Check innodb_strict_mode
innodb_mode=\$(mysql -e "SHOW VARIABLES LIKE 'innodb_strict_mode';" | grep -c "OFF")
if [ "\$innodb_mode" -eq 0 ]; then
    echo "Updating innodb_strict_mode..."
    echo "innodb_strict_mode=0" >> /etc/my.cnf || echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf && service mariadb restart
fi

echo "Configuring MySQL permissions..."
user=\$(awk -F= '/user=/ {print \$2}' /usr/local/directadmin/conf/my.cnf) && pass=\$(awk -F= '/password=/ {gsub(/"/,"",\$2); print \$2}' /usr/local/directadmin/conf/my.cnf) && mysql -e "GRANT ALL PRIVILEGES ON *.* TO '\$user'@'127.0.0.1' IDENTIFIED BY '\$pass' WITH GRANT OPTION; FLUSH PRIVILEGES;"

echo "Checking DirectAdmin configuration..."
grep -q "mysqlconf" /usr/local/directadmin/conf/directadmin.conf || { [ -f /usr/local/directadmin/conf/mysql.conf ] && echo "mysqlconf=/usr/local/directadmin/conf/mysql.conf" >> /usr/local/directadmin/conf/directadmin.conf; }

# change CloudLinux to AlmaLinux in /etc/redhat-release
if [ "$da_cl" == "y" ]; then
    echo "Changing CloudLinux to AlmaLinux in /etc/redhat-release..."
    sed -i 's/CloudLinux/AlmaLinux/g' /etc/redhat-release
    # Show what is in /etc/redhat-release
    echo "Current /etc/redhat-release: $(cat /etc/redhat-release)"
fi

# Displaying innodb_strict_mode
echo "Current innodb_strict_mode value:"
mysql -e "SHOW VARIABLES LIKE 'innodb_strict_mode';"

# Check if mysqlconf exists in directadmin.conf
if grep -q "mysqlconf" /usr/local/directadmin/conf/directadmin.conf; then
    echo "'mysqlconf' exists in directadmin.conf"
else
    echo "'mysqlconf' not found in directadmin.conf"
fi
EOF

# Back at the local server
plesk bin extension --uninstall panel-migrator
plesk bin extension --install panel-migrator
echo -e "[client]\nuser=admin\npassword=\$(cat /etc/psa/.psa.shadow)\nsocket=/var/lib/mysql/mysql.sock" > /root/.my.cnf

echo "Configarting Plesk Panel Migrator extension..."
if [ -d "/usr/local/psa/admin/plib/modules/panel-migrator" ]; then
    path_migrator = "/usr/local/psa/admin/plib/modules/panel-migrator"
    wget -qO $path_migrator/backend/lib/python/parallels/plesk/source/custom/connections.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/custom/connections.py;
    wget -qO $path_migrator/backend/lib/python/parallels/plesk/source/directadmin/agent/dumper.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/directadmin/agent/dumper.py;
    wget -qO $path_migrator/backend/lib/python/parallels/core/utils/os_version.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/os_version.py;
elif [ -d "/opt/psa/admin/plib/modules/panel-migrator" ]; then
    path_migrator = "/opt/psa/admin/plib/modules/panel-migrator"
    wget -qO $path_migrator/backend/lib/python/parallels/plesk/source/custom/connections.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/custom/connections.py;
    wget -qO $path_migrator/backend/lib/python/parallels/plesk/source/directadmin/agent/dumper.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/directadmin/agent/dumper.py;
    wget -qO $path_migrator/backend/lib/python/parallels/core/utils/os_version.py https://raw.githubusercontent.com/peter21581/DirectAdmin2Plesk/main/source/os_version.py;
fi

# Check and set innodb_strict_mode on Plesk DB
innodb_mode_check=$(plesk db "SHOW VARIABLES LIKE 'innodb_strict_mode';" | grep -c "OFF")
if [ "$innodb_mode_check" -eq 0 ]; then
    echo "innodb_strict_mode=0" >> /etc/my.cnf || echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf
    service mariadb restart
fi

echo "Migration preparation is complete."
