#!/bin/bash

# check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# check OS if /etc/redhat-relese exist
if [ ! -f /etc/redhat-release ]; then
  echo "OS not supported"
  exit
fi

# check if /etc/psa/.psa.shadow exist
if [ ! -f /etc/psa/.psa.shadow ]; then
  echo "Plesk not installed"
  exit
fi

# Script to install MariaDB 10.6 on AlmaLinux 8.x
echo "dump all db to /tmp/all-databases.sql";
MYSQL_PWD=`cat /etc/psa/.psa.shadow` mysqldump -u admin --verbose --all-databases --routines --triggers > /tmp/all-databases.sql;

echo "stop mariadb service";
service mariadb stop;

echo "backup /var/lib/mysql";
cp -v -a /var/lib/mysql/ /var/lib/mysql_backup;

echo "add repo mariadb 10.6";
cat <<EOF > /etc/yum.repos.d/MariaDB.repo
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.6/rhel8-amd64
module_hotfixes=1
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1 
priority=1
EOF

echo "install mariadb 10.6";
dnf install MariaDB-server galera-4 MariaDB-client MariaDB-shared MariaDB-backup MariaDB-common;

echo "download my.cnf";
curl -L ddos.de.co.th/da_mariadb.sh | bash;

echo "mysql upgrade";
MYSQL_PWD=`cat /etc/psa/.psa.shadow` mysql_upgrade -uadmin
systemctl restart mariadb

echo "plesk repair";
plesk sbin packagemng -sdf

echo "restore all db";
restorecon -v /var/lib/mysql/*