At Plesk
# Upload to /usr/local/psa/admin/plib/modules/panel-migrator/backend/lib/python/parallels/plesk/source/
(echo "innodb_strict_mode=0" >> /etc/my.cnf || echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf) && service mariadb restart


At DirectAdmin
(echo "innodb_strict_mode=0" >> /etc/my.cnf || echo "innodb_strict_mode=0" >> /etc/mysql/my.cnf) && service mariadb restart
user=$(awk -F= '/user=/ {print $2}' /usr/local/directadmin/conf/my.cnf) && pass=$(awk -F= '/password=/ {gsub(/"/,"",$2); print $2}' /usr/local/directadmin/conf/my.cnf) && mysql -e "GRANT ALL PRIVILEGES ON *.* TO '$user'@'127.0.0.1' IDENTIFIED BY '$pass' WITH GRANT OPTION; FLUSH PRIVILEGES;"
grep -q "mysqlconf" /usr/local/directadmin/conf/directadmin.conf || { [ -f /usr/local/directadmin/conf/mysql.conf ] && echo "mysqlconf=/usr/local/directadmin/conf/mysql.conf" >> /usr/local/directadmin/conf/directadmin.conf; }
