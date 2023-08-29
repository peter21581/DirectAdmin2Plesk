#!/bin/bash
# Install PHP 5.6 on AlmaLinux 8

#check root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
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

# check if PHP 5.6 already installed
if [ -d /opt/remi/php56 ]; then
  echo "PHP 5.6 already installed"
  exit
fi

echo "add remi repo";
dnf install -y http://rpms.remirepo.net/enterprise/remi-release-8.rpm;

echo "install php 5.6 from remi repo";
dnf install -y php56 php56-php-{bcmath,bz2,cli,common,curl,devel,fpm,gd,gmp,imagick,imap,intl,json,mbstring,mysql,opcache,pspell,readline,recode,soap,ssh2,sqlite3,tidy,xml,xmlrpc,zip};

# if /opt/remi/php56/root/usr/sbin/php-fpm exist then add php 5.6 fpm to plesk if not then exit;
if [ ! -f /opt/remi/php56/root/usr/sbin/php-fpm ]; then
  echo "PHP 5.6 FPM not installed"
  exit
else
  echo "add php 5.6 fpm to plesk";
  plesk bin php_handler --add -displayname php56-fpm-custom -path /opt/remi/php56/root/usr/sbin/php-fpm -phpini /etc/opt/remi/php56/php.ini -type fpm -id php5.6-fpm-custom -clipath /opt/remi/php56/root/usr/bin/php -service php56-php-fpm -poold /etc/opt/remi/php56/php-fpm.d;
fi