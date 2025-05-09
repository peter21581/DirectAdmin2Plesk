#!/bin/bash

# check if /etc/http or /etc/apache2 exists
if [ -d /etc/httpd ]; then
    httpd_dir=/etc/httpd
    conf_dir=$httpd_dir/conf.d
elif [ -d /etc/apache2 ]; then
    httpd_dir=/etc/apache2
    conf_dir=$httpd_dir/conf-enabled
else
    echo "Apache config directory not found. Exiting..."
    exit 1
fi

cat <<EOF > $conf_dir/cloudflare.conf
RemoteIPHeader CF-Connecting-IP
RemoteIPTrustedProxy 173.245.48.0/20
RemoteIPTrustedProxy 103.21.244.0/22
RemoteIPTrustedProxy 103.22.200.0/22
RemoteIPTrustedProxy 103.31.4.0/22
RemoteIPTrustedProxy 141.101.64.0/18
RemoteIPTrustedProxy 108.162.192.0/18
RemoteIPTrustedProxy 190.93.240.0/20
RemoteIPTrustedProxy 188.114.96.0/20
RemoteIPTrustedProxy 197.234.240.0/22
RemoteIPTrustedProxy 198.41.128.0/17
RemoteIPTrustedProxy 162.158.0.0/15
RemoteIPTrustedProxy 104.16.0.0/13
RemoteIPTrustedProxy 104.24.0.0/14
RemoteIPTrustedProxy 172.64.0.0/13
RemoteIPTrustedProxy 131.0.72.0/22
RemoteIPTrustedProxy 2400:cb00::/32
RemoteIPTrustedProxy 2606:4700::/32
RemoteIPTrustedProxy 2803:f800::/32
RemoteIPTrustedProxy 2405:b500::/32
RemoteIPTrustedProxy 2405:8100::/32
RemoteIPTrustedProxy 2a06:98c0::/29
RemoteIPTrustedProxy 2c0f:f248::/32
EOF



# Restart Apache, check if RHEL or Debian based
if [ -f /etc/redhat-release ]; then
    service httpd restart
else
    service apache2 restart
fi  
