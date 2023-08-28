#!/bin/bash

# Find PHP version directories and save them to a temporary file
find /opt/plesk/php -maxdepth 1 -type d ! -name php > /tmp/verx.txt

# Read each line from the temporary file
cat /tmp/verx.txt | cut -f 5 -d '/' | while read -r verx; do
    # Skip empty lines
    if [ -z "$verx" ]; then
        continue
    fi
    
    # Proceed with the installation and configuration for the current PHP version
    echo "Installing and configuring for PHP version $verx..."
  
    # Install development packages
    yum install "plesk-php${verx}-devel" libzstd-devel glibc-devel gcc -y
  
    # Install igbinary
    /opt/plesk/php/$verx/bin/pecl install igbinary
  
    # Configure igbinary
    cat <<EOF > "/opt/plesk/php/$verx/etc/php.d/igbinary.ini"
extension=igbinary.so
EOF
  
    # Install redis
    /opt/plesk/php/$verx/bin/pecl install redis
  
    # Configure redis
    cat <<EOF > "/opt/plesk/php/$verx/etc/php.d/redis.ini"
; Enable redis extension module
extension=redis.so
EOF
  
    # Disable expose_php header
    echo 'expose_php = off' > "/opt/plesk/php/$verx/etc/php.d/hideheader.ini"
  
    # Set permissions
    chmod 755 "/opt/plesk/php/$verx/lib64/php/modules/redis.so"
    chmod 755 "/opt/plesk/php/$verx/lib64/php/modules/igbinary.so"
  
    # Reread PHP handlers
    plesk bin php_handler --reread
  
done
