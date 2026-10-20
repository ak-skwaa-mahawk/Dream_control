#!/bin/sh
set -e

# Setup system environment
mkdir -p /etc/profile.d
echo 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /etc/profile.d/00-path.sh

# Ensure appliance directory permissions
if [ -d /appliance ]; then
    chmod -R 755 /appliance
fi
