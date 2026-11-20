#!/bin/sh
set -e
update-ca-certificates

GATEWAY=10.10.0.2

ip route replace default via "$GATEWAY"
echo "nameserver $GATEWAY" > /etc/resolv.conf

echo "[$(hostname)] ready: route and DNS via $GATEWAY"
exec sleep infinity