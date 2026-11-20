#!/bin/sh
set -e

#Look up names with the company DNS (dnsmasq on the gateway)
echo "nameserver 127.0.0.1" > /etc/resolv.conf
# Use the company CA to sign the fake certificates
mkdir -p /root/.mitmproxy
cp /certs/company-ca.pem /root/.mitmproxy/mitmproxy-ca.pem

echo "[proxy] starting mitmproxy on port 8080 (TLS interception ON)"
exec mitmdump --listen-port 8080 \
    --set confdir=/root/.mitmproxy \
    --set ssl_verify_upstream_trusted_ca=/certs/internet-ca.crt \
    --set flow_detail=2 \
    -s /addons/dlp.py