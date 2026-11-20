#!/bin/sh
set -e

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout company-ca.key -out company-ca.crt \
    -subj "/CN=Lab Company Root CA" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# mitmproxy wants the key and the certificate together in one file
cat company-ca.key company-ca.crt > company-ca.pem

ls -l company-ca.*