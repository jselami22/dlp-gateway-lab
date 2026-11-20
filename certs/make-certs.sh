#!/bin/sh
set -e

# the "Internet CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout internet-ca.key -out internet-ca.crt \
    -subj "/CN=Lab Internet Root CA" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# fileshare.ext: a private key and a certificate request
openssl req -newkey rsa:2048 -nodes \
    -keyout fileshare.key -out fileshare.csr \
    -subj "/CN=fileshare.ext"

# the CA checks the request and signs it
cat > fileshare.cnf <<END
subjectAltName=DNS:fileshare.ext
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid,issuer
END
openssl x509 -req -in fileshare.csr \
    -CA internet-ca.crt -CAkey internet-ca.key -CAcreateserial \
    -days 365 -sha256 -extfile fileshare.cnf -out fileshare.crt

ls -l