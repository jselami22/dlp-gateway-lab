#!/bin/sh
set -e

NAME=$1
if [ -z "$NAME" ]; then
    echo "usage: sh make-site-cert.sh <hostname>"
    exit 1
fi

openssl req -newkey rsa:2048 -nodes \
    -keyout "$NAME.key" -out "$NAME.csr" \
    -subj "/CN=$NAME"

cat > "$NAME.cnf" <<END
subjectAltName=DNS:$NAME
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityKeyIdentifier=keyid,issuer
END

openssl x509 -req -in "$NAME.csr" \
    -CA internet-ca.crt -CAkey internet-ca.key -CAcreateserial \
    -days 365 -sha256 -extfile "$NAME.cnf" -out "$NAME.crt"

ls -l "$NAME".*