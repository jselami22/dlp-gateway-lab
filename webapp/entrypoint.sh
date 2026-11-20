#!/bin/sh
set -e

if [ -n "$RETURN_VIA" ]; then
    ip route replace 10.10.0.0/24 via "$RETURN_VIA"
    echo "[$SERVICE_NAME] replies to 10.10.0.0/24 go via $RETURN_VIA"
fi

echo "[$SERVICE_NAME] starting web server on port 80"
exec python /app/app.py

