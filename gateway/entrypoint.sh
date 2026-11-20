#!/bin/sh
set -e

echo "[gateway] loading firewall rules"
nft -f /etc/lab/nftables.conf

echo "[gateway] starting DNS"
exec dnsmasq --no-daemon --conf-file=/etc/lab/dnsmasq.conf