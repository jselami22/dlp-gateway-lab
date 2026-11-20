FROM alpine:3.20

RUN apk add --no-cache nftables dnsmasq iproute2 tcpdump bind-tools

COPY nftables.conf /etc/lab/nftables.conf
COPY dnsmasq.conf /etc/lab/dnsmasq.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]