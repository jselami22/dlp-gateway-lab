# DLP Gateway Lab

A small company network in Docker where one gateway controls what data may leave (Idea to prevent information leak from inside the companies ground.):
a default-deny firewall, a company DNS, a TLS-intercepting proxy with a Python
DLP engine, a company-only mail server, and a live dashboard of every decision.

All 32 functional tests pass, and 10 of 11 red-team upload attacks
(renamed files, base64, gzip, split files, ...) are blocked.

I put together a report with a more detailed explanation of the architecture, set up, tests, results, and other findings. If you are interested in this project [report](report.md)

## Architecture

| Layer | Technology |
| --- | --- |
| Networks | Docker: `corp_net` 10.10.0.0/24, `outside_net` 10.20.0.0/24 |
| Firewall | nftables, default-deny |
| DNS | dnsmasq, listed names only |
| Proxy + DLP | mitmproxy + `proxy/addons/dlp.py`, rules in `policy.yaml` |
| Mail | aiosmtpd, company-to-company only |
| Dashboard | Flask, http://localhost:8000 |

## Quick start

Requires Docker Desktop (or Docker Engine with Compose).

```bash
# 1. Generate the lab's certificates (written to certs/)
docker run --rm -v "${PWD}/certs:/certs" -w /certs alpine:3.20 sh -c "apk add --no-cache openssl && sh make-certs.sh && sh make-company-ca.sh && sh make-site-cert.sh cloud.ext && sh make-site-cert.sh webmail.ext"

# 2. Create your .env from the template and set a secret
cp .env.example .env

# 3. Build and start the lab
docker compose up -d --build

# 4. Issue Alice's company token, put it in .env as COMPANY_TOKEN, then recreate Alice
docker compose exec proxy python /addons/make_token.py alice@corp.local
docker compose up -d alice

# 5. Run all tests (results are saved to results/)
docker compose exec alice sh /tests/run-all.sh
```

## Disclaimer

This is a learning lab. All services are fake and run on one machine.
Intercepting TLS traffic on networks or devices you do not own, or without
the users' knowledge, may be illegal.
