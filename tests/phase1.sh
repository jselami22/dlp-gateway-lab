#!/bin/sh
# Phase 1 checks. Run inside an employee:
#   docker compose exec alice sh /tests/phase1.sh

PASS=0
FAIL=0

# check <expected: ok|blocked> <description> <command...>
check() {
    want=$1
    desc=$2
    shift 2
    if "$@" > /dev/null 2>&1; then got=ok; else got=blocked; fi

    if [ "$got" = "$want" ]; then
        PASS=$((PASS + 1))
        echo "PASS  $desc ($got)"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL  $desc (expected $want, got $got)"
    fi
}

# A fake photo: JPEG magic bytes + random data
printf '\377\330\377\340' > /tmp/photo.jpg
head -c 20000 /dev/urandom >> /tmp/photo.jpg

echo "== DNS"
check ok      "wiki.corp resolves"              ping -c 1 -W 2 wiki.corp
check blocked "google.com does not resolve"     sh -c "dig +short google.com | grep -q ."

echo "== Internal traffic"
check ok      "wiki.corp homepage"              curl -sf --max-time 5 http://wiki.corp/
check ok      "photo upload to wiki.corp"       curl -sf --max-time 5 -F file=@/tmp/photo.jpg http://wiki.corp/upload

echo "== Direct routes to the outside (must be blocked)"
check blocked "direct HTTP to fileshare.ext"          curl -sf --noproxy '*' --max-time 3 http://fileshare.ext/
check blocked "direct photo upload to fileshare.ext"  curl -sf --noproxy '*' --max-time 3 -F file=@/tmp/photo.jpg http://fileshare.ext/upload
check blocked "SMTP to the outside"   curl -s --max-time 3 smtp://10.20.0.12:25

echo "== Through the proxy (DLP)"
check ok      "web page via proxy"                curl -sf --max-time 5 https://fileshare.ext/
check blocked "photo upload via proxy"            curl -sf --max-time 5 -F file=@/tmp/photo.jpg https://fileshare.ext/upload
check ok      "text upload via proxy"             sh -c "printf hello > /tmp/note.txt && curl -sf --max-time 5 -F doc=@/tmp/note.txt https://fileshare.ext/upload"

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]