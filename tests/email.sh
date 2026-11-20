#!/bin/sh
# Phase 4 email checks. Run from Windows:
#   docker compose exec alice sh /tests/email.sh

PASS=0
FAIL=0

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

cd /tmp
printf 'From: alice@corp.local\r\nTo: bob@corp.local\r\nSubject: Lunch\r\n\r\nSee you at 12.\r\n' > mail.txt
printf 'From: bob@corp.local\r\nTo: carol@corp.local\r\nSubject: Fake\r\n\r\nhi\r\n' > spoof.txt

MAIL=smtp://mail.corp:587
LOGIN="--user alice@corp.local:alice123"
GMAIL="--mail-from alice.personal@gmail.ext --mail-rcpt friend@gmail.ext --upload-file mail.txt"

echo "== Company mail server (mail.corp)"
check ok      "company -> company"                curl -s $MAIL $LOGIN --mail-from alice@corp.local --mail-rcpt bob@corp.local --upload-file mail.txt
check blocked "company -> external recipient"     curl -s $MAIL $LOGIN --mail-from alice@corp.local --mail-rcpt friend@gmail.ext --upload-file mail.txt
check blocked "envelope spoofing (send as bob)"   curl -s $MAIL $LOGIN --mail-from bob@corp.local --mail-rcpt carol@corp.local --upload-file mail.txt
check blocked "header spoofing (From: bob)"       curl -s $MAIL $LOGIN --mail-from alice@corp.local --mail-rcpt carol@corp.local --upload-file spoof.txt
check blocked "no login"                          curl -s $MAIL --mail-from alice@corp.local --mail-rcpt bob@corp.local --upload-file mail.txt
check blocked "wrong password"                    curl -s $MAIL --user alice@corp.local:wrong --mail-from alice@corp.local --mail-rcpt bob@corp.local --upload-file mail.txt

echo "== Personal mail provider (smtp.gmail.ext)"
check blocked "direct SMTP, port 587"             curl -s --max-time 4 smtp://smtp.gmail.ext:587 $GMAIL
check blocked "direct SMTP, port 25"              curl -s --max-time 4 smtp://smtp.gmail.ext:25 $GMAIL
check blocked "tunnel through proxy, port 25"     curl -s --max-time 6 -x http://10.10.0.2:8080 --proxytunnel smtp://smtp.gmail.ext:25 $GMAIL
check blocked "tunnel through proxy, port 443"    curl -s --max-time 6 -x http://10.10.0.2:8080 --proxytunnel smtp://smtp.gmail.ext:443 $GMAIL

echo "== Webmail (webmail.ext)"
check ok      "company account login"             curl -sf -d "username=alice@corp.local&password=x" https://webmail.ext/login
check blocked "personal account login"            curl -sf -d "username=alice.personal@gmail.ext&password=x" https://webmail.ext/login

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]