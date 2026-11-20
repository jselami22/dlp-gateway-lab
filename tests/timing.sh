#!/bin/sh
# How much delay do the proxy and the DLP add?
#   docker compose exec alice sh /tests/timing.sh

N=20
cd /tmp
printf 'hello from alice' > note.txt
printf '\377\330\377\340' > photo.jpg
head -c 20000 /dev/urandom >> photo.jpg

# measure <label> <curl options...>: average time of N requests, in milliseconds
measure() {
    label=$1
    shift
    total=0
    i=0
    while [ $i -lt $N ]; do
        t=$(curl -s -o /dev/null -w '%{time_total}' "$@")
        total=$(echo "$total $t" | awk '{ print $1 + $2 }')
        i=$((i + 1))
    done
    avg=$(echo "$total $N" | awk '{ printf "%.1f", $1 / $2 * 1000 }')
    printf '%-48s %7s ms\n' "$label" "$avg"
}

echo "Average over $N requests each:"
measure "wiki.corp, HTTP, no proxy"                -F doc=@note.txt http://wiki.corp/upload
measure "fileshare.ext, HTTP, via proxy"           -F doc=@note.txt http://fileshare.ext/upload
measure "fileshare.ext, HTTPS, via proxy"          -F doc=@note.txt https://fileshare.ext/upload
measure "fileshare.ext, HTTPS, photo (blocked)"    -F file=@photo.jpg https://fileshare.ext/upload