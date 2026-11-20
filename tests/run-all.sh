#!/bin/sh
# Run every test suite, print the results and save them to /results.
#   docker compose exec alice sh /tests/run-all.sh

mkdir -p /results
OUT=/results/results-$(date -u +%Y%m%d-%H%M%S).txt

{
    echo "DLP Gateway Lab - test run $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    for suite in phase1 email attacks; do
        echo
        echo "########## $suite"
        sh /tests/$suite.sh
    done
} 2>&1 | tee "$OUT"

echo
echo "== Summary"
grep "^Result:" "$OUT"
echo "Saved to $OUT"