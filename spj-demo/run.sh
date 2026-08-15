#!/usr/bin/env bash
# Record a full demo run.
#
# Produces the artifacts under spj-demo/artifacts:
#   transcript.txt  — the narrated run, written by the demo binary
#   session.log     — terminal capture of the same run
#   session.timing  — timing data for the capture; replay with:
#                     scriptreplay -t spj-demo/artifacts/session.timing \
#                         spj-demo/artifacts/session.log
#   ledgers.md      — the cost ledger tables as markdown
#   tweak-index.bin — the toy tweak index scene 7 emits and audits
#
# Run from anywhere; requires the repo dev shell (bitcoind comes from
# BITCOIND_EXE): nix develop -c ./spj-demo/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p spj-demo/artifacts
script -q -T spj-demo/artifacts/session.timing \
    -c "cargo run --quiet -p spj-demo" \
    spj-demo/artifacts/session.log
