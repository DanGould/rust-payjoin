#!/usr/bin/env bash
# Record the silent payjoin demo video with its narration.
#
#   build.sh OUT.mp4 NARRATION.md VO_DIR
#
# Next to OUT.mp4 it writes the take's marks (OUT.marks.json), subtitles
# from the narration (OUT.srt, OUT.vtt, and a track in OUT.mp4 that players
# show only when asked) and thumbnail.png, the title card.
#
# Starts the wallets (spj-web, with its own regtest bitcoind and payjoin
# mailroom), records one take in headless Chromium with record.mjs, and lays
# the audio files in VO_DIR
# (`<id>.wav`, one per `## id` block of NARRATION.md) over it with mux.mjs.
# The take holds each segment as long as its audio, so new audio of any
# length needs only a rerun. A segment without audio is held for a guess at
# its reading time and left silent.
#
# Everything started here binds to 127.0.0.1, runs in its own process group,
# and is killed when the script exits, whether it succeeds or not.
# KEEP_WORK keeps logs and frames.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)

if [ -z "${SPJ_VIDEO_TOOLS:-}" ]; then
    export SPJ_VIDEO_TOOLS=1
    exec nix develop "$repo" --command nix shell nixpkgs#chromium nixpkgs#ffmpeg \
        nixpkgs#qrencode --command "$0" "$@"
fi

out=$(realpath -m "${1:?usage: build.sh OUT.mp4 NARRATION.md VO_DIR}")
narration=$(realpath "${2:?narration script}")
vo=$(realpath "${3:?audio directory}")
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
work=$(mktemp -d "${TMPDIR:-/tmp}/spjw.XXXXXX")
mkdir -p "$(dirname "$out")"
groups=()

cleanup() {
    local status=$?
    for pgid in "${groups[@]}"; do kill -TERM -- "-$pgid" 2>/dev/null || true; done
    for _ in $(seq 20); do
        local alive=0
        for pgid in "${groups[@]}"; do kill -0 -- "-$pgid" 2>/dev/null && alive=1; done
        [ $alive = 0 ] && break
        sleep 0.5
    done
    for pgid in "${groups[@]}"; do kill -KILL -- "-$pgid" 2>/dev/null || true; done
    if [ $status != 0 ]; then tail -n 30 "$work"/*.log >&2 2>/dev/null || true; fi
    if [ -n "${KEEP_WORK:-}" ]; then echo "work kept in $work" >&2; else rm -rf "$work"; fi
    exit $status
}
trap cleanup EXIT INT TERM

start() {
    local name=$1
    shift
    setsid "$@" >"$work/$name.log" 2>&1 &
    groups+=($!)
}

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

wait_for() {
    local what=$1 tries=$2
    shift 2
    for _ in $(seq "$tries"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    echo "timed out waiting for $what" >&2
    return 1
}

wallet_port=$(free_port)

(cd "$repo" && { [ -f Cargo.lock ] || cp Cargo-recent.lock Cargo.lock; } && cargo build -q -p spj-web)

# The wallets' regtest node and mailroom: no proxy for any of it.
start wallets env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
    TMPDIR="$work" "$repo/target/debug/spj-web" --port "$wallet_port"
wait_for "the wallets" 240 curl -sf "http://127.0.0.1:$wallet_port/api/state"

WORK="$work/take" WALLETS_URL="http://127.0.0.1:$wallet_port" CHROME=chromium \
    CDP_PORT="$(free_port)" VO_DIR="$vo" NARRATION="$narration" \
    node "$here/record.mjs" "$work/take.mp4" "$work/marks.json" \
    "$(dirname "$out")/thumbnail.png" | tee "$work/record.log"
# URIs name a public mailbox host, which the wallets' mailroom answers for
# locally. Its count of requests shows they all went there.
curl -sf "http://127.0.0.1:$wallet_port/api/state" >"$work/state.json"
python3 -c 'import json,sys; m = json.load(sys.stdin)["mailroom"]; print("mailroom {}: {} requests, all to the local directory".format(m["host"], m["requests"]))' <"$work/state.json"
# Each transfer Bob found by scanning, the label it paid, and whether a
# wallet restored from his backup words, knowing no labels, finds it too.
# A silent transfer the restore misses fails the take.
python3 -c '
import json, sys
received = json.load(sys.stdin)["received"]
missed = 0
for r in received:
    if not r["by_scan"]:
        print("received {}: {} sats to the address".format(r["txid"][:12], r["amount"]))
        continue
    print("received {}: {} sats on label {}{}, restore {}".format(
        r["txid"][:12], r["amount"], r["label"],
        " ({})".format(r["label_for"]) if r["label_for"] else "",
        "finds it" if r["restored"] else "MISSES it"))
    missed += not r["restored"]
sys.exit(1 if missed else 0)
' <"$work/state.json"
node "$here/subs.mjs" "$narration" "$work/marks.json" "${out%.mp4}.srt" "${out%.mp4}.vtt"
node "$here/mux.mjs" "$work/take.mp4" "$work/marks.json" "$vo" "$out" "${out%.mp4}.srt"
cp "$work/marks.json" "${out%.mp4}.marks.json"
echo "wrote $out"
