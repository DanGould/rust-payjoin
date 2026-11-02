#!/usr/bin/env bash
# Record a narrated run of the six scenes as a terminal recording, and film
# the silent payjoins of scenes 3 and 5 in a local mempool explorer during the
# same run, so the transcript, the recording and the explorer videos show the
# same transactions.
#
#   nix develop -c spj-demo/video/record-run.sh OUT_DIR [PACE_MS]
#
# Writes to OUT_DIR:
#   spj-demo.cast        asciinema recording of the run
#   spj-demo.gif/.mp4    the recording rendered by agg, and as H.264
#   transcript.txt       the narration as text
#   scene3-*.mp4, scene5-*.mp4 (+ .png)   explorer videos, see record-tx.sh
#
# Run it inside the repository's dev shell, which provides bitcoind. asciinema,
# agg and ffmpeg come from an ephemeral `nix shell`. Keep the proxy settings:
# nix and the explorer backend fetch through them, and every loopback request
# bypasses them. Exits non-zero unless every scene passed.
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 OUT_DIR [PACE_MS]" >&2
    exit 2
fi
out=$(realpath -m "$1")
pace=${2:-60}
repo=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$out"

cargo build --quiet --locked --manifest-path "$repo/Cargo.toml" -p spj-demo
bin="$repo/target/debug/spj-demo"

# asciinema's own size flags are ignored for the render, so agg sets it.
# The inner script takes its values as arguments, hence single quotes.
# shellcheck disable=SC2016
nix shell nixpkgs#asciinema nixpkgs#asciinema-agg nixpkgs#ffmpeg --command bash -euo pipefail -c '
    out=$1 bin=$2 pace=$3
    asciinema rec --overwrite --quiet -i 2 \
        -c "$bin --pace $pace --transcript $out/transcript.txt --video $out" \
        "$out/spj-demo.cast"
    agg --cols 124 --rows 30 --font-size 14 --theme monokai \
        "$out/spj-demo.cast" "$out/spj-demo.gif"
    ffmpeg -y -loglevel error -i "$out/spj-demo.gif" -movflags faststart \
        -pix_fmt yuv420p -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" "$out/spj-demo.mp4"
' _ "$out" "$bin" "$pace"

# asciinema doesn't pass on the recorded command's status, so read the
# verdict from the transcript.
grep -q '^6 of 6 scenes passed$' "$out/transcript.txt"
echo "wrote $out"
