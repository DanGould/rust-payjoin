#!/usr/bin/env bash
# Record the silent payjoin demo video with its narration.
#
#   build.sh OUT.mp4 NARRATION.md VO_DIR
#
# Starts the wallets (spj-web, with its own regtest bitcoind and payjoin
# mailroom) and a mempool explorer following that node, records one take in
# headless Chromium with record.mjs, and lays the audio files in VO_DIR
# (`<id>.wav`, one per `## id` block of NARRATION.md) over it with mux.mjs.
# The take holds each segment as long as its audio, so new audio of any
# length needs only a rerun. A segment without audio is held for a guess at
# its reading time and left silent.
#
# Everything started here binds to 127.0.0.1, runs in its own process group,
# and is killed when the script exits, whether it succeeds or not.
#
# MEMPOOL_DIR names a mempool checkout with a built backend (default
# /home/claude-agent/payjoin/mempool); MEMPOOL_FRONTEND a built frontend whose
# transaction page reads the `pj` and `sp` fragment parameters (default the
# agent/spj-explorer worktree beside it). KEEP_WORK keeps logs and frames.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)

if [ -z "${SPJ_VIDEO_TOOLS:-}" ]; then
    export SPJ_VIDEO_TOOLS=1
    exec nix develop "$repo" --command nix shell nixpkgs#chromium nixpkgs#ffmpeg \
        nixpkgs#mariadb nixpkgs#qrencode --command "$0" "$@"
fi

out=$(realpath -m "${1:?usage: build.sh OUT.mp4 NARRATION.md VO_DIR}")
narration=$(realpath "${2:?narration script}")
vo=$(realpath "${3:?audio directory}")
mempool=${MEMPOOL_DIR:-/home/claude-agent/payjoin/mempool}
frontend=${MEMPOOL_FRONTEND:-/home/claude-agent/payjoin/mempool-wt-spj-explorer/frontend/dist/mempool/browser}
for built in "$mempool/backend/dist/index.js" "$frontend/index.html"; do
    [ -f "$built" ] || {
        echo "missing $built: build the mempool checkout first" >&2
        exit 1
    }
done

export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
# A short path, since MariaDB refuses a socket path over 107 bytes.
work=$(mktemp -d "${TMPDIR:-/tmp}/spjw.XXXXXX")
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
db_port=$(free_port)
api_port=$(free_port)
web_port=$(free_port)

(cd "$repo" && { [ -f Cargo.lock ] || cp Cargo-recent.lock Cargo.lock; } && cargo build -q -p spj-web)

# The wallets' regtest node and mailroom: no proxy for any of it.
start wallets env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
    TMPDIR="$work" "$repo/target/debug/spj-web" --port "$wallet_port" \
    --explorer "http://127.0.0.1:$web_port" --node-info "$work/node.json"
wait_for "the wallets" 240 curl -sf "http://127.0.0.1:$wallet_port/api/state"
rpc_port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rpc_port"])' "$work/node.json")
cookie=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["cookie"])' "$work/node.json")

mariadb-install-db --no-defaults --datadir="$work/db" --auth-root-authentication-method=socket \
    >"$work/db-install.log" 2>&1
start mariadb mariadbd --no-defaults --datadir="$work/db" --socket="$work/db.sock" \
    --bind-address=127.0.0.1 --port="$db_port" --pid-file="$work/db.pid"
wait_for MariaDB 60 mariadb-admin --socket="$work/db.sock" -u "$(id -un)" ping
mariadb --socket="$work/db.sock" -u "$(id -un)" -e "
    CREATE DATABASE mempool;
    CREATE USER 'mempool'@'127.0.0.1' IDENTIFIED BY 'mempool';
    GRANT ALL PRIVILEGES ON mempool.* TO 'mempool'@'127.0.0.1';"

cat >"$work/mempool-config.json" <<EOF
{
  "MEMPOOL": {
    "OFFICIAL": false, "NETWORK": "regtest", "BACKEND": "none", "ENABLED": true,
    "HTTP_PORT": $api_port, "SPAWN_CLUSTER_PROCS": 0, "API_URL_PREFIX": "/api/v1/",
    "POLL_RATE_MS": 1000, "CACHE_DIR": "$work/cache", "CACHE_ENABLED": false,
    "INITIAL_BLOCKS_AMOUNT": 8, "MEMPOOL_BLOCKS_AMOUNT": 8, "INDEXING_BLOCKS_AMOUNT": 0,
    "BLOCKS_SUMMARIES_INDEXING": false, "GOGGLES_INDEXING": false,
    "AUTOMATIC_POOLS_UPDATE": false, "AUDIT": false, "RUST_GBT": true,
    "CPFP_INDEXING": false, "PRICE_UPDATES_PER_HOUR": 0, "STDOUT_LOG_MIN_PRIORITY": "info",
    "EXTERNAL_ASSETS": [], "EXTERNAL_MAX_RETRY": 1, "EXTERNAL_RETRY_INTERVAL": 0,
    "ALLOW_UNREACHABLE": true, "UNIX_SOCKET_PATH": ""
  },
  "CORE_RPC": {
    "HOST": "127.0.0.1", "PORT": $rpc_port, "USERNAME": "", "PASSWORD": "",
    "TIMEOUT": 60000, "COOKIE": true, "COOKIE_PATH": "$cookie"
  },
  "DATABASE": {
    "ENABLED": true, "HOST": "127.0.0.1", "PORT": $db_port, "SOCKET": "",
    "DATABASE": "mempool", "USERNAME": "mempool", "PASSWORD": "mempool",
    "TIMEOUT": 180000, "PID_DIR": ""
  },
  "SYSLOG": { "ENABLED": false },
  "STATISTICS": { "ENABLED": false, "TX_PER_SECOND_SAMPLE_PERIOD": 150 },
  "MAXMIND": { "ENABLED": false },
  "LIGHTNING": { "ENABLED": false },
  "SOCKS5PROXY": { "ENABLED": false },
  "FIAT_PRICE": { "ENABLED": false },
  "REDIS": { "ENABLED": false }
}
EOF

# The backend fetches the mining pool list from GitHub on a fresh database,
# so it keeps any proxy settings for that one outbound request.
start backend env -C "$mempool/backend" MEMPOOL_CONFIG_FILE="$work/mempool-config.json" \
    node --max-old-space-size=2048 dist/index.js
wait_for "the mempool backend" 240 curl -sf "http://127.0.0.1:$api_port/api/v1/blocks/tip/height"
start explorer node "$repo/spj-demo/video/serve.mjs" "$frontend" "$web_port" "$api_port"
wait_for "the explorer" 40 curl -sf "http://127.0.0.1:$web_port/"

WORK="$work/take" WALLETS_URL="http://127.0.0.1:$wallet_port" CHROME=chromium \
    CDP_PORT="$(free_port)" VO_DIR="$vo" NARRATION="$narration" \
    node "$here/record.mjs" "$work/take.mp4" "$work/marks.json" | tee "$work/record.log"
mkdir -p "$(dirname "$out")"
node "$here/mux.mjs" "$work/take.mp4" "$work/marks.json" "$vo" "$out"
cp "$work/marks.json" "${out%.mp4}.marks.json"
echo "wrote $out"
