#!/usr/bin/env bash
# Film a transaction's page in a local mempool explorer.
#
#   record-tx.sh --rpc-port PORT --cookie PATH --txid TXID --out FILE.mp4 [--frames N]
#
# Points a mempool backend at the regtest bitcoind listening on 127.0.0.1:PORT
# (cookie auth), serves the mempool frontend, opens /tx/TXID in headless
# Chromium, and encodes the captured frames to FILE.mp4. A full-page PNG is
# written next to it as FILE.png.
#
# Everything this script starts (MariaDB, the backend, the static server and
# Chromium) binds to 127.0.0.1 on a free port, runs in its own process group,
# and is killed when the script exits, whether it succeeds or not. The
# bitcoind belongs to the caller and is left alone. For a transaction that is
# already confirmed, that bitcoind needs -txindex.
#
# MEMPOOL_DIR names a mempool checkout with built backend/dist and
# frontend/dist (default: /home/claude-agent/payjoin/mempool). Set KEEP_LOGS
# to keep the services' logs and the captured frames after the script exits.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if ! command -v mariadbd >/dev/null || ! command -v chromium >/dev/null ||
    ! command -v ffmpeg >/dev/null; then
    exec nix shell nixpkgs#mariadb nixpkgs#chromium nixpkgs#ffmpeg --command "$0" "$@"
fi

frames=48
while [ $# -gt 0 ]; do
    case "$1" in
        --rpc-port)
            rpc_port=$2
            shift 2
            ;;
        --cookie)
            cookie=$2
            shift 2
            ;;
        --txid)
            txid=$2
            shift 2
            ;;
        --out)
            out=$2
            shift 2
            ;;
        --frames)
            frames=$2
            shift 2
            ;;
        *)
            echo "unknown argument $1" >&2
            exit 2
            ;;
    esac
done
: "${rpc_port:?--rpc-port is required}" "${cookie:?--cookie is required}"
: "${txid:?--txid is required}" "${out:?--out is required}"
mempool=${MEMPOOL_DIR:-/home/claude-agent/payjoin/mempool}
for built in "$mempool/backend/dist/index.js" "$mempool/frontend/dist/mempool/browser/index.html"; do
    [ -f "$built" ] || {
        echo "missing $built: build the mempool checkout first" >&2
        exit 1
    }
done

# Requests to the services started here must not go through an HTTP proxy.
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost

# A short path, since MariaDB refuses a socket path over 107 bytes.
work=$(mktemp -d /tmp/spjv.XXXXXX)
groups=()

cleanup() {
    local status=$?
    for pgid in "${groups[@]}"; do kill -TERM -- "-$pgid" 2>/dev/null || true; done
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        local alive=0
        for pgid in "${groups[@]}"; do kill -0 -- "-$pgid" 2>/dev/null && alive=1; done
        [ $alive = 0 ] && break
        sleep 0.5
    done
    for pgid in "${groups[@]}"; do kill -KILL -- "-$pgid" 2>/dev/null || true; done
    if [ $status != 0 ] && [ -z "${KEEP_LOGS:-}" ]; then
        tail -n 20 "$work"/*.log >&2 2>/dev/null || true
    fi
    if [ -n "${KEEP_LOGS:-}" ]; then echo "logs kept in $work" >&2; else rm -rf "$work"; fi
    exit $status
}
trap cleanup EXIT INT TERM

# Run a command in a new process group with its output in $work/<name>.log.
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

db_port=$(free_port)
api_port=$(free_port)
web_port=$(free_port)
cdp_port=$(free_port)

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
wait_for "the mempool backend to see $txid" 240 \
    curl -sf "http://127.0.0.1:$api_port/api/v1/tx/$txid"

start serve node "$here/serve.mjs" "$mempool/frontend/dist/mempool/browser" "$web_port" "$api_port"
wait_for "the frontend server" 40 curl -sf "http://127.0.0.1:$web_port/"

start chromium chromium --headless=new --no-sandbox --disable-gpu --no-proxy-server \
    --user-data-dir="$work/chromium" --remote-debugging-address=127.0.0.1 \
    --remote-debugging-port="$cdp_port" about:blank
node "$here/capture.mjs" "$cdp_port" "http://127.0.0.1:$web_port/tx/$txid" "$work/shots" "$frames" |
    tee "$work/capture.log"

mkdir -p "$(dirname "$out")"
# Hold the top of the page for 2 s and the bottom for 3 s around the sweep.
ffmpeg -loglevel error -y -framerate 8 -i "$work/shots/frames/%03d.png" \
    -vf "tpad=start_mode=clone:start_duration=2:stop_mode=clone:stop_duration=3,scale=1280:-2,format=yuv420p" \
    -c:v libx264 -preset medium -crf 23 -movflags +faststart "$out"
cp "$work/shots/tx-full.png" "${out%.mp4}.png"
echo "wrote $out"
