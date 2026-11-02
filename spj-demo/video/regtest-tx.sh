#!/usr/bin/env bash
# Make one regtest transaction paying a P2TR output and film its mempool page.
#
#   regtest-tx.sh OUT.mp4
#
# Starts its own regtest bitcoind with -txindex on free localhost ports, mines
# a confirmed P2TR payment, runs record-tx.sh on it, and stops the node on
# exit. BITCOIND_EXE picks the bitcoind binary; bitcoin-cli is taken from the
# same directory.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=${1:?usage: regtest-tx.sh OUT.mp4}

if [ -z "${BITCOIND_EXE:-}" ]; then
    BITCOIND_EXE=$(nix build --no-link --print-out-paths nixpkgs#bitcoind)/bin/bitcoind
fi
bin=$(dirname "$BITCOIND_EXE")

work=$(mktemp -d /tmp/spjn.XXXXXX)
node_pid=
cleanup() {
    local status=$?
    if [ -n "$node_pid" ]; then
        kill -TERM "$node_pid" 2>/dev/null || true
        for _ in $(seq 40); do
            kill -0 "$node_pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$node_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
    exit $status
}
trap cleanup EXIT INT TERM

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
rpc_port=$(free_port)

"$BITCOIND_EXE" -regtest -datadir="$work" -txindex=1 -listen=0 \
    -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport="$rpc_port" -fallbackfee=0.0001 \
    -printtoconsole=0 &
node_pid=$!
cli() { "$bin/bitcoin-cli" -regtest -datadir="$work" -rpcport="$rpc_port" "$@"; }
for _ in $(seq 60); do
    cli -rpcwait -rpcwaittimeout=1 getblockcount >/dev/null 2>&1 && break
    sleep 0.5
done

cli -named createwallet wallet_name=demo >/dev/null
mine_to=$(cli getnewaddress "" bech32m)
cli generatetoaddress 101 "$mine_to" >/dev/null
pay_to=$(cli getnewaddress "" bech32m)
txid=$(cli -named sendtoaddress address="$pay_to" amount=0.5 fee_rate=2)
cli generatetoaddress 1 "$mine_to" >/dev/null
echo "txid $txid pays $pay_to"

"$here/record-tx.sh" --rpc-port "$rpc_port" --cookie "$work/regtest/.cookie" --txid "$txid" \
    --out "$out"
