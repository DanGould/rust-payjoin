#!/usr/bin/env bash

set -euo pipefail
OS=$(uname -s)

echo "Generating payjoin.py..."
cd ../payjoin-ffi/
cargo run --bin uniffi-bindgen generate src/payjoin.udl --language python --out-dir ../payjoin-python/src/payjoinpython/ --no-format

echo "Generating native binaries..."
cargo build --profile release-smaller
case $OS in
  "Darwin")
    echo "Copying macOS libpayjoinffi.dylib..."
    cp ../target/release-smaller/libpayjoinffi.dylib ../payjoin-python/src/payjoinpython/libpayjoinffi.dylib
    ;;
  "Linux")
    echo "Copying linux libpayjoinffi.so..."
    cp ../target/release-smaller/libpayjoinffi.so ../payjoin-python/src/payjoinpython/libpayjoinffi.so
    ;;
esac
cd ../payjoin-python/

echo "All done!"
