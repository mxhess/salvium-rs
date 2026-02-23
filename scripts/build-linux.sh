#!/usr/bin/env bash
# Build Salvium shared libraries for Linux (x86_64)
#
# Produces:
#   prebuilt/linux-x86_64/libsalvium_crypto.so
#   prebuilt/linux-x86_64/libsalvium_ffi.so

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
OUT_DIR="$ROOT_DIR/prebuilt/linux-x86_64"

echo "==> Building Salvium libraries for Linux x86_64..."

cargo build --release \
  -p salvium-crypto \
  -p salvium-ffi \
  --manifest-path "$ROOT_DIR/Cargo.toml"

mkdir -p "$OUT_DIR"
cp "$ROOT_DIR/target/release/libsalvium_crypto.so" "$OUT_DIR/"
cp "$ROOT_DIR/target/release/libsalvium_ffi.so" "$OUT_DIR/"

echo "==> Done:"
ls -lh "$OUT_DIR/"*.so
