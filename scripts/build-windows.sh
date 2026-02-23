#!/usr/bin/env bash
# Build Salvium shared libraries for Windows (x86_64, cross-compile from Linux)
#
# Produces:
#   prebuilt/windows-x86_64/salvium_crypto.dll
#   prebuilt/windows-x86_64/salvium_ffi.dll
#
# Prerequisites:
#   rustup target add x86_64-pc-windows-gnu
#   apt install gcc-mingw-w64-x86-64  (or equivalent)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
OUT_DIR="$ROOT_DIR/prebuilt/windows-x86_64"

echo "==> Building Salvium libraries for Windows x86_64..."

cargo build --release \
  --target x86_64-pc-windows-gnu \
  -p salvium-crypto \
  -p salvium-ffi \
  --manifest-path "$ROOT_DIR/Cargo.toml"

mkdir -p "$OUT_DIR"
cp "$ROOT_DIR/target/x86_64-pc-windows-gnu/release/salvium_crypto.dll" "$OUT_DIR/"
cp "$ROOT_DIR/target/x86_64-pc-windows-gnu/release/salvium_ffi.dll" "$OUT_DIR/"

echo "==> Done:"
ls -lh "$OUT_DIR/"*.dll
