#!/usr/bin/env bash
# Build Salvium shared/static libraries for macOS (arm64 + x86_64)
#
# Produces:
#   prebuilt/macos/libsalvium_crypto.dylib  (universal)
#   prebuilt/macos/libsalvium_ffi.dylib     (universal)
#   prebuilt/macos/libsalvium_crypto.a      (universal)
#   prebuilt/macos/libsalvium_ffi.a         (universal)
#
# Prerequisites:
#   rustup target add aarch64-apple-darwin x86_64-apple-darwin

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
OUT_DIR="$ROOT_DIR/prebuilt/macos"

TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

echo "==> Building Salvium libraries for macOS..."

for target in "${TARGETS[@]}"; do
  echo "  -> $target"
  cargo build --release \
    --target "$target" \
    -p salvium-crypto \
    -p salvium-ffi \
    --manifest-path "$ROOT_DIR/Cargo.toml"
done

echo "==> Creating universal binaries..."
mkdir -p "$OUT_DIR"

for lib in libsalvium_crypto libsalvium_ffi; do
  # Universal dylib
  lipo -create \
    "$ROOT_DIR/target/aarch64-apple-darwin/release/${lib}.dylib" \
    "$ROOT_DIR/target/x86_64-apple-darwin/release/${lib}.dylib" \
    -output "$OUT_DIR/${lib}.dylib"

  # Universal static lib
  lipo -create \
    "$ROOT_DIR/target/aarch64-apple-darwin/release/${lib}.a" \
    "$ROOT_DIR/target/x86_64-apple-darwin/release/${lib}.a" \
    -output "$OUT_DIR/${lib}.a"
done

echo "==> Done:"
ls -lh "$OUT_DIR/"*
