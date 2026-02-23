#!/usr/bin/env bash
# Build salvium-crypto as a WASM package for browser/Cloudflare Workers.
#
# Produces:
#   prebuilt/wasm/salvium_crypto.js
#   prebuilt/wasm/salvium_crypto_bg.wasm
#   prebuilt/wasm/salvium_crypto.d.ts
#   prebuilt/wasm/package.json
#
# Prerequisites:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-pack
#
# For Cloudflare Workers, import with:
#   import * as salvium from './salvium_crypto';

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
OUT_DIR="$ROOT_DIR/prebuilt/wasm"

# Default to bundler target (works with Workers, Webpack, Vite, etc.)
# Use --target web for plain <script> usage, --target nodejs for Node.
TARGET="${WASM_TARGET:-bundler}"

echo "==> Building salvium-crypto WASM package (target: $TARGET)..."

wasm-pack build \
  "$ROOT_DIR/crates/salvium-crypto" \
  --release \
  --target "$TARGET" \
  --out-dir "$OUT_DIR" \
  --out-name salvium_crypto

# Remove wasm-pack's generated .gitignore (we want to commit/ship this)
rm -f "$OUT_DIR/.gitignore"

echo ""
echo "==> Done:"
ls -lh "$OUT_DIR/"*

echo ""
echo "Exports:"
if command -v wasm-objdump &>/dev/null; then
  wasm-objdump -x "$OUT_DIR/salvium_crypto_bg.wasm" | grep "^ - func" | head -20
  echo "  ..."
else
  echo "  (install wabt for wasm-objdump to list exports)"
fi
