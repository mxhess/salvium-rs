#!/usr/bin/env bash
set -euo pipefail

# Build the QuickJS-compatible wallet bundle for the Flutter app.
#
# Format: IIFE with global name "SalviumJS" — QuickJS evaluate() requires
# a script, not an ESM module. The IIFE wraps everything as:
#   var SalviumJS = (() => { ... })()
#
# After building, copies the bundle into the Flutter assets directory.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLUTTER_ASSETS="$SCRIPT_DIR/../whiskywallet_flutter/assets"

cd "$SCRIPT_DIR"

bun x esbuild \
  src/wallet-bundle-entry.js \
  --bundle \
  --format=iife \
  --global-name=SalviumJS \
  --platform=neutral \
  --target=es2020 \
  --outfile=dist/salvium-wallet-bundle.js \
  --external:bun:ffi \
  --external:fs/promises \
  --external:url \
  --external:path

cp dist/salvium-wallet-bundle.js "$FLUTTER_ASSETS/salvium-js-bundle.js"

echo "Bundle copied to $FLUTTER_ASSETS/salvium-js-bundle.js"

