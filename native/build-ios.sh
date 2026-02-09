#!/usr/bin/env bash
# Build libsalvium_crypto.a for iOS (device + simulator)
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Produces: native/lib/ios/libsalvium_crypto.a (universal fat binary via lipo)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRATE_DIR="$SCRIPT_DIR/../crates/salvium-crypto"
OUT_DIR="$SCRIPT_DIR/lib/ios"

TARGETS=(
  aarch64-apple-ios         # Device (arm64)
  aarch64-apple-ios-sim     # Simulator (Apple Silicon)
  x86_64-apple-ios          # Simulator (Intel)
)

echo "==> Building salvium-crypto for iOS targets..."

for target in "${TARGETS[@]}"; do
  echo "  -> $target"
  cargo build --release --target "$target" --manifest-path "$CRATE_DIR/Cargo.toml"
done

echo "==> Creating universal binary with lipo..."
mkdir -p "$OUT_DIR"

# Collect all .a paths
LIBS=()
for target in "${TARGETS[@]}"; do
  LIBS+=("$CRATE_DIR/../../target/$target/release/libsalvium_crypto.a")
done

lipo -create "${LIBS[@]}" -output "$OUT_DIR/libsalvium_crypto.a"

echo "==> Done: $OUT_DIR/libsalvium_crypto.a"
lipo -info "$OUT_DIR/libsalvium_crypto.a"
