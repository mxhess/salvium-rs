#!/usr/bin/env bash
# Build libsalvium_crypto.a for iOS (device + simulator) as an xcframework.
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Produces: prebuilt/ios/SalviumCrypto.xcframework

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
CRATE_DIR="$ROOT_DIR/crates/salvium-crypto"
OUT_DIR="$ROOT_DIR/prebuilt/ios"
WORK_DIR="$OUT_DIR/build"

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

echo "==> Creating xcframework..."
mkdir -p "$WORK_DIR"

# Device .a (single arch, no lipo needed)
DEVICE_LIB="$CRATE_DIR/target/aarch64-apple-ios/release/libsalvium_crypto.a"

# Merge simulator slices (aarch64-sim + x86_64) into one fat .a
SIM_FAT="$WORK_DIR/libsalvium_crypto-sim.a"
lipo -create \
  "$CRATE_DIR/target/aarch64-apple-ios-sim/release/libsalvium_crypto.a" \
  "$CRATE_DIR/target/x86_64-apple-ios/release/libsalvium_crypto.a" \
  -output "$SIM_FAT"

# Remove old xcframework if present
rm -rf "$OUT_DIR/SalviumCrypto.xcframework"

# Create xcframework from device .a + simulator fat .a
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" \
  -library "$SIM_FAT" \
  -output "$OUT_DIR/SalviumCrypto.xcframework"

# Clean up work dir
rm -rf "$WORK_DIR"

echo "==> Done: $OUT_DIR/SalviumCrypto.xcframework"

