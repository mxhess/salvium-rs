#!/usr/bin/env bash
# Build Salvium static libraries for iOS (device + simulator) as xcframeworks.
#
# Produces:
#   prebuilt/ios/SalviumCrypto.xcframework
#   prebuilt/ios/SalviumFfi.xcframework
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
OUT_DIR="$ROOT_DIR/prebuilt/ios"
WORK_DIR="$OUT_DIR/build"

TARGETS=(
  aarch64-apple-ios         # Device (arm64)
  aarch64-apple-ios-sim     # Simulator (Apple Silicon)
  x86_64-apple-ios          # Simulator (Intel)
)

# Libraries to build and package (parallel arrays — bash 3.2 compatible)
CRATES=(       "salvium-crypto"      "salvium-ffi"    )
LIB_NAMES=(    "libsalvium_crypto"   "libsalvium_ffi" )
FRAMEWORK_NAMES=( "SalviumCrypto"    "SalviumFfi"     )

echo "==> Building Salvium libraries for iOS targets..."

for target in "${TARGETS[@]}"; do
  echo "  -> $target"
  for crate in "${CRATES[@]}"; do
    cargo build --release \
      --target "$target" \
      -p "$crate" \
      --manifest-path "$ROOT_DIR/Cargo.toml"
  done
done

echo "==> Creating xcframeworks..."
mkdir -p "$WORK_DIR"

for i in "${!CRATES[@]}"; do
  lib="${LIB_NAMES[$i]}"
  framework="${FRAMEWORK_NAMES[$i]}"

  echo "  -> $framework.xcframework"

  # Device .a (single arch, no lipo needed)
  DEVICE_LIB="$ROOT_DIR/target/aarch64-apple-ios/release/${lib}.a"

  # Merge simulator slices (aarch64-sim + x86_64) into one fat .a
  SIM_FAT="$WORK_DIR/${lib}-sim.a"
  lipo -create \
    "$ROOT_DIR/target/aarch64-apple-ios-sim/release/${lib}.a" \
    "$ROOT_DIR/target/x86_64-apple-ios/release/${lib}.a" \
    -output "$SIM_FAT"

  # Remove old xcframework if present
  rm -rf "$OUT_DIR/$framework.xcframework"

  # Create xcframework from device .a + simulator fat .a
  xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" \
    -library "$SIM_FAT" \
    -output "$OUT_DIR/$framework.xcframework"
done

# Clean up work dir
rm -rf "$WORK_DIR"

echo "==> Done:"
ls -d "$OUT_DIR"/*.xcframework
