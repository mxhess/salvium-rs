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

# Minimum iOS version — must be consistent across Rust and C compilation.
# Prevents ___chkstk_darwin linker errors from vendored C code (OpenSSL/SQLCipher)
# being compiled with macOS settings instead of iOS.
export IPHONEOS_DEPLOYMENT_TARGET="14.0"

# Set cross-compilation C compiler per target so vendored C builds (openssl-sys,
# libsqlite3-sys) use the correct iOS SDK instead of the macOS host SDK.
export CC_aarch64_apple_ios="$(xcrun --sdk iphoneos --find clang)"
export CFLAGS_aarch64_apple_ios="-isysroot $(xcrun --sdk iphoneos --show-sdk-path) -mios-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"

export CC_aarch64_apple_ios_sim="$(xcrun --sdk iphonesimulator --find clang)"
export CFLAGS_aarch64_apple_ios_sim="-isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) -mios-simulator-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"

export CC_x86_64_apple_ios="$(xcrun --sdk iphonesimulator --find clang)"
export CFLAGS_x86_64_apple_ios="-isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) -mios-simulator-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"

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
