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

# Minimum iOS version — consistent across Rust and all vendored C compilation.
export IPHONEOS_DEPLOYMENT_TARGET="14.0"

for target in "${TARGETS[@]}"; do
  echo "  -> $target"

  # Determine the correct Apple SDK for this target
  case "$target" in
    aarch64-apple-ios)
      sdk="iphoneos"
      min_ver_flag="-mios-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"
      ;;
    *)
      sdk="iphonesimulator"
      min_ver_flag="-mios-simulator-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"
      ;;
  esac

  SDK_PATH="$(xcrun --sdk "$sdk" --show-sdk-path)"
  CC_PATH="$(xcrun --sdk "$sdk" --find clang)"
  AR_PATH="$(xcrun --sdk "$sdk" --find ar)"
  RANLIB_PATH="$(xcrun --sdk "$sdk" --find ranlib)"

  # Env var key: aarch64-apple-ios -> aarch64_apple_ios
  target_env="${target//-/_}"

  # ── cc crate (libsqlite3-sys / SQLCipher build) ──
  export "CC_${target_env}=${CC_PATH}"
  export "CFLAGS_${target_env}=-isysroot ${SDK_PATH} ${min_ver_flag}"
  export "AR_${target_env}=${AR_PATH}"
  export "RANLIB_${target_env}=${RANLIB_PATH}"

  # ── openssl-src (uses its own Configure/make, not the cc crate) ──
  # OpenSSL ios64-xcrun / iossimulator-xcrun configs look up the SDK via
  # CROSS_TOP + CROSS_SDK (e.g. .../iPhoneOS.platform/Developer + iPhoneOS17.0.sdk).
  # Without these, openssl-src falls back to the macOS host SDK and produces
  # ___chkstk_darwin references that don't exist on iOS.
  PLATFORM_DIR="${SDK_PATH%/SDKs/*}"          # .../iPhoneOS.platform/Developer
  SDK_NAME="${SDK_PATH##*/}"                   # iPhoneOS17.0.sdk
  export CROSS_TOP="$PLATFORM_DIR"
  export CROSS_SDK="$SDK_NAME"

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
