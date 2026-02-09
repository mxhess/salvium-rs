#!/usr/bin/env bash
# Build libsalvium_crypto.so for Android (arm64, armv7, x86_64)
#
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   Set ANDROID_NDK_HOME to your NDK path (e.g. ~/Android/Sdk/ndk/26.1.10909125)
#
# Produces:
#   prebuilt/android/arm64-v8a/libsalvium_crypto.so
#   prebuilt/android/armeabi-v7a/libsalvium_crypto.so
#   prebuilt/android/x86_64/libsalvium_crypto.so

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
CRATE_DIR="$ROOT_DIR/crates/salvium-crypto"
OUT_DIR="$ROOT_DIR/prebuilt/android"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "Error: ANDROID_NDK_HOME is not set."
  echo "Set it to your Android NDK path, e.g.:"
  echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.1.10909125"
  exit 1
fi

# Map Rust target -> Android ABI -> NDK toolchain target
declare -A TARGET_ABI=(
  [aarch64-linux-android]="arm64-v8a"
  [armv7-linux-androideabi]="armeabi-v7a"
  [x86_64-linux-android]="x86_64"
)

declare -A TARGET_CC=(
  [aarch64-linux-android]="aarch64-linux-android21-clang"
  [armv7-linux-androideabi]="armv7a-linux-androideabi21-clang"
  [x86_64-linux-android]="x86_64-linux-android21-clang"
)

# Find the NDK toolchain bin directory
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$TOOLCHAIN" ]; then
  # Try macOS path
  TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"
fi
if [ ! -d "$TOOLCHAIN" ]; then
  echo "Error: Cannot find NDK toolchain in $ANDROID_NDK_HOME"
  exit 1
fi

echo "==> Building salvium-crypto for Android targets..."
echo "    NDK: $ANDROID_NDK_HOME"

for target in "${!TARGET_ABI[@]}"; do
  abi="${TARGET_ABI[$target]}"
  cc="${TARGET_CC[$target]}"
  echo "  -> $target ($abi)"

  # Set linker for this target via CARGO_TARGET env vars
  target_upper="${target//-/_}"
  target_upper="${target_upper^^}"
  export "CARGO_TARGET_${target_upper}_LINKER=$TOOLCHAIN/$cc"
  export "CC_${target//-/_}=$TOOLCHAIN/$cc"
  export "AR_${target//-/_}=$TOOLCHAIN/llvm-ar"

  cargo build --release --target "$target" --manifest-path "$CRATE_DIR/Cargo.toml"

  mkdir -p "$OUT_DIR/$abi"
  cp "$CRATE_DIR/target/$target/release/libsalvium_crypto.so" \
     "$OUT_DIR/$abi/libsalvium_crypto.so"
done

echo "==> Done. Libraries:"
for target in "${!TARGET_ABI[@]}"; do
  abi="${TARGET_ABI[$target]}"
  ls -lh "$OUT_DIR/$abi/libsalvium_crypto.so"
done
