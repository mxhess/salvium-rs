#!/usr/bin/env bash
# Build Salvium shared libraries for Android (arm64, armv7, x86_64)
#
# Produces:
#   prebuilt/android/arm64-v8a/libsalvium_crypto.so
#   prebuilt/android/arm64-v8a/libsalvium_ffi.so
#   prebuilt/android/armeabi-v7a/libsalvium_crypto.so
#   prebuilt/android/armeabi-v7a/libsalvium_ffi.so
#   prebuilt/android/x86_64/libsalvium_crypto.so
#   prebuilt/android/x86_64/libsalvium_ffi.so
#
# Prerequisites:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   Set ANDROID_NDK_HOME to your NDK path (e.g. ~/Android/Sdk/ndk/26.1.10909125)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
OUT_DIR="$ROOT_DIR/prebuilt/android"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "Error: ANDROID_NDK_HOME is not set."
  echo "Set it to your Android NDK path, e.g.:"
  echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.1.10909125"
  exit 1
fi

# Parallel arrays — bash 3.2 compatible (no declare -A)
TARGETS=(        "aarch64-linux-android"             "armv7-linux-androideabi"             "x86_64-linux-android" )
TARGET_ABIS=(    "arm64-v8a"                         "armeabi-v7a"                         "x86_64"              )
TARGET_CCS=(     "aarch64-linux-android21-clang"     "armv7a-linux-androideabi21-clang"    "x86_64-linux-android21-clang" )

# Find the NDK toolchain bin directory
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$TOOLCHAIN" ]; then
  TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"
fi
if [ ! -d "$TOOLCHAIN" ]; then
  TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-aarch64/bin"
fi
if [ ! -d "$TOOLCHAIN" ]; then
  echo "Error: Cannot find NDK toolchain in $ANDROID_NDK_HOME"
  exit 1
fi

# Crates to build (order matters: ffi depends on crypto, but cargo handles that)
CRATES=("salvium-crypto" "salvium-ffi")

echo "==> Building Salvium libraries for Android"
echo "    NDK: $ANDROID_NDK_HOME"
echo "    Crates: ${CRATES[*]}"
echo ""

for i in "${!TARGETS[@]}"; do
  target="${TARGETS[$i]}"
  abi="${TARGET_ABIS[$i]}"
  cc="${TARGET_CCS[$i]}"
  echo "  ── $target ($abi) ──"

  # Set linker/compiler for this target via CARGO_TARGET env vars
  target_upper="${target//-/_}"
  target_upper="${target_upper^^}"
  export "CARGO_TARGET_${target_upper}_LINKER=$TOOLCHAIN/$cc"
  export "CC_${target//-/_}=$TOOLCHAIN/$cc"
  export "AR_${target//-/_}=$TOOLCHAIN/llvm-ar"
  export PATH="$TOOLCHAIN:$PATH"

  for crate in "${CRATES[@]}"; do
    echo "    Building $crate..."
    cargo build --release \
      --target "$target" \
      -p "$crate" \
      --manifest-path "$ROOT_DIR/Cargo.toml"
  done

  # Copy built .so files to prebuilt directory
  mkdir -p "$OUT_DIR/$abi"

  # salvium-crypto -> libsalvium_crypto.so
  cp "$ROOT_DIR/target/$target/release/libsalvium_crypto.so" \
     "$OUT_DIR/$abi/libsalvium_crypto.so"

  # salvium-ffi -> libsalvium_ffi.so
  cp "$ROOT_DIR/target/$target/release/libsalvium_ffi.so" \
     "$OUT_DIR/$abi/libsalvium_ffi.so"

  echo ""
done

echo "==> Done. Libraries:"
for i in "${!TARGETS[@]}"; do
  abi="${TARGET_ABIS[$i]}"
  echo "  $abi:"
  ls -lh "$OUT_DIR/$abi/"*.so
done
