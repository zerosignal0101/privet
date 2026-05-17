#!/usr/bin/env bash
set -euo pipefail

# Build privet-ffi for Android ARM64.
# Prerequisites:
#   - Android NDK installed
#   - Rust target: rustup target add aarch64-linux-android
#   - Cargo config in .cargo/config.toml: linker = "aarch64-linux-android21-clang"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Detect NDK — try common locations on Windows, macOS, Linux
detect_ndk() {
  # 1. Explicit env vars
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    echo "$ANDROID_NDK_HOME"
    return
  fi
  # 2. ANDROID_HOME / SDK manager
  local sdk_root="${ANDROID_HOME:-$HOME/Android/Sdk}"
  if [ -d "$sdk_root/ndk" ]; then
    ls -d "$sdk_root/ndk/"* 2>/dev/null | sort -V | tail -1
    return
  fi
  # 3. Windows default (AppData\Local)
  local win_sdk="$HOME/AppData/Local/Android/Sdk"
  if [ -d "$win_sdk/ndk" ]; then
    ls -d "$win_sdk/ndk/"* 2>/dev/null | sort -V | tail -1
    return
  fi
  # 4. macOS Homebrew
  if [ -d "/usr/local/lib/android/sdk/ndk" ]; then
    ls -d "/usr/local/lib/android/sdk/ndk/"* 2>/dev/null | sort -V | tail -1
    return
  fi
  echo ""
}

NDK="$(detect_ndk)"
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
  echo "ERROR: Android NDK not found."
  echo "Set ANDROID_NDK_HOME or ANDROID_HOME to your SDK path."
  exit 1
fi
echo "Using NDK: $NDK"

# Detect host OS for prebuilt toolchain
case "$(uname -s)" in
  Linux)  HOST_TAG="linux-x86_64"   ;;
  Darwin) HOST_TAG="darwin-x86_64"  ;;
  MINGW*|MSYS*) HOST_TAG="windows-x86_64" ;;
  *)      HOST_TAG="windows-x86_64" ;;
esac

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG"
if [ ! -d "$TOOLCHAIN" ]; then
  echo "ERROR: toolchain not found at $TOOLCHAIN"
  exit 1
fi

# On Windows Git Bash, the .cmd wrapper is needed
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  CLANG="$TOOLCHAIN/bin/aarch64-linux-android21-clang.cmd"
else
  CLANG="$TOOLCHAIN/bin/aarch64-linux-android21-clang"
fi

export PATH="$TOOLCHAIN/bin:$PATH"
export CC_aarch64_linux_android="$CLANG"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"

cd "$PROJECT_DIR"
cargo build -p privet-ffi --target aarch64-linux-android --release

# Copy to Flutter jniLibs
JNILIBS="$PROJECT_DIR/privet_app/android/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNILIBS"
cp "target/aarch64-linux-android/release/libprivet_ffi.so" "$JNILIBS/libprivet_ffi.so"

echo "---"
echo "libprivet_ffi.so built and copied to $JNILIBS"
echo "Run 'flutter run' to deploy to your Android device."
