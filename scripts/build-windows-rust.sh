#!/usr/bin/env bash
set -euo pipefail

# Build privet-ffi for Windows (x86_64) and copy it where Flutter expects it.
#
# Usage:
#   bash scripts/build-windows-rust.sh          # debug build
#   bash scripts/build-windows-rust.sh release  # release build
#
# The Flutter Windows CMakeLists.txt looks for the DLL at
# target/release/privet_ffi.dll.  For debug development, this script
# builds with the debug profile but still stages the DLL at the
# release path so CMake can find it without regenerating.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

cargo build -p privet-ffi --release
# Already at target/release/privet_ffi.dll — no extra copy needed.
echo "---"
echo "privet_ffi.dll (release) built at target/release/privet_ffi.dll"

echo "Run 'flutter run -d windows' to launch."
