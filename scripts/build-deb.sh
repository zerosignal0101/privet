#!/usr/bin/env bash
# Build Privet .deb package for Debian/Ubuntu.
#
# Prerequisites (build-time):
#   sudo apt install cmake ninja-build clang pkg-config libgtk-3-dev
#   rustup toolchain install stable
#   flutter (with Linux desktop support enabled)
#
# Build order:
#   1. cargo build -p privet-ffi --release       # Rust FFI library
#   2. flutter build linux --release              # Flutter app
#   3. bash scripts/build-deb.sh                  # Package .deb
#
set -euo pipefail

APP_NAME="Privet"
BUNDLE="privet_app/build/linux/x64/release/bundle"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_DIR/dist"

# Extract version from pubspec.yaml
VERSION=$(grep '^version:' "$REPO_DIR/privet_app/pubspec.yaml" | sed 's/version: *//' | sed 's/+.*//')

DEB_NAME="${APP_NAME,,}_${VERSION}_amd64"
DEB_DIR="/tmp/$DEB_NAME"

echo "==> Building $APP_NAME v$VERSION .deb"

# Ensure the Flutter bundle exists
if [ ! -f "$REPO_DIR/$BUNDLE/$APP_NAME" ]; then
  echo "ERROR: Flutter bundle not found. Run 'flutter build linux --release' first."
  echo "  cd privet_app && flutter build linux --release"
  exit 1
fi

# Clean and create package directory
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/lib/$APP_NAME/lib"
mkdir -p "$DEB_DIR/usr/bin"

# ---- Copy app bundle ----
echo "==> Copying app bundle..."
cp "$REPO_DIR/$BUNDLE/$APP_NAME" "$DEB_DIR/usr/lib/$APP_NAME/"
cp "$REPO_DIR/$BUNDLE/lib"/*.so "$DEB_DIR/usr/lib/$APP_NAME/lib/"
cp -r "$REPO_DIR/$BUNDLE/data" "$DEB_DIR/usr/lib/$APP_NAME/"

# ---- Desktop integration ----
mkdir -p "$DEB_DIR/usr/share/applications"
cp "$REPO_DIR/$BUNDLE/share/applications/com.privet.privet_app.desktop" \
   "$DEB_DIR/usr/share/applications/"
# Update Exec to point to the actual binary location
sed -i 's|Exec=Privet|Exec=/usr/bin/privet|' \
  "$DEB_DIR/usr/share/applications/com.privet.privet_app.desktop"

# ---- Icons (multiple sizes) ----
for size in 64 128 256 512; do
  mkdir -p "$DEB_DIR/usr/share/icons/hicolor/${size}x${size}/apps"
  cp "$REPO_DIR/$BUNDLE/share/icons/hicolor/${size}x${size}/apps/com.privet.privet_app.png" \
     "$DEB_DIR/usr/share/icons/hicolor/${size}x${size}/apps/"
done

# ---- Metainfo ----
mkdir -p "$DEB_DIR/usr/share/metainfo"
cp "$REPO_DIR/$BUNDLE/share/metainfo/com.privet.privet_app.metainfo.xml" \
   "$DEB_DIR/usr/share/metainfo/"

# ---- Symlink for PATH access ----
ln -s /usr/lib/$APP_NAME/$APP_NAME "$DEB_DIR/usr/bin/${APP_NAME,,}"

# ---- DEBIAN/control ----
cat > "$DEB_DIR/DEBIAN/control" <<EOF
Package: ${APP_NAME,,}
Version: $VERSION
Architecture: amd64
Maintainer: Privet Team <https://github.com/zerosignal/privet>
Section: net
Priority: optional
Depends: libgtk-3-0 (>= 3.24),
         libglib2.0-0 (>= 2.56),
         libstdc++6 (>= 9),
         libc6 (>= 2.31),
         xclip | wl-clipboard
Recommends: wl-clipboard
Description: LAN file transfer tool
 Privet is a peer-to-peer file transfer application for local networks.
 It uses QUIC (with TCP fallback) for fast, secure transfers between
 devices on the same LAN without needing a central server.
 .
 Features:
  • Zero-configuration discovery (mDNS, UDP beacon, subnet scan)
  • Encrypted transfers via mutual TLS
  • Drag-and-drop and clipboard paste support
  • Cross-platform (Linux, Windows, Android)
EOF

# ---- DEBIAN/postinst ----
cat > "$DEB_DIR/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

APP_NAME="Privet"

# Update icon cache if possible
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
fi

# Update desktop database if possible
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database >/dev/null 2>&1 || true
fi

echo "=== $APP_NAME installed ==="
echo "For clipboard file/image support, ensure xclip or wl-clipboard is installed:"
echo "  sudo apt install xclip           # X11"
echo "  sudo apt install wl-clipboard    # Wayland"
POSTINST
chmod 755 "$DEB_DIR/DEBIAN/postinst"

# ---- DEBIAN/prerm (clean up symlink on removal) ----
cat > "$DEB_DIR/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
# The symlink /usr/bin/privet is inside the package, dpkg removes it automatically.
PRERM
chmod 755 "$DEB_DIR/DEBIAN/prerm"

# ---- Build .deb ----
echo "==> Building .deb package..."
mkdir -p "$DIST_DIR"
fakeroot dpkg-deb --build "$DEB_DIR" "$DIST_DIR/${DEB_NAME}.deb"

# Cleanup
rm -rf "$DEB_DIR"

echo ""
echo "==> Done: $DIST_DIR/${DEB_NAME}.deb"
echo "    Install with: sudo dpkg -i $DIST_DIR/${DEB_NAME}.deb"
echo "    Uninstall with: sudo apt remove ${APP_NAME,,}"
