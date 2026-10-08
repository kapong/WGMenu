#!/bin/bash
# Build WGMenu.app with swiftc (Xcode Command Line Tools). Run as normal user.
set -euo pipefail
cd "$(dirname "$0")"
command -v swiftc >/dev/null || { echo "swiftc not found. Run: xcode-select --install"; exit 1; }
APP=build/WGMenu.app
rm -rf build
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -swift-version 5 -parse-as-library -O \
  -target arm64-apple-macos13.0 \
  Sources/*.swift -o "$APP/Contents/MacOS/WGMenu"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/wireguard.pdf "$APP/Contents/Resources/wireguard.pdf"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
codesign --force --sign - "$APP"
echo "Built $APP"
