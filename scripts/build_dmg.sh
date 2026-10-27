#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="FileLocker"
DISPLAY_NAME="文件保险箱"
VERSION="1.0.0"
BUNDLE_ID="com.example.FileLocker"

BUILD_DIR="build"
APP="$BUILD_DIR/$APP_NAME.app"
ICONSET="$BUILD_DIR/$APP_NAME.iconset"
MASTER_PNG="$BUILD_DIR/icon_master.png"

echo "==> 编译 release 可执行文件"
swift build --disable-sandbox -c release

echo "==> 组装 .app 包"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"

cp ".build/release/$APP_NAME" "$APP/Contents/MacOS/$APP_NAME"

cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleExecutable</key>
    <string>FileLocker</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.FileLocker</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>FileLocker</string>
    <key>CFBundleDisplayName</key>
    <string>文件保险箱</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
</dict>
</plist>
EOF

echo "==> 生成应用图标"
swift scripts/make_icon.swift "$MASTER_PNG"

rm -rf "$ICONSET"
mkdir -p "$ICONSET"
sips -z 16 16 "$MASTER_PNG" --out "$ICONSET/icon_16x16.png" >/dev/null
sips -z 32 32 "$MASTER_PNG" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
sips -z 32 32 "$MASTER_PNG" --out "$ICONSET/icon_32x32.png" >/dev/null
sips -z 64 64 "$MASTER_PNG" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$MASTER_PNG" --out "$ICONSET/icon_128x128.png" >/dev/null
sips -z 256 256 "$MASTER_PNG" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$MASTER_PNG" --out "$ICONSET/icon_256x256.png" >/dev/null
sips -z 512 512 "$MASTER_PNG" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$MASTER_PNG" --out "$ICONSET/icon_512x512.png" >/dev/null
cp "$MASTER_PNG" "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

echo "==> 代码签名（ad-hoc）"
codesign --force --deep --sign - "$APP"

echo "==> 生成 DMG"
STAGING="$BUILD_DIR/staging"
rm -rf "$STAGING"
mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/"
ln -s /Applications "$STAGING/Applications"

DMG="$BUILD_DIR/$APP_NAME.dmg"
rm -f "$DMG"
hdiutil create -volname "$DISPLAY_NAME" -srcfolder "$STAGING" -ov -format UDZO "$DMG" >/dev/null

echo ""
echo "完成：$DMG"
echo "应用：$APP"
