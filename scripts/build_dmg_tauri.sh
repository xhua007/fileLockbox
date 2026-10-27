#!/usr/bin/env bash
# 构建 Tauri 版本并打包成 DMG（macOS，Intel + Apple Silicon 通用）
set -e

cd "$(dirname "$0")/.."
source "$HOME/.cargo/env"

echo "==> 构建通用版 App (arm64 + x86_64) ..."
npm run tauri build -- --target universal-apple-darwin --bundles app 2>&1 | tail -10

APP_DIR="src-tauri/target/universal-apple-darwin/release/bundle/macos"
APP_NAME="FileLocker.app"
APP_PATH="$APP_DIR/$APP_NAME"

if [ ! -d "$APP_PATH" ]; then
  echo "App 构建失败"
  exit 1
fi

echo "==> ad-hoc 签名 ..."
codesign --force --deep --sign - "$APP_PATH"

STAGING="build-tauri/staging"
rm -rf "$STAGING"
mkdir -p build-tauri
mkdir -p "$STAGING"
cp -R "$APP_PATH" "$STAGING/"
ln -s /Applications "$STAGING/Applications"

DMG_PATH="build-tauri/FileLocker-macOS-universal.dmg"
rm -f "$DMG_PATH"

echo "==> 生成 DMG ..."
hdiutil create -volname "FileLocker" \
  -srcfolder "$STAGING" \
  -ov -format UDZO \
  -imagekey zlib-level=9 \
  "$DMG_PATH"

echo "==> 签名 DMG (ad-hoc) ..."
codesign --force --sign - "$DMG_PATH" 2>/dev/null || true

SIZE=$(du -h "$DMG_PATH" | cut -f1)
echo
echo "✅ 打包完成: $DMG_PATH ($SIZE)"
echo "✅ App 位置: $APP_PATH"
