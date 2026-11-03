#!/usr/bin/env bash
# 检查当前项目代码是否满足 COMPATIBILITY_RULES.md 规范与回归测试
set -e

cd "$(dirname "$0")/.."
echo "================================================="
echo "🔍 开始执行 FileLocker 向后兼容性与健康检查..."
echo "================================================="

echo "1. 检查前端 JavaScript 语法..."
node -c src/app.js
echo "   ✅ 前端语法无异常"

echo "2. 检查 Rust 后端编译..."
cargo check --manifest-path src-tauri/Cargo.toml
echo "   ✅ Rust 编译检查通过"

echo "3. 执行向后兼容与安全回归单元测试..."
cargo test --manifest-path src-tauri/Cargo.toml
echo "   ✅ 所有兼容性与安全回归测试全部通过！"

echo "================================================="
echo "🎉 恭喜！当前修改完全符合 COMPATIBILITY_RULES.md"
echo "================================================="

