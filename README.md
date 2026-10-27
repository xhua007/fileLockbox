# FileLocker 文件保险箱

一款本地优先的加密文件保险箱，支持 macOS 与 Windows。文件在本地使用 AES-256-GCM 加密后保存，不依赖任何云服务。

当前主版本基于 **Tauri 2 + Rust + 原生 HTML/CSS/JS**；仓库同时保留了早期的 **SwiftUI / SwiftPM** 实现（`Sources/FileLocker`），仅支持 macOS 13+。

## 功能特性

- **本地加密存储**：文件写入磁盘前即完成加密，文件名与索引同样加密
- **文件与文件夹**：文件夹会自动打包为 zip 后整体加密，导出时自动还原
- **拖拽添加**：拖入文件/文件夹即可加入保险箱，重复项（同名同大小）自动跳过
- **搜索与批量操作**：支持关键字筛选、多选、批量导出 / 恢复 / 删除
- **打开与导出**：临时解密到应用临时目录供预览，或导出指定路径、恢复到原位置
- **安全删除**：删除条目时先解密并移入系统废纸篓，再清除密文
- **修改密码**：重新包装主密钥，无需重新加密已有文件
- **恢复码**：首次设置密码时生成 120 位熵的恢复码，忘记密码时可用于重置
- **记住密码**：可选将密码保存在系统钥匙串（不勾选则不落盘）
- **自动锁定**：默认 5 分钟无操作自动锁定，可在设置中调整；锁定时清理临时解密文件
- **深色模式**：跟随系统外观自动切换

## 安全设计

| 项目 | 实现 |
| --- | --- |
| 文件加密 | AES-256-GCM，每个 blob 使用随机 12 字节 nonce |
| 密钥派生 | PBKDF2-HMAC-SHA256，600,000 次迭代，16 字节随机盐 |
| 主密钥 | 运行时随机生成 256 位，不直接落盘 |
| 密码包装 | 密码派生 KEK 后 AES-GCM 包装主密钥（`keyring.json`） |
| 恢复码包装 | 独立盐派生 KEK 包装主密钥，与密码互不相关 |
| 索引 | 整个条目列表 JSON 使用主密钥加密后写入 `index.enc` |
| 恢复码格式 | 24 字符 Crockford Base32，形如 `ABCD-EFGH-JKLM-NPQR-STVW-XYZA`，输入时自动纠正常见混淆字符 |
| 临时文件 | 退出 / 锁定时清空临时解密目录 |

> 本项目为个人项目，尚未经过第三方安全审计。请务必离线备份恢复码；恢复码遗失且忘记密码时，数据无法找回。

## 技术栈

- **桌面框架**：Tauri 2
- **后端**：Rust（`aes-gcm`、`pbkdf2`、`sha2`、`hmac`、`zip`、`keyring`、`trash`、`directories`、`uuid`）
- **前端**：单文件 `src/index.html`（原生 HTML/CSS/JS，无构建步骤）
- **旧版实现**：SwiftUI（仅在 macOS 上通过 SwiftPM 构建，支持 Touch ID）

## 目录结构

```text
.
├── .github/workflows/build.yml   # tag 触发的 macOS / Windows 打包
├── src/                          # Tauri 前端（单文件页面）
├── src-tauri/                    # Rust 后端
│   ├── src/
│   │   ├── crypto.rs             # PBKDF2 派生、AES-256-GCM、恢复码
│   │   ├── vault.rs              # 保险箱核心逻辑（加解密、索引、导入导出）
│   │   ├── keychain.rs           # 系统钥匙串存取密码
│   │   ├── fs.rs                 # 废纸篓、打开路径、大小格式化
│   │   ├── models.rs             # 条目 / keyring / 配置数据结构
│   │   └── lib.rs                # Tauri 命令注册
│   ├── capabilities/default.json # 窗口权限
│   └── tauri.conf.json           # 应用与打包配置
├── scripts/
│   ├── build_dmg_tauri.sh        # 构建 macOS 通用版并生成 DMG
│   ├── build_dmg.sh              # 构建旧版 Swift 应用并生成 DMG
│   └── make_icon.swift           # 生成应用图标
├── Sources/FileLocker/           # 旧版 SwiftUI 实现（macOS 13+）
├── Package.swift
└── package.json
```

## 开发与构建

前置依赖：

- Node.js 20+
- Rust stable（1.70+）与 Cargo
- macOS：Xcode Command Line Tools；Windows：MSVC 工具链 + WebView2

```bash
# 安装依赖
npm install

# 开发模式（热重载）
npm run dev

# 构建安装包（输出到 src-tauri/target/release/bundle）
npm run build
```

macOS 通用版（arm64 + x86_64）DMG：

```bash
./scripts/build_dmg_tauri.sh
```

构建旧版 SwiftUI 应用（需 Xcode Command Line Tools）：

```bash
./scripts/build_dmg.sh
```

## 数据存储位置

应用数据目录由 `directories::ProjectDirs` 决定：

- macOS：`~/Library/Application Support/com.filelocker.FileLocker`
- Windows：`%APPDATA%\com\filelocker\FileLocker`

```text
com.filelocker.FileLocker/
├── config.json          # 自动锁定等配置
└── vault/
    ├── salt.bin         # 密码派生盐
    ├── keyring.json     # 密码 / 恢复码包装后的主密钥
    ├── index.enc        # 加密的条目索引
    ├── data/*.bin       # 加密后的文件与文件夹 blob
    └── tmp/             # 临时解密目录（锁定/退出时清空）
```

## 持续集成

[.github/workflows/build.yml](.github/workflows/build.yml) 会在推送 `v*` 标签或手动触发时运行：

- macOS：构建 universal 应用并输出 `.dmg`
- Windows：构建 `.msi` 与 NSIS `.exe`

```bash
git tag -a v1.0.0 -m "FileLocker v1.0.0"
git push origin v1.0.0
```

构建产物以 artifact 形式上传到对应的工作流运行记录中。
