# FileLocker 文件保险箱

一款本地优先的加密文件保险箱，支持 macOS 与 Windows。文件在本地使用 AES-256-GCM 加密后保存，不依赖任何云服务。

本项目基于 **Tauri 2 + Rust + 原生 HTML/CSS/JS** 构建，一套代码在 macOS 与 Windows 上实现 100% 一致的功能体验。

## 功能特性

- **本地加密存储**：文件写入磁盘前即完成加密，文件名与索引同样加密
- **超大文件流式分块加密**：按 2MB 分块流式加密/解密，峰值内存占用恒定 ~4MB，流畅支持数 GB 级超大文件，向下 100% 兼容历史单 blob 格式
- **条目行内重命名**：支持快捷键（F2）、右键上下文菜单或条目操作栏一键重命名已加密文件/文件夹
- **多保险箱切换与独立管理**：支持创建多个独立保险箱（如工作档案、私人照片等），各自拥有独立的数据目录、加密主密钥、密码及钥匙串凭证，支持一键切换、重命名与安全清理
- **文件与文件夹**：文件夹会自动打包为 zip 后整体加密，导出时自动还原
- **拖拽添加**：拖入文件/文件夹即可加入保险箱，重复项（同名同大小）自动跳过
- **搜索与批量操作**：支持关键字筛选、多选、批量导出 / 恢复 / 删除
- **打开与导出**：临时解密到应用临时目录供预览，或导出指定路径、恢复到原位置
- **彻底删除条目**：删除条目时移除密文 blob 与索引，不留在系统废纸篓；临时解密出的明文会先尽力覆写再删除（受 SSD / CoW 文件系统限制，覆写不保证物理擦除，安全边界仍建立在加密上）
- **崩溃容灾保护**：索引与 Keyring 采用临时文件刷盘 + 原子替换，并自动维护 `index.enc.bak` 备份，防止异常断电导致索引损毁
- **修改密码**：重新包装主密钥，无需重新加密已有文件
- **恢复码**：首次设置密码时生成 120 位熵的恢复码，忘记密码时可用于重置
- **记住密码**：可选将主密码保存在系统钥匙串，解锁时免输入。这是系统凭据存储，**不包含指纹 / 人脸等生物识别门控**；不勾选则密码不落盘
- **自动锁定**：默认 5 分钟无操作自动锁定，可在设置中调整；锁定时清理临时解密文件
- **深色模式**：跟随系统外观自动切换

## 安全设计

| 项目         | 实现                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------ |
| 文件加密     | AES-256-GCM，流式 2MB 分块加密（独立 Nonce、结尾防篡改标记）+ 历史单 blob 自动识别         |
| 密钥派生     | PBKDF2-HMAC-SHA256，600,000 次迭代（旧版 100,000 次自动升级），16 字节随机盐               |
| 主密钥       | 运行时随机生成 256 位，不直接落盘                                                          |
| 密码包装     | 密码派生 KEK 后 AES-GCM 包装主密钥（`keyring.json`，原子写入）                             |
| 恢复码包装   | 独立盐派生 KEK 包装主密钥，与密码互不相关                                                  |
| 索引与备份   | 整个条目列表 JSON 使用主密钥加密，采用原子落盘并自动保留 `index.enc.bak` 容灾              |
| 内存安全     | 锁定时对主密钥与临时派生 KEK 进行零化擦除 (Zeroize)                                        |
| 多保险箱隔离 | 钥匙串服务独立命名（`com.filelocker.vault.<id>`），默认保险箱保留原有命名保持兼容          |
| 恢复码格式   | 24 字符 Crockford Base32，形如 `ABCD-EFGH-JKLM-NPQR-STVW-XYZA`，输入时自动纠正常见混淆字符 |
| 临时文件     | 启动 / 退出 / 锁定时自动清空临时解密目录                                                   |

> 本项目为个人项目，尚未经过第三方安全审计。请务必离线备份恢复码；恢复码遗失且忘记密码时，数据无法找回。

## 技术栈

- **桌面框架**：Tauri 2
- **后端**：Rust（`aes-gcm`、`pbkdf2`、`sha2`、`hmac`、`zip`、`keyring`、`trash`、`directories`、`uuid`）
- **前端**：单文件 `src/index.html`（原生 HTML/CSS/JS，无构建步骤）

## 目录结构

```text
.
├── .github/workflows/build.yml   # tag 触发的 macOS / Windows 打包
├── src/                          # Tauri 前端（单文件页面）
├── src-tauri/                    # Rust 后端
│   ├── src/
│   │   ├── crypto.rs             # PBKDF2 派生、AES-256-GCM、流式分块加解密、恢复码
│   │   ├── vault.rs              # 保险箱核心逻辑（多保险箱、索引、导入导出、重命名）
│   │   ├── keychain.rs           # 系统钥匙串 / 凭据管理器存取密码
│   │   ├── fs.rs                 # 废纸篓/回收站、打开路径、大小格式化
│   │   ├── models.rs             # 条目 / keyring / 配置数据结构
│   │   └── lib.rs                # Tauri 命令注册与窗口事件
│   ├── capabilities/default.json # 窗口权限
│   └── tauri.conf.json           # 应用与打包配置
├── scripts/
│   └── build_dmg_tauri.sh        # 构建 macOS 通用版并生成 DMG
└── package.json
```

## 开发与构建

### 1. 前置环境

- **Node.js**：20+
- **Rust**：stable（1.70+）与 Cargo
- **系统工具链**：
  - macOS：Xcode Command Line Tools (`xcode-select --install`)
  - Windows：MSVC C++ 构建工具链 + WebView2 Runtime

### 2. 安装依赖

首次运行前需安装前端与 CLI 依赖：

```bash
npm install
```

### 3. 本地运行项目（开发模式）

通过以下命令启动应用开发模式：

```bash
npm run dev
```

- **自动编译**：会自动编译 Rust 后端代码并拉起原生客户端窗口。
- **热重载**：修改前端代码（`src/index.html` 等）后无需重启，自动实时刷新页面。

### 4. 运行单元测试

验证加解密逻辑、恢复码生成、原子写入与索引容灾自愈：

```bash
cd src-tauri && cargo test
```

### 5. 本地打包与自用安装指南

#### 打包前准备（可选但建议）

如果近期有大范围代码修改或出现过 LLVM 增量缓存报错，建议先清理一次旧缓存以保证构建纯净：

```bash
cd src-tauri && cargo clean && cd ..
```

---

#### 方式一：快速构建并直接安装到本机（推荐个人使用）

若仅供本机日常使用，无需经历磁盘映像制作过程，直接构建原生 `.app` 最为迅速：

1. **编译原生 App 产物**：
   ```bash
   npx tauri build --bundles app
   ```
2. **安装到 macOS 系统的「应用程序」**：
   ```bash
   cp -R src-tauri/target/release/bundle/macos/FileLocker.app /Applications/
   ```
   _也可以在终端运行 `open src-tauri/target/release/bundle/macos`，直接在访达窗口中将 `FileLocker.app` 拖入左侧边栏的「应用程序」文件夹。_

---

#### 方式二：标准 DMG 安装镜像打包（跨平台标准方式）

生成带图形拖拽安装界面的 `.dmg` 文件：

```bash
npm run build
```

打包完成后产物输出位置：

- **macOS**：
  - DMG 安装包：`src-tauri/target/release/bundle/dmg/FileLocker_1.0.0_aarch64.dmg`（Apple Silicon）或相应架构包
  - App 应用程序：`src-tauri/target/release/bundle/macos/FileLocker.app`
- **Windows**：
  - MSI 安装包：`src-tauri/target/release/bundle/msi/*.msi`
  - NSIS 安装程序：`src-tauri/target/release/bundle/nsis/*.exe`

---

#### 方式三：打包 macOS 通用版 DMG（Universal，同时支持 M 系列与 Intel）

适合分发给其他不同芯片架构的 Mac 电脑使用：

```bash
./scripts/build_dmg_tauri.sh
```

- 输出产物位于：`build-tauri/FileLocker-macOS-universal.dmg`（内置 Applications 替身快捷方式，双击即可拖入安装）。

---

#### ⚠️ 首次启动注意说明（macOS Gatekeeper 安全提示）

由于个人本地编译的应用未购买苹果年费开发者证书（采用本地签名），macOS 首次打开时可能会提示 **“无法打开，因为无法验证开发者”**。只需任选以下一种方式授权一次即可：

- **方式 A（最快捷）**：在访达「应用程序」中找到 **FileLocker**，**按住 Control 键并点击它（或右键）-> 选择「打开」-> 在弹出的确认弹窗中点击「打开」**；
- **方式 B**：打开 Mac **「系统设置」->「隐私与安全性」**，向下滑动找到 _已阻止使用 FileLocker_，点击其右侧的 **「仍要打开」**。

_首次授权后，即可在 Launchpad、Spotlight 或程序坞中正常双击秒开。_

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
