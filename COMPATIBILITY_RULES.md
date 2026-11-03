# FileLocker 版本升级与向后兼容设计规范 (COMPATIBILITY_RULES.md)

> **核心原则**：用户的加密数据资产高于一切。任何版本升级均必须严格遵守 **“向前兼容读取，向后静默升级” (Read Old, Write New)**，确保用户跨版本更新客户端时实现 **0 数据丢失、0 解密失败、0 迁移中断**。

---

## 目录
- [一、持久化数据与元数据版本化](#一持久化数据与元数据版本化)
- [二、KDF 密钥派生：自适应读取与单向升级](#二kdf-密钥派生自适应读取与单向升级)
- [三、Serde 数据结构：宽进严出规范](#三serde-数据结构宽进严出规范)
- [四、启动期自动迁移管道 (Auto-Migration Pipeline)](#四启动期自动迁移管道-auto-migration-pipeline)
- [五、CI 自动化“祖传测试资产”保障 (Golden Test Fixtures)](#五ci-自动化祖传测试资产保障-golden-test-fixtures)
- [六、版本变更与发布检查清单 (Checklist)](#六版本变更与发布检查清单-checklist)

---

## 一、持久化数据与元数据版本化

落盘的任何数据（包括加密 blob、keyring、索引、配置文件）**绝对禁止**假设“运行环境与生成环境代码一致”。所有持久化实体必须能够自报版本与参数。

### 1.1 文件加密流魔数规范 (Magic Number)
所有的加密文件必须在文件头部写入固定的协议魔数（Magic Header）：

| 格式标识 | 格式描述 | 兼容策略 |
| :--- | :--- | :--- |
| **无魔数** | 历史 v0 单 blob 格式（整个文件一次性 AES-GCM 加密） | **保留只读解密分支**。若文件不以 `FLCK_CHUNK` 开头，自动回退到单 blob 解密。 |
| `FLCK_CHUNK\x01\x00` | 历史 v1 流式分块（无分块序号与 AAD 认证） | **保留只读解密分支**。允许正确流式还原。 |
| `FLCK_CHUNK\x02\x00` | 当前 v2 流式分块（AAD 绑定分块序号、大小与结束标记） | 当前写入默认标准。 |

> ⚠️ **严禁规则**：未来如果引入 v3（例如添加压缩支持或更替密码算法），**严禁直接修改或删除 v0 / v1 / v2 的解密实现**。新格式必须使用新魔数（如 `FLCK_CHUNK\x03\x00`），旧解密代码转为只读兼容层永久保留。

### 1.2 Keyring 元数据自报家门
主密钥包装文件（`keyring.json`）必须显式持久化其派生所使用的参数与算法，不得硬编码在编译期常量中。

```json
{
  "version": 3,
  "kdf_type": "pbkdf2-hmac-sha256",
  "iterations": 600000,
  "recovery_iterations": 600000,
  "password_wrap": [ ... ],
  "recovery_salt": [ ... ],
  "recovery_wrap": [ ... ]
}
```

---

## 二、KDF 密钥派生：自适应读取与单向升级

在软件演进中，因对抗算力增长（如防范 AI 与 GPU 集群离线爆破），安全基线（如 PBKDF2 迭代次数、甚至迁移到 Argon2id）必然会提升。此时必须遵循 **机会性升级（Opportunistic Upgrade）** 策略：

```
                    ┌─────────────────────────┐
                    │ 用户输入密码发起解锁请求  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ 读取 Keyring 声明的参数   │
                    │ (如历史的 100k / 120k)   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ 用旧参数成功解密主密钥 MK │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              ▼                                     ▼
   【若当前参数 < 目标基线 600k】              【若当前参数已是最新】
              │                                     │
              ▼                                     ▼
 ┌─────────────────────────┐               ┌─────────────────┐
 │ 在内存中以最新 600k 参数  │               │ 直接进入主界面   │
 │ 重新加密包装主密钥       │               └─────────────────┘
 └────────────┬────────────┘
              │
              ▼
 ┌─────────────────────────┐
 │ 原子刷盘覆盖 Keyring    │
 │ (完成静默单向升级)      │
 └─────────────────────────┘
```

### 规则要求：
1. **读取时极度包容**：解密函数必须接受任意历史迭代次数（120,000 / 100,000 / 600,000），绝不能因参数旧而拒绝尝试。
2. **解锁后单向升级**：仅在“密码验证成功且获得明文主密钥”的瞬间升级 Keyring 并回写磁盘。**绝不降级**。
3. **用户无感**：升级过程对用户透明，无需弹出繁琐的“数据格式转换”警告，避免造成恐慌。

---

## 三、Serde 数据结构：宽进严出规范

在 Rust 中处理落盘的 JSON（如 `keyring.json`、`index.enc` 序列化结构、`config.json`、`vaults.json`）时，必须执行“宽进严出”原则，防止因字段缺失或字段命名规则变动引发崩溃。

### 3.1 字段别名（Serde Alias）
所有曾受历史版本命名影响的字段，必须保留别名支持（包括 Swift 时代的驼峰命名与 Rust 时代的蛇形命名）：

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct Keyring {
    pub version: u32,

    #[serde(alias = "passwordWrap")]
    pub password_wrap: Vec<u8>,

    #[serde(alias = "recoverySalt")]
    pub recovery_salt: Vec<u8>,

    #[serde(alias = "recoveryWrap")]
    pub recovery_wrap: Vec<u8>,

    #[serde(default)]
    pub iterations: Option<u32>,
}
```

### 3.2 新增字段必须标记 `#[serde(default)]`
- 任何新增字段**必须且只能**是 `Option<T>` 或者具备 `#[serde(default)]`。
- **严禁**直接向持久化模型中添加必选字段（non-optional / non-default），否则读取旧版生成的 JSON 时会直接报反序列化错误。

---

## 四、启动期自动迁移管道 (Auto-Migration Pipeline)

当应用发生物理路径变更、数据分库目录演变或系统级配置迁移时，**严禁依赖用户手动操作**。必须在 Rust 后端 `app_init` 阶段内置启动迁移器。

### 4.1 目录迁移规范
若由于应用标识（Bundle Identifier）更迭导致存储目录变动（例如早期路径 `FileLocker/` 与正式路径 `com.filelocker.FileLocker/`）：

1. **自动探测**：启动时检测新路径是否存在有效的 `vault`；
2. **自动搬迁**：若新路径为空且检测到合法的旧路径，自动执行目录平滑复制（保留原始文件作备份，直至新路径验证成功）；
3. **钥匙串平滑过渡**：尝试从旧服务名（如 `com.filelocker.vault`）读取凭证，若成功读取，自动写入新服务名（`com.filelocker.FileLocker`），并删除旧条目。

### 4.2 迁移函数模板
```rust
/// 在 VaultManager 初始化前必须调用的轻量迁移流水线
pub fn run_startup_migrations(app_data_dir: &Path) {
    let legacy_mac_dir = dirs::home_dir()
        .map(|h| h.join("Library/Application Support/FileLocker"));
    
    if let Some(old_dir) = legacy_mac_dir {
        if old_dir.exists() && !app_data_dir.join("vault").exists() {
            log::info!("检测到历史版本数据目录，开始自动迁移...");
            let _ = migrate_legacy_directory(&old_dir, app_data_dir);
        }
    }
}
```

---

## 五、CI 自动化“祖传测试资产”保障 (Golden Test Fixtures)

无论文档制定得多完备，人为疏漏不可避免。**最可靠的防线是自动化测试 (Unit & Integration Tests)**。

### 5.1 历史样本库 (Fixtures)
在代码库中永久维护测试资产目录 `src-tauri/tests/fixtures/`：
- `fixtures/v1_vault/`：包含 v1.0.0 正式版生成的加密文件、keyring 和 index；
- `fixtures/v2_vault/`：包含多保险箱架构初期的加密数据包。

### 5.2 兼容性回归测试断言
每次运行 `cargo test` 或在 GitHub Actions 执行 CI 时，必须执行向后兼容回归测试：

```rust
#[test]
fn test_regression_can_unlock_and_decrypt_v1_fixtures() {
    let fixture_path = Path::new("tests/fixtures/v1_vault");
    if !fixture_path.exists() {
        return; // 测试用例准备中
    }
    
    let mut vm = VaultManager::load_from_path(fixture_path);
    // 验证能否正确用旧版密码解锁
    let unlock_res = vm.unlock("TestPassword123!", false);
    assert!(unlock_res.is_ok(), "必须能解锁历史 v1 固化测试库！");
    
    // 验证能否完整还原旧版加密文件明文
    let decrypted = vm.decrypt_entry_to_memory("test-entry-id");
    assert_eq!(decrypted.unwrap(), b"Hello, World from v1.0.0!");
}
```
> 只要任何重构不小心破坏了解锁旧库的逻辑，CI 立即变红拦截发布。

---

## 六、版本变更与发布检查清单 (Checklist)

在合并 PR 或打包新版本前，开发者必须逐项核对：

- [ ] **是否修改了落盘文件格式？**
  - [ ] 若修改了，是否更新了 `version` 标识？
  - [ ] 是否在解密代码中保留了对老版本的只读解析支持？
- [ ] **是否修改了 Serde 数据模型？**
  - [ ] 所有新增字段是否都标有 `#[serde(default)]`？
  - [ ] 字段改名是否配置了 `#[serde(alias = "...")]`？
- [ ] **是否升级了加密算法或 KDF 迭代次数？**
  - [ ] 旧库使用旧参数是否仍能正确派生解密？
  - [ ] 解锁后是否能单向静默升级？
- [ ] **是否变动了存储路径或系统钥匙串命名？**
  - [ ] 启动期是否包含自动探测与迁移逻辑？
- [ ] **自动化兼容测试是否通过？**
  - [ ] 本地执行 `cargo test` 全量通过（无 regression）。

