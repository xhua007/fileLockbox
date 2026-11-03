use crate::crypto;
use crate::fs as vfs;
use crate::keychain;
use crate::models::{AppConfig, CreateVaultResult, Keyring, VaultEntry, VaultInfo, VaultProfile};
use chrono::Utc;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

#[derive(Debug)]
pub struct VaultManager {
    pub entries: Vec<VaultEntry>,
    /// 主密钥使用 ProtectedMasterKey 锁定在物理内存（mlock），防止 swap 到磁盘，离开作用域时自动清零与解锁。
    pub master_key: Option<crypto::ProtectedMasterKey>,
    pub is_unlocked: bool,
    pub data_base: PathBuf,
    pub current_vault_id: String,
    pub current_vault_name: String,
    pub vault_dir: PathBuf,
    pub data_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub config_path: PathBuf,
    pub auto_lock_minutes: u64,
    pub failed_attempts: u32,
    pub lockout_until: Option<i64>,
    pub recovery_failed_attempts: u32,
    pub recovery_lockout_until: Option<i64>,
    /// 最近一次有效操作的时间戳（秒）。存放在 Cell 中以便 `&self` 方法也能刷新，
    /// 由 Rust 侧后台线程据此执行权威的空闲自动锁定。
    pub last_activity: Cell<i64>,
}

/// 防爆破状态：落盘保存，重启应用后仍然生效，避免「关掉再开」重置失败计数。
#[derive(Serialize, Deserialize, Default, Clone)]
struct GuardState {
    #[serde(default)]
    failed_attempts: u32,
    #[serde(default)]
    lockout_until: Option<i64>,
    #[serde(default)]
    recovery_failed_attempts: u32,
    #[serde(default)]
    recovery_lockout_until: Option<i64>,
}

/// security.json：按保险箱 id 隔离的防爆破状态集合。
#[derive(Serialize, Deserialize, Default)]
struct GuardFile {
    #[serde(default)]
    vaults: BTreeMap<String, GuardState>,
}

pub fn app_data_dir() -> PathBuf {
    ProjectDirs::from("com", "filelocker", "FileLocker")
        .expect("无法定位应用数据目录")
        .data_dir()
        .to_path_buf()
}

/// 密码强度策略（与前端展示规则保持一致，但由 Rust 侧强制执行，
/// 防止绕过前端直接调用命令设置弱密码）。
fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.chars().count() < 8 {
        return Err("密码至少需要 8 位".into());
    }
    let lower = password.to_lowercase();
    for weak in ["12345678", "password", "qwerty", "admin"] {
        if lower.starts_with(weak) {
            return Err("密码过于简单，容易被字典工具破解".into());
        }
    }
    if let Some(first) = password.chars().next() {
        if password.chars().all(|c| c == first) {
            return Err("密码过于简单（全部为相同字符）".into());
        }
    }
    if password.chars().all(|c| c.is_ascii_digit()) {
        return Err("密码不能为纯数字".into());
    }
    Ok(())
}

/// 尽力擦除文件：先把内容覆写为 0 并 `sync_all`，再从文件系统删除。
///
/// 注意：这只是**尽力而为**的清理，不代表物理介质上的数据一定被覆盖。
/// 在 SSD（TRIM / 磨损均衡）、写时复制文件系统（APFS / Btrfs）、
/// 开启快照或日志的文件系统上，覆写同一逻辑偏移无法保证抹掉底层旧数据。
/// 因此安全边界应建立在加密上：本应用落盘的 blob 均为密文，
/// 删除后不残留可读明文；此函数仅用于收尾清理临时解密出的明文。
fn best_effort_erase_file(path: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    // 符号链接只删除链接本身，避免顺着链接覆写外部文件。
    if meta.file_type().is_symlink() {
        return fs::remove_file(path);
    }
    let len = meta.len();
    if len > 0 {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write;
            let chunk_size = 64 * 1024;
            let zeros = vec![0u8; chunk_size];
            let mut written = 0u64;
            while written < len {
                let to_write = (chunk_size as u64).min(len - written) as usize;
                let _ = f.write_all(&zeros[..to_write]);
                written += to_write as u64;
            }
            let _ = f.sync_all();
        }
    }
    fs::remove_file(path)
}

fn best_effort_erase_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            // 使用 DirEntry::file_type（不跟随符号链接），避免符号链接环导致无限递归。
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                best_effort_erase_dir(&p);
                let _ = fs::remove_dir(&p);
            } else {
                let _ = best_effort_erase_file(&p);
            }
        }
    }
}

/// 创建应用私有目录，并在 Unix 上收紧为 0700（仅当前用户可进入/读写）。
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// 以 0600 权限预创建目标文件，随后的写入/解密不会改变该权限，
/// 避免临时明文在创建瞬间落入同机其他用户可读的宽权限文件。
fn create_private_file(path: &Path) -> std::io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// 删除临时明文：文件先尽力覆写再删除，目录递归清理。
fn remove_plain_path(path: &Path) {
    if path.is_dir() {
        best_effort_erase_dir(path);
        let _ = fs::remove_dir(path);
    } else if path.exists() {
        let _ = best_effort_erase_file(path);
    }
}

/// 加密索引落盘的 JSON 外层结构（整个 entries 数组一次加密）。
#[derive(Serialize, Deserialize)]
struct IndexData {
    /// 单调递增的索引代次。与钥匙串中的锚点比对，可发现旧索引被整体替换回来的回滚攻击。
    /// 旧版本索引没有该字段，默认 0。
    #[serde(default)]
    generation: u64,
    entries: Vec<VaultEntry>,
}

/// 校验索引代次相对锚点没有倒退。
fn check_index_generation(generation: u64, anchor: Option<u64>) -> Result<(), String> {
    if let Some(anchor) = anchor {
        if generation < anchor {
            return Err(format!(
                "检测到索引版本回滚（索引代次 {generation} < 期望 {anchor}），已拒绝加载。\
                 若你并未手动还原过数据目录，请警惕本地文件被替换"
            ));
        }
    }
    Ok(())
}

/// 代次锚点：优先使用系统钥匙串（位于应用数据目录之外，不易与索引一起被回滚）。
/// 单元测试中禁用钥匙串锚点，避免测试之间（以及与本机真实保险箱之间）互相干扰。
fn load_generation_anchor(vault_id: &str) -> Option<u64> {
    #[cfg(not(test))]
    {
        keychain::load_index_generation(vault_id).ok()
    }
    #[cfg(test)]
    {
        let _ = vault_id;
        None
    }
}

fn store_generation_anchor(vault_id: &str, generation: u64) {
    #[cfg(not(test))]
    {
        let _ = keychain::store_index_generation(vault_id, generation);
    }
    #[cfg(test)]
    {
        let _ = (vault_id, generation);
    }
}

const KEYRING_VERSION: u32 = 3;
const DEFAULT_AUTO_LOCK_MINUTES: u64 = 5;

/// 原子写入文件：写入同目录下的临时文件并执行 sync_all 刷盘，再原子重命名替换目标。
/// 避免系统崩溃或断电导致目标文件损坏或截断为 0 字节。
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "无法获取目标路径父目录".to_string())?;
    let tmp_path = parent.join(format!(".{}.tmp", Uuid::new_v4()));

    {
        use std::io::Write;
        let mut file =
            fs::File::create(&tmp_path).map_err(|e| format!("创建临时写入文件失败: {e}"))?;
        file.write_all(data)
            .map_err(|e| format!("写入临时数据失败: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("临时文件刷盘同步失败: {e}"))?;
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        #[cfg(target_os = "windows")]
        {
            let _ = fs::remove_file(path);
            if fs::rename(&tmp_path, path).is_ok() {
                return Ok(());
            }
        }
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("原子重命名替换文件失败: {e}"));
    }
    Ok(())
}

fn vaults_path(data_base: &Path) -> PathBuf {
    data_base.join("vaults.json")
}

/// 生产构建下只保留文件名，避免错误信息把本机绝对路径暴露到前端或日志。
fn redact_path(p: &Path) -> String {
    if cfg!(debug_assertions) {
        p.display().to_string()
    } else {
        p.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "<未知路径>".to_string())
    }
}

/// 元数据文件头：存在则说明内容是 AES-GCM 密文（密钥来自系统钥匙串）。
const META_MAGIC: &[u8] = b"FLCK_META\x01";

/// 元数据加密密钥。单元测试中返回 `None`（回退明文），避免读写开发机真实钥匙串。
fn metadata_key() -> Option<[u8; 32]> {
    #[cfg(not(test))]
    {
        keychain::load_or_create_metadata_key().ok()
    }
    #[cfg(test)]
    {
        None
    }
}

fn load_meta_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    if let Some(enc) = bytes.strip_prefix(META_MAGIC) {
        if let Some(key) = metadata_key() {
            if let Ok(plain) = crypto::decrypt(enc, &key) {
                return serde_json::from_slice(&plain).ok();
            }
        }
    }
    // 兼容明文文件
    serde_json::from_slice(&bytes).ok()
}

/// 元数据落盘：统一写入标准原子 JSON。
fn save_meta_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), String> {
    let json = serde_json::to_vec(value).map_err(|e| format!("序列化元数据失败: {e}"))?;
    atomic_write(path, &json)
}

fn load_vault_profiles(data_base: &Path) -> Vec<VaultProfile> {
    let p = vaults_path(data_base);
    if let Some(profiles) = load_meta_json::<Vec<VaultProfile>>(&p) {
        if !profiles.is_empty() {
            return profiles;
        }
    }

    // 默认保险箱档案（向后完全兼容已有保险箱）
    let default_profile = VaultProfile {
        id: "default".to_string(),
        name: "默认保险箱".to_string(),
        created_at: Utc::now().timestamp_millis(),
    };
    let profiles = vec![default_profile];
    // 文件存在但读不出来（例如钥匙串暂时不可用）时不要覆盖，避免把已加密的档案冲掉。
    if !p.exists() {
        let _ = save_vault_profiles(data_base, &profiles);
    }
    profiles
}

fn save_vault_profiles(data_base: &Path, profiles: &[VaultProfile]) -> Result<(), String> {
    save_meta_json(&vaults_path(data_base), profiles)
}

fn vault_dir_for(data_base: &Path, id: &str) -> PathBuf {
    if id == "default" || id.is_empty() {
        data_base.join("vault")
    } else {
        data_base.join("vaults").join(id)
    }
}

impl VaultManager {
    pub fn new() -> Self {
        let data_base = app_data_dir();
        let config_path = data_base.join("config.json");

        let app_config = load_config(&config_path);
        let auto_lock_minutes = app_config
            .as_ref()
            .and_then(|c| c.auto_lock_minutes)
            .unwrap_or(DEFAULT_AUTO_LOCK_MINUTES);

        let profiles = load_vault_profiles(&data_base);
        let target_vault_id = app_config
            .as_ref()
            .and_then(|c| c.current_vault_id.clone())
            .unwrap_or_else(|| "default".to_string());

        let active_profile = profiles
            .iter()
            .find(|p| p.id == target_vault_id)
            .cloned()
            .unwrap_or_else(|| {
                profiles.first().cloned().unwrap_or(VaultProfile {
                    id: "default".to_string(),
                    name: "默认保险箱".to_string(),
                    created_at: Utc::now().timestamp_millis(),
                })
            });

        let vault_dir = vault_dir_for(&data_base, &active_profile.id);
        let data_dir = vault_dir.join("data");
        let temp_dir = vault_dir.join("tmp");

        let _ = create_private_dir(&data_dir);
        let _ = create_private_dir(&temp_dir);

        let vm = VaultManager {
            entries: Vec::new(),
            master_key: None,
            is_unlocked: false,
            data_base,
            current_vault_id: active_profile.id,
            current_vault_name: active_profile.name,
            vault_dir,
            data_dir,
            temp_dir,
            config_path,
            auto_lock_minutes,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        };

        // 启动时主动清理上次异常断电或退出遗留的临时解密明文文件
        let _ = vm.clear_temp();

        vm
    }

    fn salt_path(&self) -> PathBuf {
        self.vault_dir.join("salt.bin")
    }
    fn index_path(&self) -> PathBuf {
        self.vault_dir.join("index.enc")
    }
    fn keyring_path(&self) -> PathBuf {
        self.vault_dir.join("keyring.json")
    }

    pub fn vault_exists(&self) -> bool {
        self.salt_path().exists() && self.index_path().exists()
    }

    fn guard_path(&self) -> PathBuf {
        self.data_base.join("security.json")
    }

    fn load_guard(&self) -> GuardState {
        fs::read(self.guard_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<GuardFile>(&b).ok())
            .and_then(|f| f.vaults.get(&self.current_vault_id).cloned())
            .unwrap_or_default()
    }

    /// 把当前内存中的防爆破计数写回 security.json（按保险箱 id 隔离）。
    fn persist_guard(&self) {
        let mut file = fs::read(self.guard_path())
            .ok()
            .and_then(|b| serde_json::from_slice::<GuardFile>(&b).ok())
            .unwrap_or_default();
        file.vaults.insert(
            self.current_vault_id.clone(),
            GuardState {
                failed_attempts: self.failed_attempts,
                lockout_until: self.lockout_until,
                recovery_failed_attempts: self.recovery_failed_attempts,
                recovery_lockout_until: self.recovery_lockout_until,
            },
        );
        if let Ok(bytes) = serde_json::to_vec(&file) {
            let _ = atomic_write(&self.guard_path(), &bytes);
        }
    }

    /// 以落盘数据为准刷新计数，确保重启应用或多保险箱切换后冷却状态不被绕过。
    fn refresh_guard(&mut self) {
        let g = self.load_guard();
        self.failed_attempts = g.failed_attempts;
        self.lockout_until = g.lockout_until;
        self.recovery_failed_attempts = g.recovery_failed_attempts;
        self.recovery_lockout_until = g.recovery_lockout_until;
    }

    fn lockout_cooldown(attempts: u32) -> i64 {
        match attempts {
            0..=2 => 0,
            3..=4 => 5,
            5..=7 => 30,
            8..=9 => 60,
            _ => 300,
        }
    }

    /// 记录一次有效操作时间；Rust 侧后台线程据此判断空闲超时。
    fn touch(&self) {
        self.last_activity.set(Utc::now().timestamp());
    }

    /// 前端用户活动心跳（mousemove/keydown 等），让 Rust 权威自动锁
    /// 能感知"用户仍在操作"，而不是仅统计会触发命令的操作。
    pub fn touch_activity(&self) {
        if self.is_unlocked {
            self.touch();
        }
    }

    /// 权威空闲自动锁定：由后台线程周期调用，不依赖前端计时器。
    pub fn enforce_auto_lock(&mut self) {
        if !self.is_unlocked || self.auto_lock_minutes == 0 {
            return;
        }
        let idle = Utc::now().timestamp() - self.last_activity.get();
        if idle >= (self.auto_lock_minutes as i64) * 60 {
            self.lock();
        }
    }

    fn require_unlocked(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        if !self.is_unlocked {
            return Err("保险箱尚未解锁".into());
        }
        self.touch();
        // 返回 `Zeroizing` 副本：调用方用完后栈上的字节会被自动清零，不会长期残留。
        self.master_key
            .as_ref()
            .map(|k| Zeroizing::new(**k))
            .ok_or_else(|| "主密钥缺失".into())
    }

    /// 首次设置密码：生成随机 master_key，用密码/恢复码分别包装后落盘。
    pub fn set_password(&mut self, password: &str, remember: bool) -> Result<String, String> {
        if password.is_empty() {
            return Err("密码不能为空".into());
        }
        validate_password_strength(password)?;
        create_private_dir(&self.data_dir).map_err(|e| format!("创建数据目录失败: {e}"))?;

        // 随机主密钥
        let master_key: [u8; 32] = crypto::random_bytes(32)
            .try_into()
            .expect("长度必为 32");

        // 密码盐 + KEK 包装（Argon2id）
        let password_salt = crypto::random_bytes(crypto::SALT_LEN);
        let mut password_kek = crypto::derive_key_argon2id(
            password,
            &password_salt,
            crypto::ARGON2_DEFAULT_MEMORY_KIB,
            crypto::ARGON2_DEFAULT_ITERATIONS,
            crypto::ARGON2_DEFAULT_PARALLELISM,
        )?;
        let password_wrap = crypto::encrypt(&master_key, &password_kek)?;
        crypto::zeroize_slice(&mut password_kek);

        // 恢复码（Argon2id）
        let recovery_code = crypto::generate_recovery_code();
        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let mut recovery_kek = crypto::derive_key_recovery_argon2id(
            &recovery_code,
            &recovery_salt,
            crypto::ARGON2_DEFAULT_MEMORY_KIB,
            crypto::ARGON2_DEFAULT_ITERATIONS,
            crypto::ARGON2_DEFAULT_PARALLELISM,
        )?;
        let recovery_wrap = crypto::encrypt(&master_key, &recovery_kek)?;
        crypto::zeroize_slice(&mut recovery_kek);

        let keyring = Keyring {
            version: KEYRING_VERSION,
            password_wrap,
            recovery_salt,
            recovery_wrap,
            iterations: Some(crypto::ARGON2_DEFAULT_ITERATIONS),
            recovery_iterations: Some(crypto::ARGON2_DEFAULT_ITERATIONS),
            kdf_type: Some(crypto::KDF_TYPE_ARGON2ID.to_string()),
            memory_kib: Some(crypto::ARGON2_DEFAULT_MEMORY_KIB),
            parallelism: Some(crypto::ARGON2_DEFAULT_PARALLELISM),
            recovery_kdf_type: Some(crypto::KDF_TYPE_ARGON2ID.to_string()),
            recovery_memory_kib: Some(crypto::ARGON2_DEFAULT_MEMORY_KIB),
            recovery_parallelism: Some(crypto::ARGON2_DEFAULT_PARALLELISM),
        };
        let keyring_json =
            serde_json::to_vec(&keyring).map_err(|e| format!("序列化 keyring 失败: {e}"))?;
        atomic_write(&self.keyring_path(), &keyring_json)?;
        atomic_write(&self.salt_path(), &password_salt)?;

        // 空索引
        self.entries = Vec::new();
        self.master_key = Some(crypto::ProtectedMasterKey::new(master_key));
        self.is_unlocked = true;
        self.failed_attempts = 0;
        self.lockout_until = None;
        self.recovery_failed_attempts = 0;
        self.recovery_lockout_until = None;
        self.persist_guard();
        self.touch();
        self.save_index()?;

        if remember {
            let _ = keychain::save_password(&self.current_vault_id, password);
        } else {
            let _ = keychain::delete_password(&self.current_vault_id);
        }

        Ok(recovery_code)
    }

    /// 用密码解锁（包含防暴力破解指数冷却保护）。
    pub fn unlock(&mut self, password: &str, remember: bool) -> Result<Vec<VaultEntry>, String> {
        if !self.vault_exists() {
            return Err("保险箱尚未设置密码".into());
        }

        // 以落盘状态为准，避免重启应用绕过安全冷却。
        self.refresh_guard();
        let now = Utc::now().timestamp();
        if let Some(lockout) = self.lockout_until {
            if now < lockout {
                let remaining = lockout - now;
                return Err(format!("输错密码次数过多，安全保护中，请等待 {remaining} 秒后再试"));
            } else {
                self.lockout_until = None;
            }
        }

        let unlock_res = if self.keyring_path().exists() {
            self.unwrap_with_password(password)
        } else {
            let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
            let master_key = crypto::derive_key_password(password, &salt);
            self.load_index_with_key(&master_key).map(|_| master_key)
        };

        let master_key = match unlock_res {
            Ok(mk) => {
                self.failed_attempts = 0;
                self.lockout_until = None;
                self.persist_guard();
                mk
            }
            Err(_) => {
                self.failed_attempts += 1;
                let cooldown = Self::lockout_cooldown(self.failed_attempts);
                if cooldown > 0 {
                    // 以判定失败的当前时刻起算，避免 KDF 耗时（尤其是旧设备/调试构建）侵蚀冷却窗口。
                    self.lockout_until = Some(Utc::now().timestamp() + cooldown);
                }
                self.persist_guard();
                if cooldown > 0 {
                    return Err(format!(
                        "密码错误！已连续输错 {} 次，安全保护触发，请等待 {} 秒后再试",
                        self.failed_attempts, cooldown
                    ));
                } else {
                    let tries_left = 3 - self.failed_attempts;
                    return Err(format!("密码错误！剩余 {} 次尝试后将触发安全冷却延迟", tries_left));
                }
            }
        };

        self.entries = self.load_index_with_key(&master_key)?;
        self.master_key = Some(crypto::ProtectedMasterKey::new(master_key));
        self.is_unlocked = true;
        self.touch();

        if remember {
            let _ = keychain::save_password(&self.current_vault_id, password);
        } else {
            let _ = keychain::delete_password(&self.current_vault_id);
        }
        Ok(self.entries.clone())
    }

    fn unwrap_with_password(&self, password: &str) -> Result<[u8; 32], String> {
        let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
        let keyring_bytes =
            fs::read(self.keyring_path()).map_err(|e| format!("读取 keyring 失败: {e}"))?;
        let keyring: Keyring =
            serde_json::from_slice(&keyring_bytes).map_err(|e| format!("解析 keyring 失败: {e}"))?;

        let kdf_type = keyring
            .kdf_type
            .as_deref()
            .unwrap_or(crypto::KDF_TYPE_PBKDF2);
        let iters = keyring
            .iterations
            .unwrap_or(crypto::LEGACY_PBKDF2_ITERATIONS);
        let recovery_iters = keyring
            .recovery_iterations
            .or(keyring.iterations)
            .unwrap_or(crypto::LEGACY_PBKDF2_ITERATIONS);

        let mut kek = if kdf_type == crypto::KDF_TYPE_ARGON2ID {
            let mem = keyring
                .memory_kib
                .unwrap_or(crypto::ARGON2_DEFAULT_MEMORY_KIB);
            let p_iters = keyring
                .iterations
                .unwrap_or(crypto::ARGON2_DEFAULT_ITERATIONS);
            let par = keyring
                .parallelism
                .unwrap_or(crypto::ARGON2_DEFAULT_PARALLELISM);
            crypto::derive_key_argon2id(password, &salt, mem, p_iters, par)?
        } else {
            crypto::derive_key_password_with_iter(password, &salt, iters)
        };

        let mk_bytes = crypto::decrypt(&keyring.password_wrap, &kek)?;
        crypto::zeroize_slice(&mut kek);
        if mk_bytes.len() != 32 {
            return Err("主密钥长度无效".into());
        }
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&mk_bytes);

        // 仅单向升级：若旧版本使用 PBKDF2 或未升级至 Argon2id，成功解锁后单向机会性升级至 Argon2id。
        // 恢复码包装在不知道恢复码的情况下无法同步升级，因此原样保留其旧参数与类型。
        if kdf_type != crypto::KDF_TYPE_ARGON2ID {
            let rec_kdf = keyring
                .recovery_kdf_type
                .clone()
                .or_else(|| keyring.kdf_type.clone())
                .unwrap_or_else(|| crypto::KDF_TYPE_PBKDF2.to_string());
            let new_kek = crypto::derive_key_argon2id(
                password,
                &salt,
                crypto::ARGON2_DEFAULT_MEMORY_KIB,
                crypto::ARGON2_DEFAULT_ITERATIONS,
                crypto::ARGON2_DEFAULT_PARALLELISM,
            );
            if let Ok(mut new_kek) = new_kek {
                let upgraded = crypto::encrypt(&mk, &new_kek);
                crypto::zeroize_slice(&mut new_kek);
                if let Ok(new_wrap) = upgraded {
                    let mut updated = keyring.clone();
                    updated.version = KEYRING_VERSION;
                    updated.password_wrap = new_wrap;
                    updated.kdf_type = Some(crypto::KDF_TYPE_ARGON2ID.to_string());
                    updated.memory_kib = Some(crypto::ARGON2_DEFAULT_MEMORY_KIB);
                    updated.iterations = Some(crypto::ARGON2_DEFAULT_ITERATIONS);
                    updated.parallelism = Some(crypto::ARGON2_DEFAULT_PARALLELISM);
                    updated.recovery_kdf_type = Some(rec_kdf);
                    updated.recovery_iterations = Some(recovery_iters);
                    if let Ok(bytes) = serde_json::to_vec(&updated) {
                        let _ = atomic_write(&self.keyring_path(), &bytes);
                    }
                }
            }
        }

        Ok(mk)
    }

    fn unwrap_with_recovery(&self, code: &str) -> Result<[u8; 32], String> {
        let keyring_bytes =
            fs::read(self.keyring_path()).map_err(|e| format!("读取 keyring 失败: {e}"))?;
        let keyring: Keyring =
            serde_json::from_slice(&keyring_bytes).map_err(|e| format!("解析 keyring 失败: {e}"))?;

        let rec_kdf = keyring
            .recovery_kdf_type
            .as_deref()
            .or(keyring.kdf_type.as_deref())
            .unwrap_or(crypto::KDF_TYPE_PBKDF2);

        let mut kek = if rec_kdf == crypto::KDF_TYPE_ARGON2ID {
            let mem = keyring
                .recovery_memory_kib
                .or(keyring.memory_kib)
                .unwrap_or(crypto::ARGON2_DEFAULT_MEMORY_KIB);
            let iters = keyring
                .recovery_iterations
                .or(keyring.iterations)
                .unwrap_or(crypto::ARGON2_DEFAULT_ITERATIONS);
            let par = keyring
                .recovery_parallelism
                .or(keyring.parallelism)
                .unwrap_or(crypto::ARGON2_DEFAULT_PARALLELISM);
            crypto::derive_key_recovery_argon2id(code, &keyring.recovery_salt, mem, iters, par)?
        } else {
            let iters = keyring
                .recovery_iterations
                .or(keyring.iterations)
                .unwrap_or(crypto::LEGACY_PBKDF2_ITERATIONS);
            crypto::derive_key_recovery_with_iter(code, &keyring.recovery_salt, iters)
        };

        let mk_bytes = crypto::decrypt(&keyring.recovery_wrap, &kek)?;
        crypto::zeroize_slice(&mut kek);
        if mk_bytes.len() != 32 {
            return Err("主密钥长度无效".into());
        }
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&mk_bytes);
        Ok(mk)
    }

    /// 将旧版本保险箱升级为 keyring 体系。返回新生成的恢复码。
    #[allow(dead_code)]
    fn upgrade_to_keyring(
        &self,
        master_key: &[u8; 32],
        password: &str,
    ) -> Result<String, String> {
        let password_salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
        let mut password_kek = crypto::derive_key_argon2id(
            password,
            &password_salt,
            crypto::ARGON2_DEFAULT_MEMORY_KIB,
            crypto::ARGON2_DEFAULT_ITERATIONS,
            crypto::ARGON2_DEFAULT_PARALLELISM,
        )?;
        let password_wrap = crypto::encrypt(master_key, &password_kek)?;
        crypto::zeroize_slice(&mut password_kek);

        let recovery_code = crypto::generate_recovery_code();
        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let mut recovery_kek = crypto::derive_key_recovery_argon2id(
            &recovery_code,
            &recovery_salt,
            crypto::ARGON2_DEFAULT_MEMORY_KIB,
            crypto::ARGON2_DEFAULT_ITERATIONS,
            crypto::ARGON2_DEFAULT_PARALLELISM,
        )?;
        let recovery_wrap = crypto::encrypt(master_key, &recovery_kek)?;
        crypto::zeroize_slice(&mut recovery_kek);

        let keyring = Keyring {
            version: KEYRING_VERSION,
            password_wrap,
            recovery_salt,
            recovery_wrap,
            iterations: Some(crypto::ARGON2_DEFAULT_ITERATIONS),
            recovery_iterations: Some(crypto::ARGON2_DEFAULT_ITERATIONS),
            kdf_type: Some(crypto::KDF_TYPE_ARGON2ID.to_string()),
            memory_kib: Some(crypto::ARGON2_DEFAULT_MEMORY_KIB),
            parallelism: Some(crypto::ARGON2_DEFAULT_PARALLELISM),
            recovery_kdf_type: Some(crypto::KDF_TYPE_ARGON2ID.to_string()),
            recovery_memory_kib: Some(crypto::ARGON2_DEFAULT_MEMORY_KIB),
            recovery_parallelism: Some(crypto::ARGON2_DEFAULT_PARALLELISM),
        };
        let bytes = serde_json::to_vec(&keyring).map_err(|e| format!("序列化失败: {e}"))?;
        atomic_write(&self.keyring_path(), &bytes)?;
        Ok(recovery_code)
    }

    pub fn lock(&mut self) {
        // `Zeroizing` 在释放时自动清零，无需手动擦除。
        self.master_key = None;
        self.entries.clear();
        self.is_unlocked = false;
        let _ = self.clear_temp();
    }

    pub fn has_saved_password(&self) -> bool {
        keychain::has_saved_password(&self.current_vault_id)
    }

    /// 使用系统钥匙串中已记住的密码解锁。
    ///
    /// 注意：这不是生物识别。凭据以明文密码形式存放在系统钥匙串中，
    /// 能否免输入读取由系统钥匙串自身的访问控制决定。
    pub fn unlock_with_keychain(&mut self) -> Result<Vec<VaultEntry>, String> {
        let pwd = keychain::load_password(&self.current_vault_id)?;
        self.unlock(&pwd, false)
    }

    pub fn list_entries(&self) -> Result<Vec<VaultEntry>, String> {
        if !self.is_unlocked {
            return Err("保险箱尚未解锁".into());
        }
        Ok(self.entries.clone())
    }

    /// 条目行内重命名
    pub fn rename_entry(&mut self, id: &str, new_name: &str) -> Result<VaultEntry, String> {
        let _mk = self.require_unlocked()?;
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return Err("条目名称不能为空".to_string());
        }
        if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
            return Err("条目名称不能包含路径分隔符".to_string());
        }
        if self.entries.iter().any(|e| e.id != id && e.name == trimmed) {
            return Err("已存在相同名称的条目".to_string());
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| "条目不存在".to_string())?;
        entry.name = trimmed.to_string();
        let updated = entry.clone();
        self.save_index()?;
        Ok(updated)
    }

    /// 多保险箱：获取当前保险箱状态
    pub fn get_current_vault_info(&self) -> VaultInfo {
        VaultInfo {
            id: self.current_vault_id.clone(),
            name: self.current_vault_name.clone(),
            exists: self.vault_exists(),
            is_unlocked: self.is_unlocked,
            has_saved_password: self.has_saved_password(),
        }
    }

    /// 多保险箱：列出所有保险箱概要
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, String> {
        let profiles = load_vault_profiles(&self.data_base);
        let list = profiles
            .into_iter()
            .map(|p| {
                let vdir = vault_dir_for(&self.data_base, &p.id);
                let exists = vdir.join("salt.bin").exists() && vdir.join("index.enc").exists();
                let is_unlocked = if p.id == self.current_vault_id {
                    self.is_unlocked
                } else {
                    false
                };
                let has_saved_password = if p.id == self.current_vault_id {
                    keychain::has_saved_password(&p.id)
                } else {
                    false
                };
                VaultInfo {
                    id: p.id,
                    name: p.name,
                    exists,
                    is_unlocked,
                    has_saved_password,
                }
            })
            .collect();
        Ok(list)
    }

    /// 多保险箱：切换当前保险箱
    pub fn switch_vault(&mut self, target_id: &str) -> Result<VaultInfo, String> {
        if target_id == self.current_vault_id {
            return Ok(self.get_current_vault_info());
        }

        let profiles = load_vault_profiles(&self.data_base);
        let target = profiles
            .iter()
            .find(|p| p.id == target_id)
            .ok_or_else(|| format!("未找到保险箱: {target_id}"))?;

        // 切换前先安全锁定当前保险箱
        self.lock();

        self.current_vault_id = target.id.clone();
        self.current_vault_name = target.name.clone();
        self.vault_dir = vault_dir_for(&self.data_base, &target.id);
        self.data_dir = self.vault_dir.join("data");
        self.temp_dir = self.vault_dir.join("tmp");

        let _ = create_private_dir(&self.data_dir);
        let _ = create_private_dir(&self.temp_dir);
        let _ = self.clear_temp();

        // 切换后以目标保险箱的落盘状态刷新防爆破计数
        self.refresh_guard();
        self.touch();

        // 更新应用配置中的当前活跃保险箱
        let mut cfg = load_config(&self.config_path).unwrap_or_default();
        cfg.current_vault_id = Some(target.id.clone());
        let _ = save_meta_json(&self.config_path, &cfg);

        Ok(self.get_current_vault_info())
    }

    /// 多保险箱：创建全新保险箱
    pub fn create_vault(
        &mut self,
        name: &str,
        password: &str,
        remember: bool,
    ) -> Result<CreateVaultResult, String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("保险箱名称不能为空".into());
        }
        let mut profiles = load_vault_profiles(&self.data_base);
        if profiles.iter().any(|p| p.name == trimmed) {
            return Err("已存在同名保险箱，请使用不同名称".into());
        }

        let new_id = format!("vault_{}", Uuid::new_v4().simple());
        let new_profile = VaultProfile {
            id: new_id.clone(),
            name: trimmed.to_string(),
            created_at: Utc::now().timestamp_millis(),
        };
        profiles.push(new_profile);
        save_vault_profiles(&self.data_base, &profiles)?;

        // 切换到新保险箱
        self.switch_vault(&new_id)?;

        // 初始化密码与主密钥
        let recovery_code = self.set_password(password, remember)?;

        Ok(CreateVaultResult {
            vault: self.get_current_vault_info(),
            recovery_code,
        })
    }

    /// 多保险箱：重命名保险箱
    pub fn rename_vault(&mut self, vault_id: &str, new_name: &str) -> Result<(), String> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return Err("保险箱名称不能为空".into());
        }
        let mut profiles = load_vault_profiles(&self.data_base);
        if profiles.iter().any(|p| p.id != vault_id && p.name == trimmed) {
            return Err("已存在同名保险箱".into());
        }

        let profile = profiles
            .iter_mut()
            .find(|p| p.id == vault_id)
            .ok_or_else(|| "保险箱不存在".to_string())?;
        profile.name = trimmed.to_string();
        save_vault_profiles(&self.data_base, &profiles)?;

        if self.current_vault_id == vault_id {
            self.current_vault_name = trimmed.to_string();
        }
        Ok(())
    }

    /// 多保险箱：删除保险箱（保留至少一个）
    pub fn delete_vault(&mut self, vault_id: &str) -> Result<VaultInfo, String> {
        // 破坏性操作：必须处于已解锁状态，避免锁定态下被静默清空数据。
        self.require_unlocked()?;
        let mut profiles = load_vault_profiles(&self.data_base);
        if profiles.len() <= 1 {
            return Err("至少需要保留一个保险箱，无法删除".into());
        }

        let pos = profiles
            .iter()
            .position(|p| p.id == vault_id)
            .ok_or_else(|| "保险箱不存在".to_string())?;
        let removed = profiles.remove(pos);

        // 如果要删除的是当前正在使用的保险箱，先锁定
        if self.current_vault_id == vault_id {
            self.lock();
        }

        // 删除目标保险箱数据目录与钥匙串密码
        let target_vdir = vault_dir_for(&self.data_base, &removed.id);
        if target_vdir.exists() {
            let _ = fs::remove_dir_all(&target_vdir);
        }
        let _ = keychain::delete_password(&removed.id);
        let _ = keychain::delete_index_generation(&removed.id);

        save_vault_profiles(&self.data_base, &profiles)?;

        // 若删除了当前激活的保险箱，自动切换到剩余的第一个保险箱
        if self.current_vault_id == vault_id {
            let next_id = profiles[0].id.clone();
            self.switch_vault(&next_id)?;
        }

        Ok(self.get_current_vault_info())
    }

    /// 添加文件/文件夹：支持超大文件流式分块加密，内存占用恒定 ~4MB，支持任意 GB 级大文件。
    pub fn add_files(&mut self, paths: Vec<String>) -> Result<Vec<VaultEntry>, String> {
        let mk = self.require_unlocked()?;
        create_private_dir(&self.data_dir).map_err(|e| format!("创建 data 目录失败: {e}"))?;

        let existing = self.entries.clone();
        let mut added: Vec<VaultEntry> = Vec::new();
        let mut skipped = 0usize;

        for p_str in paths {
            let p = PathBuf::from(&p_str);
            if !p.exists() {
                return Err(format!("文件不存在: {}", redact_path(&p)));
            }

            // 从应用 tmp 目录拖入的文件（本应用临时解密出的副本）跳过。
            if let Ok(tmp_canon) = self.temp_dir.canonicalize() {
                if let Ok(p_canon) = p.canonicalize() {
                    if p_canon.starts_with(&tmp_canon) {
                        skipped += 1;
                        continue;
                    }
                }
            }

            let name = p
                .file_name()
                .ok_or_else(|| format!("路径无文件名: {}", redact_path(&p)))?
                .to_string_lossy()
                .to_string();
            let is_dir = p.is_dir();

            let id = Uuid::new_v4().to_string();
            let blob_name = format!("{}.bin", Uuid::new_v4());
            let blob_path = self.data_dir.join(&blob_name);

            let (kind, size) = if is_dir {
                // 文件夹先打包成临时 zip，再流式加密：内存占用不再等于文件夹总大小。
                // 临时 zip 中为明文，用完立即尽力擦除。
                create_private_dir(&self.temp_dir)
                    .map_err(|e| format!("创建临时目录失败: {e}"))?;
                let zip_path = self.temp_dir.join(format!("zip-{}.tmp", Uuid::new_v4()));
                if let Err(e) = zip_directory_to_file(&p, &zip_path) {
                    let _ = fs::remove_file(&zip_path);
                    return Err(e);
                }
                let enc_result = crypto::encrypt_file_stream(&zip_path, &blob_path, &mk);
                let _ = best_effort_erase_file(&zip_path);
                let s = enc_result?;
                ("folder".to_string(), s)
            } else {
                // 超大文件流式分块加密，峰值内存占用仅 ~4MB，支持任意 GB 级文件
                let s = crypto::encrypt_file_stream(&p, &blob_path, &mk)?;
                ("file".to_string(), s)
            };

            // 同名 + 同大小视为重复
            let is_dup = existing.iter().chain(added.iter()).any(|e| {
                e.name == name && e.size == size
            });
            if is_dup {
                let _ = fs::remove_file(&blob_path);
                skipped += 1;
                continue;
            }

            let entry = VaultEntry {
                id: id.clone(),
                name: name.clone(),
                size,
                added_at: Utc::now().timestamp_millis(),
                kind,
                original_path: Some(p_str.clone()),
                cipher_path: blob_name,
            };
            added.push(entry);

            // 原文件移入废纸篓（若源文件在 vault 目录内则不移除，避免误删自己）。
            if let Ok(vault_canon) = self.vault_dir.canonicalize() {
                if let Ok(p_canon) = p.canonicalize() {
                    if p_canon.starts_with(&vault_canon) {
                        continue;
                    }
                }
            }
            let _ = vfs::move_to_trash(&p);
        }

        self.entries.extend(added.iter().cloned());
        self.save_index()?;

        let _ = skipped;
        Ok(added)
    }

    /// 在指定目录下找到一个不冲突的目标路径（同名时附加 " 2", " 3"...）。
    fn unique_path(dir: &Path, name: &str) -> PathBuf {
        let candidate = dir.join(name);
        if !candidate.exists() {
            return candidate;
        }
        let stem = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        let ext = Path::new(name)
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{s}"))
            .unwrap_or_default();
        let mut idx = 2;
        loop {
            let new_name = format!("{stem} {idx}{ext}");
            let cand = dir.join(new_name);
            if !cand.exists() {
                return cand;
            }
            idx += 1;
        }
    }

    /// 文件夹条目：解密后是 zip 字节。直接在内存中使用 Cursor 解压到 target_dir/name，无临时磁盘文件产生。
    fn extract_folder_to(data: &[u8], name: &str, target_dir: &Path) -> Result<PathBuf, String> {
        fs::create_dir_all(target_dir).map_err(|e| format!("创建目标目录失败: {e}"))?;
        let final_dir = Self::unique_path(target_dir, name);
        fs::create_dir_all(&final_dir).map_err(|e| format!("创建目录失败: {e}"))?;

        let cursor = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("打开 zip 失败: {e}"))?;
        archive
            .extract(&final_dir)
            .map_err(|e| format!("解压文件夹失败: {e}"))?;
        Ok(final_dir)
    }

    pub fn open_entry(&self, id: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let mk = self.require_unlocked()?;
        let blob_path = self.data_dir.join(&entry.cipher_path);
        create_private_dir(&self.temp_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

        let target = if entry.kind == "folder" {
            let data = crypto::decrypt_file_to_bytes(&blob_path, &mk)?;
            let work = self.temp_dir.join(Uuid::new_v4().to_string());
            create_private_dir(&work).map_err(|e| format!("创建临时目录失败: {e}"))?;
            match Self::extract_folder_to(&data, &entry.name, &work) {
                Ok(dir) => dir,
                Err(e) => {
                    remove_plain_path(&work);
                    return Err(e);
                }
            }
        } else {
            let target_path = Self::unique_path(&self.temp_dir, &entry.name);
            create_private_file(&target_path).map_err(|e| format!("创建临时文件失败: {e}"))?;
            crypto::decrypt_file_stream(&blob_path, &target_path, &mk)?;
            target_path
        };

        if let Err(e) = vfs::open_path(&target) {
            // 打开失败时清理已解密出的临时明文，避免残留
            remove_plain_path(&target);
            return Err(e);
        }
        Ok(())
    }

    pub fn export_entry(&self, id: &str, target_path: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let mk = self.require_unlocked()?;
        let blob_path = self.data_dir.join(&entry.cipher_path);
        let target = PathBuf::from(target_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
        }

        if entry.kind == "folder" {
            let data = crypto::decrypt_file_to_bytes(&blob_path, &mk)?;
            let parent = target
                .parent()
                .ok_or_else(|| "目标路径无父目录".to_string())?;
            let name = target
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry.name.clone());
            let dir_name = name.strip_suffix(".zip").unwrap_or(&name).to_string();
            Self::extract_folder_to(&data, &dir_name, parent)?;
        } else {
            crypto::decrypt_file_stream(&blob_path, &target, &mk)?;
        }
        Ok(())
    }

    pub fn export_entries_to_dir(&self, ids: &[String], dir: &str) -> Result<(), String> {
        let mk = self.require_unlocked()?;
        let target_dir = PathBuf::from(dir);
        fs::create_dir_all(&target_dir).map_err(|e| format!("创建目录失败: {e}"))?;
        for id in ids {
            let entry = match self.entries.iter().find(|e| e.id == *id).cloned() {
                Some(e) => e,
                None => continue,
            };
            let blob_path = self.data_dir.join(&entry.cipher_path);
            if entry.kind == "folder" {
                let data = crypto::decrypt_file_to_bytes(&blob_path, &mk)?;
                Self::extract_folder_to(&data, &entry.name, &target_dir)?;
            } else {
                let p = Self::unique_path(&target_dir, &entry.name);
                crypto::decrypt_file_stream(&blob_path, &p, &mk)?;
            }
        }
        Ok(())
    }

    pub fn restore_entry(&mut self, id: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let mk = self.require_unlocked()?;
        let blob_path = self.data_dir.join(&entry.cipher_path);

        let target_dir = if let Some(op) = &entry.original_path {
            let orig = PathBuf::from(op);
            let parent = orig.parent().map(|p| p.to_path_buf());
            if let Some(pr) = parent {
                if pr.exists() && pr.is_dir() {
                    pr
                } else {
                    default_documents_dir()?
                }
            } else {
                default_documents_dir()?
            }
        } else {
            default_documents_dir()?
        };

        if entry.kind == "folder" {
            let data = crypto::decrypt_file_to_bytes(&blob_path, &mk)?;
            Self::extract_folder_to(&data, &entry.name, &target_dir)?;
        } else {
            let p = Self::unique_path(&target_dir, &entry.name);
            crypto::decrypt_file_stream(&blob_path, &p, &mk)?;
        }
        self.delete_stored_entry(id);
        let _ = self.save_index();
        Ok(())
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), String> {
        self.require_unlocked()?;
        if !self.entries.iter().any(|e| e.id == id) {
            return Err("条目不存在".to_string());
        }
        self.delete_stored_entry(id);
        self.save_index()?;
        Ok(())
    }

    pub fn delete_entries(&mut self, ids: &[String]) -> Result<(), String> {
        self.require_unlocked()?;
        for id in ids {
            self.delete_stored_entry(id);
        }
        self.save_index()?;
        Ok(())
    }

    fn delete_stored_entry(&mut self, id: &str) {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            let entry = self.entries.remove(pos);
            let blob = self.data_dir.join(&entry.cipher_path);
            let _ = best_effort_erase_file(&blob);
        }
    }

    /// 一键清除当前保险箱已保存在系统钥匙串中的密码
    pub fn forget_saved_password(&mut self) -> Result<(), String> {
        keychain::delete_password(&self.current_vault_id)
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<String, String> {
        let mk = self.require_unlocked()?;
        validate_password_strength(new)?;
        if self.keyring_path().exists() {
            let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
            let keyring_bytes = fs::read(self.keyring_path())
                .map_err(|e| format!("读取 keyring 失败: {e}"))?;
            let keyring: Keyring = serde_json::from_slice(&keyring_bytes)
                .map_err(|e| format!("解析 keyring 失败: {e}"))?;
            let kdf_type = keyring.kdf_type.as_deref().unwrap_or(crypto::KDF_TYPE_PBKDF2);
            let mut kek = if kdf_type == crypto::KDF_TYPE_ARGON2ID {
                let mem = keyring.memory_kib.unwrap_or(crypto::ARGON2_DEFAULT_MEMORY_KIB);
                let iters = keyring.iterations.unwrap_or(crypto::ARGON2_DEFAULT_ITERATIONS);
                let par = keyring.parallelism.unwrap_or(crypto::ARGON2_DEFAULT_PARALLELISM);
                crypto::derive_key_argon2id(old, &salt, mem, iters, par)?
            } else {
                let iters = keyring.iterations.unwrap_or(crypto::LEGACY_PBKDF2_ITERATIONS);
                crypto::derive_key_password_with_iter(old, &salt, iters)
            };
            let _ = crypto::decrypt(&keyring.password_wrap, &kek)?;
            crypto::zeroize_slice(&mut kek);
        } else {
            let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
            let mut kek = crypto::derive_key_password(old, &salt);
            let enc = fs::read(self.index_path()).map_err(|e| format!("读取索引失败: {e}"))?;
            let _ = crypto::decrypt(&enc, &kek)?;
            crypto::zeroize_slice(&mut kek);
        }

        let new_recovery = crypto::generate_recovery_code();
        self.rewrite_keyring(&mk, new, &new_recovery)?;
        if keychain::has_saved_password(&self.current_vault_id) {
            let _ = keychain::save_password(&self.current_vault_id, new);
        }
        Ok(new_recovery)
    }

    pub fn recover_password(
        &mut self,
        recovery_code: &str,
        new_password: &str,
    ) -> Result<String, String> {
        if !self.vault_exists() {
            return Err("保险箱不存在".into());
        }
        if !self.keyring_path().exists() {
            return Err("该保险箱未设置恢复码，无法通过恢复码重置".into());
        }
        validate_password_strength(new_password)?;

        // 恢复码同样需要限流，否则可被无限次尝试而绕过密码侧的冷却保护。
        self.refresh_guard();
        let now = Utc::now().timestamp();
        if let Some(lockout) = self.recovery_lockout_until {
            if now < lockout {
                let remaining = lockout - now;
                return Err(format!("恢复码输错次数过多，安全保护中，请等待 {remaining} 秒后再试"));
            } else {
                self.recovery_lockout_until = None;
            }
        }

        let mk = match self.unwrap_with_recovery(recovery_code) {
            Ok(mk) => {
                self.recovery_failed_attempts = 0;
                self.recovery_lockout_until = None;
                self.persist_guard();
                mk
            }
            Err(_) => {
                self.recovery_failed_attempts += 1;
                let cooldown = Self::lockout_cooldown(self.recovery_failed_attempts);
                if cooldown > 0 {
                    self.recovery_lockout_until = Some(Utc::now().timestamp() + cooldown);
                }
                self.persist_guard();
                if cooldown > 0 {
                    return Err(format!(
                        "恢复码错误！已连续输错 {} 次，安全保护触发，请等待 {} 秒后再试",
                        self.recovery_failed_attempts, cooldown
                    ));
                }
                let tries_left = 3 - self.recovery_failed_attempts;
                return Err(format!("恢复码错误！剩余 {} 次尝试后将触发安全冷却延迟", tries_left));
            }
        };
        let _ = self.load_index_with_key(&mk)?;
        let new_recovery = crypto::generate_recovery_code();
        self.rewrite_keyring(&mk, new_password, &new_recovery)?;
        if keychain::has_saved_password(&self.current_vault_id) {
            let _ = keychain::save_password(&self.current_vault_id, new_password);
        }
        self.entries = self.load_index_with_key(&mk)?;
        self.master_key = Some(crypto::ProtectedMasterKey::new(mk));
        self.is_unlocked = true;
        self.failed_attempts = 0;
        self.lockout_until = None;
        self.persist_guard();
        self.touch();
        Ok(new_recovery)
    }

    fn rewrite_keyring(
        &self,
        master_key: &[u8; 32],
        password: &str,
        recovery_code: &str,
    ) -> Result<(), String> {
        let password_salt = crypto::random_bytes(crypto::SALT_LEN);
        let mut password_kek = crypto::derive_key_argon2id(
            password,
            &password_salt,
            crypto::ARGON2_DEFAULT_MEMORY_KIB,
            crypto::ARGON2_DEFAULT_ITERATIONS,
            crypto::ARGON2_DEFAULT_PARALLELISM,
        )?;
        let password_wrap = crypto::encrypt(master_key, &password_kek)?;
        crypto::zeroize_slice(&mut password_kek);

        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let mut recovery_kek = crypto::derive_key_recovery_argon2id(
            recovery_code,
            &recovery_salt,
            crypto::ARGON2_DEFAULT_MEMORY_KIB,
            crypto::ARGON2_DEFAULT_ITERATIONS,
            crypto::ARGON2_DEFAULT_PARALLELISM,
        )?;
        let recovery_wrap = crypto::encrypt(master_key, &recovery_kek)?;
        crypto::zeroize_slice(&mut recovery_kek);

        let keyring = Keyring {
            version: KEYRING_VERSION,
            password_wrap,
            recovery_salt,
            recovery_wrap,
            iterations: Some(crypto::ARGON2_DEFAULT_ITERATIONS),
            recovery_iterations: Some(crypto::ARGON2_DEFAULT_ITERATIONS),
            kdf_type: Some(crypto::KDF_TYPE_ARGON2ID.to_string()),
            memory_kib: Some(crypto::ARGON2_DEFAULT_MEMORY_KIB),
            parallelism: Some(crypto::ARGON2_DEFAULT_PARALLELISM),
            recovery_kdf_type: Some(crypto::KDF_TYPE_ARGON2ID.to_string()),
            recovery_memory_kib: Some(crypto::ARGON2_DEFAULT_MEMORY_KIB),
            recovery_parallelism: Some(crypto::ARGON2_DEFAULT_PARALLELISM),
        };
        let bytes = serde_json::to_vec(&keyring).map_err(|e| format!("序列化失败: {e}"))?;
        atomic_write(&self.keyring_path(), &bytes)?;
        atomic_write(&self.salt_path(), &password_salt)?;
        Ok(())
    }

    pub fn temporary_export_url(&self, id: &str) -> Result<String, String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let mk = self.require_unlocked()?;
        let blob_path = self.data_dir.join(&entry.cipher_path);
        create_private_dir(&self.temp_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

        let name = if entry.kind == "folder" {
            format!("{}.zip", entry.name)
        } else {
            entry.name.clone()
        };
        let target = Self::unique_path(&self.temp_dir, &name);
        if target.exists() {
            let _ = fs::remove_file(&target);
        }

        if entry.kind == "folder" {
            let data = crypto::decrypt_file_to_bytes(&blob_path, &mk)?;
            create_private_file(&target).map_err(|e| format!("创建临时文件失败: {e}"))?;
            if let Err(e) = fs::write(&target, &data) {
                remove_plain_path(&target);
                return Err(format!("写入临时文件失败: {e}"));
            }
        } else {
            create_private_file(&target).map_err(|e| format!("创建临时文件失败: {e}"))?;
            crypto::decrypt_file_stream(&blob_path, &target, &mk)?;
        }

        Ok(target.to_string_lossy().to_string())
    }

    pub fn clear_temp(&self) -> Result<(), String> {
        if self.temp_dir.exists() {
            best_effort_erase_dir(&self.temp_dir);
        }
        Ok(())
    }

    pub fn save_index(&self) -> Result<(), String> {
        let mk = self
            .master_key
            .as_ref()
            .ok_or_else(|| "主密钥缺失".to_string())?;
        // 代次必须单调递增：以钥匙串锚点（其次现有索引）为基线 +1，
        // 这样即便攻击者把旧 index.enc / index.enc.bak 复制回来，也会因代次过小而拒绝加载。
        let generation = self.current_index_generation(mk).saturating_add(1);
        let index = IndexData {
            generation,
            entries: self.entries.clone(),
        };
        let json = serde_json::to_vec(&index).map_err(|e| format!("序列化索引失败: {e}"))?;
        let enc = crypto::encrypt(&json, mk)?;

        // 备份与主索引写入同一代次的最新密文：否则恢复旧备份时会因代次小于锚点
        // 被回滚检测拒绝，备份等于不可用。先写备份再写主索引，最后更新锚点。
        atomic_write(&self.vault_dir.join("index.enc.bak"), &enc)?;
        atomic_write(&self.index_path(), &enc)?;
        // 先落索引、后更新锚点：中途崩溃时索引代次会领先锚点，加载时按索引修复锚点即可。
        store_generation_anchor(&self.current_vault_id, generation);
        Ok(())
    }

    /// 当前索引应基于的代次：优先取钥匙串锚点，其次读取现有索引内记录的值。
    fn current_index_generation(&self, key: &[u8; 32]) -> u64 {
        if let Some(anchor) = load_generation_anchor(&self.current_vault_id) {
            return anchor;
        }
        if let Ok(enc) = fs::read(self.index_path()) {
            if let Ok(json) = crypto::decrypt(&enc, key) {
                if let Ok(index) = serde_json::from_slice::<IndexData>(&json) {
                    return index.generation;
                }
            }
        }
        0
    }

    /// 校验索引代次未被回滚，接受后按需把锚点修复到索引当前代次。
    fn accept_index(&self, index: IndexData) -> Result<Vec<VaultEntry>, String> {
        let anchor = load_generation_anchor(&self.current_vault_id);
        check_index_generation(index.generation, anchor)?;
        if anchor != Some(index.generation) {
            store_generation_anchor(&self.current_vault_id, index.generation);
        }
        Ok(index.entries)
    }

    fn load_index_with_key(&self, key: &[u8; 32]) -> Result<Vec<VaultEntry>, String> {
        let read_res = fs::read(self.index_path());
        let enc = match read_res {
            Ok(bytes) => bytes,
            Err(e) => {
                let bak_path = self.vault_dir.join("index.enc.bak");
                if bak_path.exists() {
                    fs::read(&bak_path).map_err(|_| format!("读取索引失败且无可用备份: {e}"))?
                } else {
                    return Err(format!("读取索引失败: {e}"));
                }
            }
        };

        match crypto::decrypt(&enc, key) {
            Ok(json) => {
                let index: IndexData =
                    serde_json::from_slice(&json).map_err(|e| format!("解析索引失败: {e}"))?;
                self.accept_index(index)
            }
            Err(primary_err) => {
                let bak_path = self.vault_dir.join("index.enc.bak");
                if bak_path.exists() {
                    if let Ok(bak_enc) = fs::read(&bak_path) {
                        if let Ok(json) = crypto::decrypt(&bak_enc, key) {
                            if let Ok(index) = serde_json::from_slice::<IndexData>(&json) {
                                // 备份同样要通过代次校验，防止攻击者回滚整个目录。
                                let entries = self.accept_index(index)?;
                                let _ = fs::copy(&bak_path, self.index_path());
                                return Ok(entries);
                            }
                        }
                    }
                }
                Err(primary_err)
            }
        }
    }

    pub fn get_auto_lock_minutes(&self) -> u64 {
        self.auto_lock_minutes
    }

    pub fn set_auto_lock_minutes(&mut self, mins: u64) {
        self.auto_lock_minutes = mins;
        let mut cfg = load_config(&self.config_path).unwrap_or_default();
        cfg.auto_lock_minutes = Some(mins);
        let _ = save_meta_json(&self.config_path, &cfg);
    }

    pub fn reset_vault(&mut self) -> Result<(), String> {
        // 破坏性操作：必须处于已解锁状态，避免锁定态下被静默清空数据。
        self.require_unlocked()?;
        if self.vault_dir.exists() {
            fs::remove_dir_all(&self.vault_dir)
                .map_err(|e| format!("删除 vault 目录失败: {e}"))?;
        }
        let _ = keychain::delete_password(&self.current_vault_id);
        // 与 delete_vault 一致：清空保险箱后同步移除索引代次锚点，
        // 否则下次新建同名保险箱会因锚点残留而误判「索引回滚」。
        let _ = keychain::delete_index_generation(&self.current_vault_id);
        self.master_key = None;
        self.entries.clear();
        self.is_unlocked = false;
        let _ = create_private_dir(&self.data_dir);
        let _ = create_private_dir(&self.temp_dir);
        Ok(())
    }

    pub fn get_vault_size(&self) -> Result<u64, String> {
        fn dir_size(p: &Path) -> u64 {
            let mut total = 0u64;
            if let Ok(rd) = fs::read_dir(p) {
                for e in rd.flatten() {
                    let path = e.path();
                    if let Ok(meta) = e.metadata() {
                        if meta.is_dir() {
                            total += dir_size(&path);
                        } else {
                            total += meta.len();
                        }
                    }
                }
            }
            total
        }
        Ok(dir_size(&self.vault_dir))
    }
}

fn load_config(path: &Path) -> Option<AppConfig> {
    load_meta_json(path)
}

fn default_documents_dir() -> Result<PathBuf, String> {
    if let Some(dirs) = directories::UserDirs::new() {
        if let Some(d) = dirs.document_dir() {
            let _ = fs::create_dir_all(d);
            return Ok(d.to_path_buf());
        }
    }
    if let Some(home) = directories::UserDirs::new().map(|d| d.home_dir().to_path_buf()) {
        let p = home.join("Documents");
        let _ = fs::create_dir_all(&p);
        return Ok(p);
    }
    Err("无法定位文档目录".into())
}

/// 把目录打包为 zip 并流式写入 `dest`，内存占用与文件夹总大小无关。
///
/// 安全处理：
/// - 用 `DirEntry::file_type()`（lstat 语义）判断类型，**不跟随符号链接**：
///   既避免链接环导致无限递归，也避免把目录树之外的敏感文件打进包里。
/// - 用 `canonicalize` 记录已访问目录，遇到重复访问（硬链接目录 / 绑定挂载）直接跳过。
fn zip_directory_to_file(dir: &Path, dest: &Path) -> Result<(), String> {
    create_private_file(dest).map_err(|e| format!("创建临时 zip 失败: {e}"))?;
    let file = fs::File::create(dest).map_err(|e| format!("打开临时 zip 失败: {e}"))?;
    let mut zip = ZipWriter::new(std::io::BufWriter::new(file));
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);

    fn add_dir<W: std::io::Write + std::io::Seek>(
        zip: &mut ZipWriter<W>,
        root: &Path,
        current: &Path,
        options: &FileOptions<()>,
        visited: &mut std::collections::HashSet<PathBuf>,
    ) -> Result<(), String> {
        let canon = fs::canonicalize(current)
            .map_err(|e| format!("规范化目录路径失败 {}: {e}", redact_path(current)))?;
        if !visited.insert(canon) {
            return Ok(());
        }

        for entry in fs::read_dir(current).map_err(|e| format!("读取目录失败: {e}"))? {
            let entry = entry.map_err(|e| format!("读取条目失败: {e}"))?;
            let path = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| format!("读取条目类型失败: {e}"))?;
            if ft.is_symlink() {
                // 跳过符号链接：不跟随可避免链接环，也避免把外部目录内容打包进来。
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|e| format!("路径前缀无效: {e}"))?;
            let rel_str = relative
                .to_str()
                .ok_or_else(|| "非 UTF-8 路径名".to_string())?;

            if ft.is_dir() {
                zip.add_directory(rel_str, *options)
                    .map_err(|e| format!("写入 zip 目录失败: {e}"))?;
                add_dir(zip, root, &path, options, visited)?;
            } else if ft.is_file() {
                zip.start_file(rel_str, *options)
                    .map_err(|e| format!("写入 zip 文件头失败: {e}"))?;
                let mut f = fs::File::open(&path).map_err(|e| format!("打开文件失败: {e}"))?;
                std::io::copy(&mut f, zip).map_err(|e| format!("复制文件内容到 zip 失败: {e}"))?;
            }
            // 其余类型（FIFO / socket / 设备文件）跳过：读取它们可能阻塞或产生副作用。
        }
        Ok(())
    }

    let mut visited = std::collections::HashSet::new();
    add_dir(&mut zip, dir, dir, &options, &mut visited)?;

    let mut writer = zip.finish().map_err(|e| format!("完成 zip 失败: {e}"))?;
    use std::io::Write;
    writer
        .flush()
        .map_err(|e| format!("刷新 zip 失败: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造测试用 VaultManager：security.json 位于 base 根目录，各保险箱数据在 base/<id> 下。
    fn make_test_vm(base: &std::path::Path, vault_id: &str) -> VaultManager {
        let vault_dir = base.join(vault_id);
        let data_dir = vault_dir.join("data");
        let temp_sub = vault_dir.join("tmp");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&temp_sub).unwrap();
        VaultManager {
            entries: Vec::new(),
            master_key: None,
            is_unlocked: false,
            data_base: base.to_path_buf(),
            current_vault_id: vault_id.into(),
            current_vault_name: "测试保险箱".into(),
            vault_dir,
            data_dir,
            temp_dir: temp_sub,
            config_path: base.join("config.json"),
            auto_lock_minutes: 5,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        }
    }

    fn tmp_base(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("filelocker_{tag}_{}", Uuid::new_v4()))
    }

    #[test]
    fn test_atomic_write() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("test_file.txt");

        atomic_write(&file_path, b"initial data").unwrap();
        assert_eq!(fs::read(&file_path).unwrap(), b"initial data");

        atomic_write(&file_path, b"updated data").unwrap();
        assert_eq!(fs::read(&file_path).unwrap(), b"updated data");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_stream_encryption_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_stream_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let src_path = temp_dir.join("large_sample.dat");
        let enc_path = temp_dir.join("large_sample.dat.enc");
        let dst_path = temp_dir.join("large_sample.dat.dec");

        // 构造大于单个分块（2.5MB）的数据测试跨分块
        let test_data = vec![0xABu8; (2.5 * 1024.0 * 1024.0) as usize];
        fs::write(&src_path, &test_data).unwrap();

        let key = [42u8; 32];
        let plain_size = crypto::encrypt_file_stream(&src_path, &enc_path, &key).unwrap();
        assert_eq!(plain_size, test_data.len() as u64);

        // 验证文件头是分块魔数
        let enc_bytes = fs::read(&enc_path).unwrap();
        assert_eq!(&enc_bytes[..12], crypto::CHUNK_MAGIC);

        // 解密
        let dec_size = crypto::decrypt_file_stream(&enc_path, &dst_path, &key).unwrap();
        assert_eq!(dec_size, test_data.len() as u64);
        assert_eq!(fs::read(&dst_path).unwrap(), test_data);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_rename_entry() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_rename_test_{}", Uuid::new_v4()));
        let vault_dir = temp_dir.join("vault");
        let data_dir = vault_dir.join("data");
        let temp_sub = vault_dir.join("tmp");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&temp_sub).unwrap();

        let mut vm = VaultManager {
            entries: Vec::new(),
            master_key: Some(crypto::ProtectedMasterKey::new([7u8; 32])),
            is_unlocked: true,
            data_base: temp_dir.clone(),
            current_vault_id: "default".into(),
            current_vault_name: "默认保险箱".into(),
            vault_dir: vault_dir.clone(),
            data_dir,
            temp_dir: temp_sub,
            config_path: temp_dir.join("config.json"),
            auto_lock_minutes: 5,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        };

        vm.entries.push(VaultEntry {
            id: "entry-1".into(),
            name: "old_name.pdf".into(),
            size: 1024,
            added_at: 1000,
            kind: "file".into(),
            original_path: None,
            cipher_path: "blob1.bin".into(),
        });
        vm.save_index().unwrap();

        // 成功重命名
        let res = vm.rename_entry("entry-1", "new_name.pdf").unwrap();
        assert_eq!(res.name, "new_name.pdf");
        assert_eq!(vm.entries[0].name, "new_name.pdf");

        // 空名失败
        assert!(vm.rename_entry("entry-1", "   ").is_err());
        // 非法路径字符失败
        assert!(vm.rename_entry("entry-1", "folder/file.pdf").is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_index_backup_recovery() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_test_{}", Uuid::new_v4()));
        let vault_dir = temp_dir.join("vault");
        let data_dir = vault_dir.join("data");
        let temp_sub = vault_dir.join("tmp");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&temp_sub).unwrap();

        let mut vm = VaultManager {
            entries: Vec::new(),
            master_key: Some(crypto::ProtectedMasterKey::new([7u8; 32])),
            is_unlocked: true,
            data_base: temp_dir.clone(),
            current_vault_id: "default".into(),
            current_vault_name: "默认保险箱".into(),
            vault_dir: vault_dir.clone(),
            data_dir,
            temp_dir: temp_sub,
            config_path: temp_dir.join("config.json"),
            auto_lock_minutes: 5,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        };

        vm.entries.push(VaultEntry {
            id: "test-id-1".into(),
            name: "secret.txt".into(),
            size: 100,
            added_at: 1000,
            kind: "file".into(),
            original_path: None,
            cipher_path: "blob.bin".into(),
        });
        vm.save_index().unwrap();

        assert!(vm.index_path().exists());

        vm.entries.push(VaultEntry {
            id: "test-id-2".into(),
            name: "notes.txt".into(),
            size: 200,
            added_at: 2000,
            kind: "file".into(),
            original_path: None,
            cipher_path: "blob2.bin".into(),
        });
        vm.save_index().unwrap();

        let bak_path = vm.vault_dir.join("index.enc.bak");
        assert!(bak_path.exists());

        fs::write(vm.index_path(), b"corrupted bytes").unwrap();

        // 备份与主索引现在写入同一代次的最新密文，因此恢复出来的是最新状态（2 条），
        // 而不是上一代（1 条）——否则旧代次备份会被回滚检测拒绝，备份形同虚设。
        let recovered = vm.load_index_with_key(&[7u8; 32]).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[1].name, "notes.txt");

        let loaded_again = vm.load_index_with_key(&[7u8; 32]).unwrap();
        assert_eq!(loaded_again.len(), 2);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_multi_vault_switching() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_multivault_test_{}", Uuid::new_v4()));
        let vault_dir = temp_dir.join("vault");
        let data_dir = vault_dir.join("data");
        let temp_sub = vault_dir.join("tmp");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&temp_sub).unwrap();

        let mut vm = VaultManager {
            entries: Vec::new(),
            master_key: None,
            is_unlocked: false,
            data_base: temp_dir.clone(),
            current_vault_id: "default".into(),
            current_vault_name: "默认保险箱".into(),
            vault_dir: vault_dir.clone(),
            data_dir,
            temp_dir: temp_sub,
            config_path: temp_dir.join("config.json"),
            auto_lock_minutes: 5,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        };

        // 默认保险箱先初始化密码（后续删除保护需在解锁态验证）
        vm.set_password("DefaultPass123!", false).unwrap();
        vm.lock();

        // 初始保险箱列表包含默认保险箱
        let list = vm.list_vaults().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "default");
        assert_eq!(list[0].name, "默认保险箱");

        // 创建新保险箱 "工作保险箱"
        let create_res = vm.create_vault("工作保险箱", "WorkPass123!", false).unwrap();
        assert_eq!(create_res.vault.name, "工作保险箱");
        assert_eq!(vm.current_vault_name, "工作保险箱");
        assert!(vm.is_unlocked);

        // 列出所有保险箱应有 2 个
        let list2 = vm.list_vaults().unwrap();
        assert_eq!(list2.len(), 2);

        // 重命名当前保险箱
        let current_id = vm.current_vault_id.clone();
        vm.rename_vault(&current_id, "绝密工作档案").unwrap();
        assert_eq!(vm.current_vault_name, "绝密工作档案");

        // 切回默认保险箱
        let switched = vm.switch_vault("default").unwrap();
        assert_eq!(switched.id, "default");
        assert_eq!(vm.current_vault_id, "default");
        // 切换后保险箱处于锁定状态
        assert!(!vm.is_unlocked);

        // 删除前需处于解锁态：切回待删除的保险箱并解锁
        vm.switch_vault(&current_id).unwrap();
        vm.unlock("WorkPass123!", false).unwrap();

        // 删除刚创建的工作保险箱
        let after_delete = vm.delete_vault(&current_id).unwrap();
        assert_eq!(after_delete.id, "default");
        let list3 = vm.list_vaults().unwrap();
        assert_eq!(list3.len(), 1);

        // 仅剩一个保险箱时，尝试删除应该报错保护
        vm.unlock("DefaultPass123!", false).unwrap();
        assert!(vm.delete_vault("default").is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_best_effort_erase_file() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_shred_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let target = temp_dir.join("sensitive_secret.txt");
        fs::write(&target, b"Confidential plain text!").unwrap();
        assert!(target.exists());

        best_effort_erase_file(&target).unwrap();
        assert!(!target.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unlock_rate_limiting() {
        let temp_dir = std::env::temp_dir().join(format!("filelocker_ratelimit_test_{}", Uuid::new_v4()));
        let vault_dir = temp_dir.join("vault");
        let data_dir = vault_dir.join("data");
        let temp_sub = vault_dir.join("tmp");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&temp_sub).unwrap();

        let mut vm = VaultManager {
            entries: Vec::new(),
            master_key: None,
            is_unlocked: false,
            data_base: temp_dir.clone(),
            current_vault_id: "default".into(),
            current_vault_name: "默认保险箱".into(),
            vault_dir: vault_dir.clone(),
            data_dir,
            temp_dir: temp_sub,
            config_path: temp_dir.join("config.json"),
            auto_lock_minutes: 5,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        };

        vm.set_password("CorrectPassword123!", false).unwrap();
        vm.lock();

        // 连续输错 3 次
        assert!(vm.unlock("wrong1", false).is_err());
        assert_eq!(vm.failed_attempts, 1);
        assert!(vm.unlock("wrong2", false).is_err());
        assert_eq!(vm.failed_attempts, 2);
        let err3 = vm.unlock("wrong3", false).unwrap_err();
        assert_eq!(vm.failed_attempts, 3);
        assert!(err3.contains("安全保护触发"));
        assert!(vm.lockout_until.is_some());

        // 此时即使输入正确密码，也处于安全冷却中，被安全阻断
        let blocked = vm.unlock("CorrectPassword123!", false).unwrap_err();
        assert!(blocked.contains("安全保护中"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_kdf_upgrade_from_weak_iterations() {
        let temp_dir =
            std::env::temp_dir().join(format!("filelocker_kdf_test_{}", Uuid::new_v4()));
        let vault_dir = temp_dir.join("vault");
        let data_dir = vault_dir.join("data");
        let temp_sub = vault_dir.join("tmp");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&temp_sub).unwrap();

        let mut vm = VaultManager {
            entries: Vec::new(),
            master_key: None,
            is_unlocked: false,
            data_base: temp_dir.clone(),
            current_vault_id: "default".into(),
            current_vault_name: "默认保险箱".into(),
            vault_dir: vault_dir.clone(),
            data_dir,
            temp_dir: temp_sub,
            config_path: temp_dir.join("config.json"),
            auto_lock_minutes: 5,
            failed_attempts: 0,
            lockout_until: None,
            recovery_failed_attempts: 0,
            recovery_lockout_until: None,
            last_activity: Cell::new(Utc::now().timestamp()),
        };

        let recovery_code = vm.set_password("OldPassword123!", false).unwrap();
        let mk = **vm.master_key.as_ref().unwrap();

        // 伪造一个使用 100,000 次迭代的旧版 keyring（不记录 recovery_iterations）
        let salt = fs::read(vm.salt_path()).unwrap();
        let mut password_kek =
            crypto::derive_key_password_with_iter("OldPassword123!", &salt, 100_000);
        let password_wrap = crypto::encrypt(&mk, &password_kek).unwrap();
        crypto::zeroize_slice(&mut password_kek);
        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let mut recovery_kek =
            crypto::derive_key_recovery_with_iter(&recovery_code, &recovery_salt, 100_000);
        let recovery_wrap = crypto::encrypt(&mk, &recovery_kek).unwrap();
        crypto::zeroize_slice(&mut recovery_kek);
        let legacy = Keyring {
            version: 2,
            password_wrap,
            recovery_salt,
            recovery_wrap,
            iterations: Some(100_000),
            recovery_iterations: None,
            kdf_type: Some("pbkdf2".to_string()),
            memory_kib: None,
            parallelism: None,
            recovery_kdf_type: Some("pbkdf2".to_string()),
            recovery_memory_kib: None,
            recovery_parallelism: None,
        };
        atomic_write(&vm.keyring_path(), &serde_json::to_vec(&legacy).unwrap()).unwrap();

        // 解锁成功后应单向升级到 Argon2id，且绝不降到 100,000
        vm.lock();
        vm.unlock("OldPassword123!", false).unwrap();
        let upgraded: Keyring =
            serde_json::from_slice(&fs::read(vm.keyring_path()).unwrap()).unwrap();
        assert_eq!(upgraded.version, KEYRING_VERSION);
        assert_eq!(upgraded.kdf_type.as_deref(), Some(crypto::KDF_TYPE_ARGON2ID));
        assert_eq!(upgraded.iterations, Some(crypto::ARGON2_DEFAULT_ITERATIONS));
        assert_eq!(upgraded.recovery_iterations, Some(100_000));
        assert_eq!(upgraded.recovery_kdf_type.as_deref(), Some("pbkdf2"));

        // 升级后旧恢复码仍然有效
        vm.lock();
        assert!(vm
            .recover_password(&recovery_code, "NewPassword123!")
            .unwrap()
            .len() > 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_guard_state_persists_across_restart() {
        let base = tmp_base("guard");
        let mut vm = make_test_vm(&base, "vault-a");
        vm.set_password("CorrectPassword123!", false).unwrap();
        vm.lock();

        for _ in 0..3 {
            assert!(vm.unlock("wrong", false).is_err());
        }
        assert!(vm.lockout_until.is_some());

        // 模拟重启：新实例从 security.json 恢复冷却，无法通过重启绕过
        let mut restarted = make_test_vm(&base, "vault-a");
        let err = restarted
            .unlock("CorrectPassword123!", false)
            .unwrap_err();
        assert!(err.contains("安全保护中"), "实际错误: {err}");

        // 冷却按保险箱隔离：另一个保险箱不应受牵连
        let mut other = make_test_vm(&base, "vault-b");
        let other_err = other.unlock("CorrectPassword123!", false).unwrap_err();
        assert!(!other_err.contains("安全保护中"), "实际错误: {other_err}");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_recovery_rate_limiting() {
        let base = tmp_base("recovery_guard");
        let mut vm = make_test_vm(&base, "vault-a");
        let recovery_code = vm.set_password("CorrectPassword123!", false).unwrap();
        vm.lock();

        for _ in 0..2 {
            assert!(vm.recover_password("WRONG-CODE", "NewPassword123!").is_err());
        }
        let err = vm
            .recover_password("WRONG-CODE", "NewPassword123!")
            .unwrap_err();
        assert!(err.contains("安全保护触发"), "实际错误: {err}");
        assert_eq!(vm.recovery_failed_attempts, 3);
        assert!(vm.recovery_lockout_until.is_some());

        // 冷却期内即使恢复码正确也被拒绝
        let blocked = vm
            .recover_password(&recovery_code, "NewPassword123!")
            .unwrap_err();
        assert!(blocked.contains("安全保护中"), "实际错误: {blocked}");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_destructive_ops_require_unlock() {
        let base = tmp_base("destructive_guard");
        let mut vm = make_test_vm(&base, "vault-a");
        vm.set_password("CorrectPassword123!", false).unwrap();
        vm.lock();

        assert!(vm.reset_vault().unwrap_err().contains("尚未解锁"));
        assert!(vm.delete_entry("whatever").unwrap_err().contains("尚未解锁"));
        assert!(vm
            .delete_entries(&["a".to_string()])
            .unwrap_err()
            .contains("尚未解锁"));
        assert!(vm.delete_vault("vault-a").unwrap_err().contains("尚未解锁"));

        // 数据未被破坏
        assert!(vm.vault_exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_password_strength_policy() {
        let base = tmp_base("pwd_policy");
        let mut vm = make_test_vm(&base, "vault-a");

        assert!(vm.set_password("short", false).unwrap_err().contains("至少"));
        assert!(vm
            .set_password("12345678", false)
            .unwrap_err()
            .contains("过于简单"));
        assert!(vm
            .set_password("83920174", false)
            .unwrap_err()
            .contains("纯数字"));
        assert!(vm
            .set_password("aaaaaaaa", false)
            .unwrap_err()
            .contains("相同字符"));
        assert!(vm.set_password("StrongPass123!", false).is_ok());

        let _ = fs::remove_dir_all(&base);
    }
}
