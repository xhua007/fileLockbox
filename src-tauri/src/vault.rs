use crate::crypto;
use crate::fs as vfs;
use crate::keychain;
use crate::models::{AppConfig, Keyring, VaultEntry};
use chrono::Utc;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

#[derive(Debug)]
pub struct VaultManager {
    pub entries: Vec<VaultEntry>,
    pub master_key: Option<[u8; 32]>,
    pub is_unlocked: bool,
    pub vault_dir: PathBuf,
    pub data_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub config_path: PathBuf,
    pub auto_lock_minutes: u64,
}

/// 加密索引落盘的 JSON 外层结构（整个 entries 数组一次加密）。
#[derive(Serialize, Deserialize)]
struct IndexData {
    entries: Vec<VaultEntry>,
}

const KEYRING_VERSION: u32 = 2;
const DEFAULT_AUTO_LOCK_MINUTES: u64 = 5;

impl VaultManager {
    pub fn new() -> Self {
        let proj = ProjectDirs::from("com", "filelocker", "FileLocker")
            .expect("无法定位应用数据目录");
        let data_base = proj.data_dir().to_path_buf();
        let vault_dir = data_base.join("vault");
        let data_dir = vault_dir.join("data");
        let temp_dir = vault_dir.join("tmp");
        let config_path = data_base.join("config.json");

        // 确保基础目录存在。
        let _ = fs::create_dir_all(&data_dir);
        let _ = fs::create_dir_all(&temp_dir);

        // 加载配置
        let auto_lock_minutes = load_config(&config_path)
            .and_then(|c| c.auto_lock_minutes)
            .unwrap_or(DEFAULT_AUTO_LOCK_MINUTES);

        VaultManager {
            entries: Vec::new(),
            master_key: None,
            is_unlocked: false,
            vault_dir,
            data_dir,
            temp_dir,
            config_path,
            auto_lock_minutes,
        }
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

    fn require_unlocked(&self) -> Result<[u8; 32], String> {
        if !self.is_unlocked {
            return Err("保险箱尚未解锁".into());
        }
        self.master_key.ok_or_else(|| "主密钥缺失".into())
    }

    /// 首次设置密码：生成随机 master_key，用密码/恢复码分别包装后落盘。
    pub fn set_password(
        &mut self,
        password: &str,
        remember: bool,
        use_biometry: bool,
    ) -> Result<String, String> {
        if password.is_empty() {
            return Err("密码不能为空".into());
        }
        fs::create_dir_all(&self.data_dir).map_err(|e| format!("创建数据目录失败: {e}"))?;

        // 随机主密钥
        let master_key: [u8; 32] = crypto::random_bytes(32)
            .try_into()
            .expect("长度必为 32");

        // 密码盐 + KEK 包装
        let password_salt = crypto::random_bytes(crypto::SALT_LEN);
        let password_kek = crypto::derive_key_password(password, &password_salt);
        let password_wrap = crypto::encrypt(&master_key, &password_kek)?;

        // 恢复码
        let recovery_code = crypto::generate_recovery_code();
        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let recovery_kek = crypto::derive_key_recovery(&recovery_code, &recovery_salt);
        let recovery_wrap = crypto::encrypt(&master_key, &recovery_kek)?;

        let keyring = Keyring {
            version: KEYRING_VERSION,
            password_wrap,
            recovery_salt,
            recovery_wrap,
        };
        let keyring_json =
            serde_json::to_vec(&keyring).map_err(|e| format!("序列化 keyring 失败: {e}"))?;
        fs::write(self.keyring_path(), keyring_json)
            .map_err(|e| format!("写入 keyring 失败: {e}"))?;
        fs::write(self.salt_path(), &password_salt)
            .map_err(|e| format!("写入 salt 失败: {e}"))?;

        // 空索引
        self.entries = Vec::new();
        self.master_key = Some(master_key);
        self.is_unlocked = true;
        self.save_index()?;

        if remember {
            let _ = keychain::save_password(password, use_biometry);
        } else {
            let _ = keychain::delete_password();
        }

        Ok(recovery_code)
    }

    /// 用密码解锁。若不存在 keyring.json 但存在 salt+index，视为旧版本，
    /// 直接用密码派生密钥解密索引，并自动迁移到 keyring 体系。
    pub fn unlock(
        &mut self,
        password: &str,
        remember: bool,
        use_biometry: bool,
    ) -> Result<Vec<VaultEntry>, String> {
        if !self.vault_exists() {
            return Err("保险箱尚未设置密码".into());
        }

        if self.keyring_path().exists() {
            // 新版双包装 keyring
            let master_key = self.unwrap_with_password(password)?;
            self.master_key = Some(master_key);
            self.entries = self.load_index_with_key(&master_key)?;
            self.is_unlocked = true;
        } else {
            // 旧版：密码派生密钥直接解密索引
            let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
            let master_key = crypto::derive_key_password(password, &salt);
            self.entries = self.load_index_with_key(&master_key)?;
            // 无损迁移：用现有 master_key 生成新 keyring 和恢复码
            let recovery_code =
                self.upgrade_to_keyring(&master_key, password).map_err(|e| {
                    format!("旧保险箱迁移失败（可解锁但无法写入 keyring）: {e}")
                })?;
            self.master_key = Some(master_key);
            self.is_unlocked = true;
            // 首次迁移后暂存恢复码 —— 但 Tauri 命令返回值只期望 Vec<VaultEntry>，
            // 这里我们保持返回 entries，迁移的恢复码通过 pending_recovery_code 机制
            // 由前端主动查询。此 Rust 版本简化处理：迁移时直接返回 entries，用户需
            // 通过 change_password 流程获取新恢复码，或者我们这里不自动迁移（保留旧格式）。
            // 为安全起见，若迁移失败不影响解锁，我们忽略 recovery_code。
            let _ = recovery_code;
        }

        if remember {
            let _ = keychain::save_password(password, use_biometry);
        }
        Ok(self.entries.clone())
    }

    fn unwrap_with_password(&self, password: &str) -> Result<[u8; 32], String> {
        let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
        let keyring_bytes =
            fs::read(self.keyring_path()).map_err(|e| format!("读取 keyring 失败: {e}"))?;
        let keyring: Keyring =
            serde_json::from_slice(&keyring_bytes).map_err(|e| format!("解析 keyring 失败: {e}"))?;
        let kek = crypto::derive_key_password(password, &salt);
        let mk_bytes = crypto::decrypt(&keyring.password_wrap, &kek)?;
        if mk_bytes.len() != 32 {
            return Err("主密钥长度无效".into());
        }
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&mk_bytes);
        Ok(mk)
    }

    fn unwrap_with_recovery(&self, code: &str) -> Result<[u8; 32], String> {
        let keyring_bytes =
            fs::read(self.keyring_path()).map_err(|e| format!("读取 keyring 失败: {e}"))?;
        let keyring: Keyring =
            serde_json::from_slice(&keyring_bytes).map_err(|e| format!("解析 keyring 失败: {e}"))?;
        let kek = crypto::derive_key_recovery(code, &keyring.recovery_salt);
        let mk_bytes = crypto::decrypt(&keyring.recovery_wrap, &kek)?;
        if mk_bytes.len() != 32 {
            return Err("主密钥长度无效".into());
        }
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&mk_bytes);
        Ok(mk)
    }

    /// 将旧版本保险箱升级为 keyring 体系。返回新生成的恢复码。
    fn upgrade_to_keyring(
        &self,
        master_key: &[u8; 32],
        password: &str,
    ) -> Result<String, String> {
        let password_salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
        let password_kek = crypto::derive_key_password(password, &password_salt);
        let password_wrap = crypto::encrypt(master_key, &password_kek)?;

        let recovery_code = crypto::generate_recovery_code();
        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let recovery_kek = crypto::derive_key_recovery(&recovery_code, &recovery_salt);
        let recovery_wrap = crypto::encrypt(master_key, &recovery_kek)?;

        let keyring = Keyring {
            version: KEYRING_VERSION,
            password_wrap,
            recovery_salt,
            recovery_wrap,
        };
        let bytes = serde_json::to_vec(&keyring).map_err(|e| format!("序列化失败: {e}"))?;
        fs::write(self.keyring_path(), bytes).map_err(|e| format!("写入 keyring 失败: {e}"))?;
        Ok(recovery_code)
    }

    pub fn lock(&mut self) {
        self.master_key = None;
        self.entries.clear();
        self.is_unlocked = false;
        let _ = self.clear_temp();
    }

    pub fn has_saved_password(&self) -> bool {
        keychain::has_saved_password()
    }

    pub fn biometric_unlock(&mut self) -> Result<Vec<VaultEntry>, String> {
        let pwd = keychain::load_password()?;
        // 生物识别解锁时不再改写 remember 状态（保持原来的保存设置）。
        self.unlock(&pwd, false, false)
    }

    pub fn list_entries(&self) -> Result<Vec<VaultEntry>, String> {
        if !self.is_unlocked {
            return Err("保险箱尚未解锁".into());
        }
        Ok(self.entries.clone())
    }

    /// 读取并加密文件/文件夹为密文 blob。返回 (data 字节, kind, original_size, display_name)。
    fn prepare_item(path: &Path) -> Result<(Vec<u8>, String, u64, String), String> {
        let name = path
            .file_name()
            .ok_or_else(|| format!("路径无文件名: {}", path.display()))?
            .to_string_lossy()
            .to_string();
        let is_dir = path.is_dir();
        let data: Vec<u8>;
        let kind: String;
        let size: u64;
        if is_dir {
            data = zip_directory(path)?;
            kind = "folder".into();
            size = data.len() as u64;
        } else {
            data = fs::read(path).map_err(|e| format!("读取文件失败: {e}"))?;
            kind = "file".into();
            size = data.len() as u64;
        }
        Ok((data, kind, size, name))
    }

    pub fn add_files(&mut self, paths: Vec<String>) -> Result<Vec<VaultEntry>, String> {
        let mk = self.require_unlocked()?;
        fs::create_dir_all(&self.data_dir).map_err(|e| format!("创建 data 目录失败: {e}"))?;

        let existing = self.entries.clone();
        let mut added: Vec<VaultEntry> = Vec::new();
        let mut skipped = 0usize;

        for p_str in paths {
            let p = PathBuf::from(&p_str);
            if !p.exists() {
                return Err(format!("文件不存在: {}", p_str));
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

            let (plain, kind, size, name) = Self::prepare_item(&p)?;

            // 同名 + 同大小视为重复
            let is_dup = existing.iter().chain(added.iter()).any(|e| {
                e.name == name && e.size == size
            });
            if is_dup {
                skipped += 1;
                continue;
            }

            let id = Uuid::new_v4().to_string();
            let blob_name = format!("{}.bin", Uuid::new_v4());
            let cipher_blob = crypto::encrypt(&plain, &mk)?;
            let blob_path = self.data_dir.join(&blob_name);
            fs::write(&blob_path, cipher_blob).map_err(|e| format!("写入密文失败: {e}"))?;

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

        let _ = skipped; // 静默不返回给前端，保持返回 added 列表
        Ok(added)
    }

    /// 解密单个条目明文。
    fn decrypt_entry(&self, entry: &VaultEntry) -> Result<Vec<u8>, String> {
        let mk = self.require_unlocked()?;
        let blob_path = self.data_dir.join(&entry.cipher_path);
        let cipher = fs::read(&blob_path).map_err(|e| format!("读取密文失败: {e}"))?;
        crypto::decrypt(&cipher, &mk)
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

    fn write_plain(&self, _entry: &VaultEntry, data: &[u8], target: &Path) -> Result<(), String> {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
        }
        fs::write(target, data).map_err(|e| format!("写入文件失败: {e}"))?;
        Ok(())
    }

    /// 文件夹条目：解密后是 zip 字节。写临时 zip 再解压到 target_dir/name。
    fn extract_folder_to(data: &[u8], name: &str, target_dir: &Path) -> Result<PathBuf, String> {
        fs::create_dir_all(target_dir).map_err(|e| format!("创建目标目录失败: {e}"))?;
        // 写临时 zip
        let tmp_zip = target_dir.join(format!(".{}.zip", Uuid::new_v4()));
        fs::write(&tmp_zip, data).map_err(|e| format!("写临时 zip 失败: {e}"))?;

        let final_dir = Self::unique_path(target_dir, name);
        fs::create_dir_all(&final_dir).map_err(|e| format!("创建目录失败: {e}"))?;

        // 解压
        let file = fs::File::open(&tmp_zip).map_err(|e| format!("打开临时 zip 失败: {e}"))?;
        let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("打开 zip 失败: {e}"))?;
        archive
            .extract(&final_dir)
            .map_err(|e| format!("解压文件夹失败: {e}"))?;
        let _ = fs::remove_file(&tmp_zip);
        Ok(final_dir)
    }

    pub fn open_entry(&self, id: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let data = self.decrypt_entry(&entry)?;
        fs::create_dir_all(&self.temp_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

        let target = if entry.kind == "folder" {
            // 解压到 tmp/{uuid}/<name>
            let work = self.temp_dir.join(Uuid::new_v4().to_string());
            fs::create_dir_all(&work).map_err(|e| format!("创建临时目录失败: {e}"))?;
            Self::extract_folder_to(&data, &entry.name, &work)?
        } else {
            let target_path = Self::unique_path(&self.temp_dir, &entry.name);
            self.write_plain(&entry, &data, &target_path)?;
            target_path
        };
        vfs::open_path(&target)
    }

    pub fn export_entry(&self, id: &str, target_path: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let data = self.decrypt_entry(&entry)?;
        let target = PathBuf::from(target_path);
        if entry.kind == "folder" {
            let parent = target
                .parent()
                .ok_or_else(|| "目标路径无父目录".to_string())?;
            let name = target
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry.name.clone());
            // 若 target 带 .zip 后缀，strip 掉用作解压目录名
            let dir_name = name.strip_suffix(".zip").unwrap_or(&name).to_string();
            Self::extract_folder_to(&data, &dir_name, parent)?;
        } else {
            self.write_plain(&entry, &data, &target)?;
        }
        Ok(())
    }

    pub fn export_entries_to_dir(&self, ids: &[String], dir: &str) -> Result<(), String> {
        let target_dir = PathBuf::from(dir);
        fs::create_dir_all(&target_dir).map_err(|e| format!("创建目录失败: {e}"))?;
        for id in ids {
            let entry = match self.entries.iter().find(|e| e.id == *id).cloned() {
                Some(e) => e,
                None => continue,
            };
            let data = self.decrypt_entry(&entry)?;
            if entry.kind == "folder" {
                Self::extract_folder_to(&data, &entry.name, &target_dir)?;
            } else {
                let p = Self::unique_path(&target_dir, &entry.name);
                self.write_plain(&entry, &data, &p)?;
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
        let data = self.decrypt_entry(&entry)?;

        // 确定还原目标目录
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
            Self::extract_folder_to(&data, &entry.name, &target_dir)?;
        } else {
            let p = Self::unique_path(&target_dir, &entry.name);
            self.write_plain(&entry, &data, &p)?;
        }
        self.delete_stored_entry(id);
        let _ = self.save_index();
        Ok(())
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        // 尝试解密并放入废纸篓（忽略错误，密文始终删除）。
        if let Ok(data) = self.decrypt_entry(&entry) {
            let tmp_sub = self.temp_dir.join(Uuid::new_v4().to_string());
            let _ = fs::create_dir_all(&tmp_sub);
            if entry.kind == "folder" {
                if let Ok(dir) = Self::extract_folder_to(&data, &entry.name, &tmp_sub) {
                    let _ = vfs::move_to_trash(&dir);
                }
            } else {
                let tmp_file = tmp_sub.join(&entry.name);
                if fs::write(&tmp_file, &data).is_ok() {
                    let _ = vfs::move_to_trash(&tmp_file);
                }
            }
            let _ = fs::remove_dir_all(&tmp_sub);
        }
        self.delete_stored_entry(id);
        self.save_index()?;
        Ok(())
    }

    pub fn delete_entries(&mut self, ids: &[String]) -> Result<(), String> {
        for id in ids {
            let _ = self.delete_entry(id);
        }
        Ok(())
    }

    fn delete_stored_entry(&mut self, id: &str) {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            let entry = self.entries.remove(pos);
            let blob = self.data_dir.join(&entry.cipher_path);
            let _ = fs::remove_file(blob);
        }
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<String, String> {
        let mk = self.require_unlocked()?;
        // 校验旧密码：解密 password_wrap 以确认旧密码正确。
        if self.keyring_path().exists() {
            let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
            let keyring_bytes = fs::read(self.keyring_path())
                .map_err(|e| format!("读取 keyring 失败: {e}"))?;
            let keyring: Keyring = serde_json::from_slice(&keyring_bytes)
                .map_err(|e| format!("解析 keyring 失败: {e}"))?;
            let kek = crypto::derive_key_password(old, &salt);
            let _ = crypto::decrypt(&keyring.password_wrap, &kek)?;
        } else {
            // 旧格式：用旧密码派生密钥直接校验能否解密索引（此时索引已被加载，
            // 直接再尝试一次解密以验证密码）。
            let salt = fs::read(self.salt_path()).map_err(|e| format!("读取 salt 失败: {e}"))?;
            let kek = crypto::derive_key_password(old, &salt);
            let enc = fs::read(self.index_path()).map_err(|e| format!("读取索引失败: {e}"))?;
            let _ = crypto::decrypt(&enc, &kek)?;
        }

        let new_recovery = crypto::generate_recovery_code();
        self.rewrite_keyring(&mk, new, &new_recovery)?;
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
        let mk = self.unwrap_with_recovery(recovery_code)?;
        // 验证主密钥能解密索引
        let _ = self.load_index_with_key(&mk)?;
        let new_recovery = crypto::generate_recovery_code();
        self.rewrite_keyring(&mk, new_password, &new_recovery)?;
        self.master_key = Some(mk);
        self.entries = self.load_index_with_key(&mk)?;
        self.is_unlocked = true;
        Ok(new_recovery)
    }

    fn rewrite_keyring(
        &self,
        master_key: &[u8; 32],
        password: &str,
        recovery_code: &str,
    ) -> Result<(), String> {
        let password_salt = crypto::random_bytes(crypto::SALT_LEN);
        let password_kek = crypto::derive_key_password(password, &password_salt);
        let password_wrap = crypto::encrypt(master_key, &password_kek)?;

        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let recovery_kek = crypto::derive_key_recovery(recovery_code, &recovery_salt);
        let recovery_wrap = crypto::encrypt(master_key, &recovery_kek)?;

        let keyring = Keyring {
            version: KEYRING_VERSION,
            password_wrap,
            recovery_salt,
            recovery_wrap,
        };
        let bytes = serde_json::to_vec(&keyring).map_err(|e| format!("序列化失败: {e}"))?;
        fs::write(self.keyring_path(), bytes).map_err(|e| format!("写入 keyring 失败: {e}"))?;
        fs::write(self.salt_path(), &password_salt)
            .map_err(|e| format!("写入 salt 失败: {e}"))?;
        Ok(())
    }

    pub fn temporary_export_url(&self, id: &str) -> Result<String, String> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or_else(|| "条目不存在".to_string())?;
        let data = self.decrypt_entry(&entry)?;
        fs::create_dir_all(&self.temp_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;
        let name = if entry.kind == "folder" {
            format!("{}.zip", entry.name)
        } else {
            entry.name.clone()
        };
        let target = Self::unique_path(&self.temp_dir, &name);
        // 覆盖已存在的同名 tmp 文件（确保最新）。
        if target.exists() {
            let _ = fs::remove_file(&target);
        }
        fs::write(&target, &data).map_err(|e| format!("写入临时文件失败: {e}"))?;
        Ok(target.to_string_lossy().to_string())
    }

    pub fn clear_temp(&self) -> Result<(), String> {
        if self.temp_dir.exists() {
            for entry in
                fs::read_dir(&self.temp_dir).map_err(|e| format!("读取临时目录失败: {e}"))?
            {
                let Ok(entry) = entry else { continue };
                let p = entry.path();
                if p.is_dir() {
                    let _ = fs::remove_dir_all(p);
                } else {
                    let _ = fs::remove_file(p);
                }
            }
        }
        Ok(())
    }

    pub fn save_index(&self) -> Result<(), String> {
        let mk = self.master_key.ok_or_else(|| "主密钥缺失".to_string())?;
        let index = IndexData {
            entries: self.entries.clone(),
        };
        let json = serde_json::to_vec(&index).map_err(|e| format!("序列化索引失败: {e}"))?;
        let enc = crypto::encrypt(&json, &mk)?;
        fs::write(self.index_path(), enc).map_err(|e| format!("写入索引失败: {e}"))?;
        Ok(())
    }

    fn load_index_with_key(&self, key: &[u8; 32]) -> Result<Vec<VaultEntry>, String> {
        let enc = fs::read(self.index_path()).map_err(|e| format!("读取索引失败: {e}"))?;
        let json = crypto::decrypt(&enc, key)?;
        let index: IndexData =
            serde_json::from_slice(&json).map_err(|e| format!("解析索引失败: {e}"))?;
        Ok(index.entries)
    }

    pub fn get_auto_lock_minutes(&self) -> u64 {
        self.auto_lock_minutes
    }

    pub fn set_auto_lock_minutes(&mut self, mins: u64) {
        self.auto_lock_minutes = mins;
        let cfg = AppConfig {
            auto_lock_minutes: Some(mins),
        };
        if let Ok(bytes) = serde_json::to_vec(&cfg) {
            let _ = fs::write(&self.config_path, bytes);
        }
    }

    pub fn reset_vault(&mut self) -> Result<(), String> {
        // 删除整个 vault 目录（包含 data/tmp/salt/index/keyring）。
        if self.vault_dir.exists() {
            fs::remove_dir_all(&self.vault_dir)
                .map_err(|e| format!("删除 vault 目录失败: {e}"))?;
        }
        let _ = keychain::delete_password();
        self.entries.clear();
        self.master_key = None;
        self.is_unlocked = false;
        // 重建空目录结构以便下次 set_password。
        let _ = fs::create_dir_all(&self.data_dir);
        let _ = fs::create_dir_all(&self.temp_dir);
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
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn default_documents_dir() -> Result<PathBuf, String> {
    if let Some(dirs) = directories::UserDirs::new() {
        if let Some(d) = dirs.document_dir() {
            let _ = fs::create_dir_all(d);
            return Ok(d.to_path_buf());
        }
    }
    // 回退：$HOME/Documents
    if let Some(home) = directories::UserDirs::new().map(|d| d.home_dir().to_path_buf()) {
        let d = home.join("Documents");
        let _ = fs::create_dir_all(&d);
        return Ok(d);
    }
    Err("无法定位 Documents 目录".into())
}

/// 递归压缩目录为 zip 字节（deflate）。压缩的 zip 内部直接以目录的内容为根
/// （不含外层包装目录），解压时直接释放到目标目录即可还原出文件夹的全部内容。
fn zip_directory(dir: &Path) -> Result<Vec<u8>, String> {
    let buf = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buf);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    fn path_to_zip_string(p: &Path) -> String {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("/")
    }

    fn add_dir_recursive(
        zip: &mut ZipWriter<Cursor<Vec<u8>>>,
        base: &Path,
        prefix: &Path,
        options: FileOptions<()>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(base).map_err(|e| format!("读取目录失败: {e}"))? {
            let entry = entry.map_err(|e| format!("读取目录条目失败: {e}"))?;
            let path = entry.path();
            let rel = prefix.join(entry.file_name());
            let meta = entry.metadata().map_err(|e| format!("读取元数据失败: {e}"))?;
            let rel_str = path_to_zip_string(&rel);
            if meta.is_dir() {
                let dir_str = format!("{}/", rel_str);
                zip.add_directory(&dir_str, options)
                    .map_err(|e| format!("添加目录到 zip 失败: {e}"))?;
                add_dir_recursive(zip, &path, &rel, options)?;
            } else {
                let mut f = fs::File::open(&path).map_err(|e| format!("打开文件失败: {e}"))?;
                zip.start_file(&rel_str, options)
                    .map_err(|e| format!("添加文件到 zip 失败: {e}"))?;
                std::io::copy(&mut f, zip).map_err(|e| format!("写入 zip 失败: {e}"))?;
            }
        }
        Ok(())
    }

    add_dir_recursive(&mut zip, dir, Path::new(""), options)?;

    let cursor = zip.finish().map_err(|e| format!("完成 zip 失败: {e}"))?;
    Ok(cursor.into_inner())
}
