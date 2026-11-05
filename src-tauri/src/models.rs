use serde::{Deserialize, Serialize};

/// 保险箱中的一个条目（解密后给前端使用的明文元数据）。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub size: u64,
    /// unix timestamp (milliseconds)
    pub added_at: i64,
    /// "file" | "folder"
    pub kind: String,
    pub original_path: Option<String>,
    /// 密文文件相对路径（位于 data_dir 下）
    pub cipher_path: String,
}

/// 落盘的 keyring：保存用「密码」和「恢复码」分别包装后的主密钥。
/// password 派生使用 vault 目录下 salt.bin 的盐值；
/// recovery 派生使用本结构中的 recovery_salt，使两种包装互不相关。
#[derive(Serialize, Deserialize, Clone)]
pub struct Keyring {
    pub version: u32,
    pub password_wrap: Vec<u8>,
    pub recovery_salt: Vec<u8>,
    pub recovery_wrap: Vec<u8>,
    /// password_wrap 的 PBKDF2 迭代次数。缺失表示旧版固定 600,000 次。
    #[serde(default)]
    pub iterations: Option<u32>,
    /// recovery_wrap 的 PBKDF2 迭代次数。缺失表示与 `iterations` 相同。
    /// 单独记录是因为恢复码包装无法在未知恢复码时随密码包装一起升级。
    #[serde(default)]
    pub recovery_iterations: Option<u32>,
    /// KDF 算法类型："pbkdf2"（默认旧版）或 "argon2id"
    #[serde(default)]
    pub kdf_type: Option<String>,
    /// Argon2id 内存占用（KiB），例如 65536（64MB）
    #[serde(default)]
    pub memory_kib: Option<u32>,
    /// Argon2id 并行度（lanes/threads）
    #[serde(default)]
    pub parallelism: Option<u32>,
    /// 恢复码包装使用的 KDF 算法类型
    #[serde(default)]
    pub recovery_kdf_type: Option<String>,
    /// 恢复码包装的 Argon2id 内存占用（KiB）
    #[serde(default)]
    pub recovery_memory_kib: Option<u32>,
    /// 恢复码包装的 Argon2id 并行度
    #[serde(default)]
    pub recovery_parallelism: Option<u32>,
    /// 设备密钥包装的主密钥（AES-256-GCM 密文）。当开启“记住密码”时写入，密钥保存在系统钥匙串中。
    /// 避免在系统钥匙串中直接存放用户明文主密码。
    #[serde(default)]
    pub device_wrap: Option<Vec<u8>>,
}

/// 索引加密落盘格式：nonce + ciphertext。
/// 整个 entries JSON 使用 master_key 做 AES-GCM 加密。
#[derive(Serialize, Deserialize)]
pub struct EncryptedIndexBlob {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// 本地应用配置（auto-lock 时长、当前激活保险箱等）。
#[derive(Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub auto_lock_minutes: Option<u64>,
    #[serde(default)]
    pub current_vault_id: Option<String>,
    /// 导入文件后是否安全粉碎原文件（而非移入系统废纸篓保留明文）
    #[serde(default)]
    pub shred_source_after_import: Option<bool>,
}

/// 保险箱概况
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultProfile {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

/// 保险箱状态与元信息
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub exists: bool,
    pub is_unlocked: bool,
    pub has_saved_password: bool,
}

/// 创建新保险箱结果（包含恢复码）
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CreateVaultResult {
    pub vault: VaultInfo,
    pub recovery_code: String,
}

/// 加密/解密/导出实时进度
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OperationProgress {
    pub stage: String, // "encrypt" | "decrypt" | "export"
    pub current_file: usize,
    pub total_files: usize,
    pub file_name: String,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub percent: f32,
    pub is_finished: bool,
}

/// 内存无痕预览数据（0 字节磁盘写入，避免外部 App 缓存与磁盘残留）
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EntryPreviewData {
    pub id: String,
    pub name: String,
    /// "image" | "text" | "pdf" | "audio" | "video" | "unsupported"
    pub kind: String,
    pub mime_type: String,
    pub data_base64: Option<String>,
    pub text_content: Option<String>,
    pub size: u64,
}
