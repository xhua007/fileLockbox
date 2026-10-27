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
}

/// 索引加密落盘格式：nonce + ciphertext。
/// 整个 entries JSON 使用 master_key 做 AES-GCM 加密。
#[derive(Serialize, Deserialize)]
pub struct EncryptedIndexBlob {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// 本地应用配置（auto-lock 时长等）。
#[derive(Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub auto_lock_minutes: Option<u64>,
}
