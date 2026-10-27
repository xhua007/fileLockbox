use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

pub const PBKDF2_ITERATIONS: u32 = 600_000;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const MASTER_KEY_LEN: usize = 32;

/// 用 PBKDF2-HMAC-SHA256 从密码 + 盐派生 32 字节密钥。
pub fn derive_key_password(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut out);
    out
}

/// Crockford-Base32 字母表（排除易混字符），共 32 个字符。
/// 0-9, A-Z 中剔除 I, L, O, U，保留 32 个。
const RECOVERY_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 生成 24 位恢复码（形如 ABCD-EFGH-JKLM-NPQR-STVW-XYZA），15 字节（120 位）熵。
/// 15 字节 = 120 bits，按 5 bits/字符 编码可得 24 个字符，每 4 个字符用 "-" 分隔。
pub fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 15];
    rand::thread_rng().fill_bytes(&mut bytes);

    let mut chars: Vec<char> = Vec::with_capacity(24);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes.iter() {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1F) as usize;
            chars.push(RECOVERY_ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    // 15*8=120 bits, 24*5=120 bits，恰好用完，无剩余。

    let mut out = String::with_capacity(24 + 5);
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(*c);
    }
    out
}

/// 归一化恢复码：去分隔符/空白，大写，替换易混字符（O→0, I/L→1, U→V）。
pub fn normalize_recovery_code(input: &str) -> String {
    let mut out = String::with_capacity(24);
    for c in input.chars() {
        match c {
            '-' | ' ' | '\t' | '\n' | '\r' => continue,
            'O' | 'o' => out.push('0'),
            'I' | 'i' | 'L' | 'l' => out.push('1'),
            'U' | 'u' => out.push('V'),
            other => {
                for u in other.to_uppercase() {
                    out.push(u);
                }
            }
        }
    }
    out
}

/// 用归一化后的恢复码派生密钥（与密码派生使用同样的 PBKDF2 参数）。
pub fn derive_key_recovery(code: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let normalized = normalize_recovery_code(code);
    derive_key_password(&normalized, salt)
}

/// AES-256-GCM 加密。返回 nonce(12) || ciphertext || tag(16) 的组合字节。
pub fn encrypt(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("加密失败: {e}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// AES-256-GCM 解密，输入为 nonce(12) || ciphertext || tag(16)。
pub fn decrypt(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN + 16 {
        return Err("密文太短，格式无效".into());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "解密失败，密钥错误或数据损坏".to_string())
}

/// 生成指定长度的加密安全随机字节。
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}
