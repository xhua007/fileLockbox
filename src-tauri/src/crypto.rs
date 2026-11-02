use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const LEGACY_PBKDF2_ITERATIONS: u32 = 600_000;
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const MASTER_KEY_LEN: usize = 32;

/// 用 PBKDF2-HMAC-SHA256 从密码 + 盐派生 32 字节密钥（自定义迭代次数）。
pub fn derive_key_password_with_iter(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut out = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out);
    out
}

/// 用 PBKDF2-HMAC-SHA256 从密码 + 盐派生 32 字节密钥（默认 100,000 次）。
pub fn derive_key_password(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    derive_key_password_with_iter(password, salt, PBKDF2_ITERATIONS)
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

/// 安全擦除内存字节，使用 volatile write + 编译器屏障防止被编译器死代码消除优化掉。
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub const CHUNK_MAGIC: &[u8; 12] = b"FLCK_CHUNK\x01\x00";
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB chunk

/// 超大文件流式分块加密：将 src 文件按 2MB 依次分块加密写入 dst，峰值内存占用稳定在 ~4MB，支持任意 GB 级超大文件。
pub fn encrypt_file_stream(src: &Path, dst: &Path, key: &[u8; KEY_LEN]) -> Result<u64, String> {
    let mut reader = File::open(src).map_err(|e| format!("打开源文件失败: {e}"))?;
    let mut writer = File::create(dst).map_err(|e| format!("创建目标密文文件失败: {e}"))?;

    writer.write_all(CHUNK_MAGIC).map_err(|e| format!("写入头部失败: {e}"))?;
    writer.write_all(&(DEFAULT_CHUNK_SIZE as u32).to_be_bytes()).map_err(|e| format!("写入分块大小失败: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    let mut buffer = vec![0u8; DEFAULT_CHUNK_SIZE];
    let mut total_plain_bytes: u64 = 0;

    let total_file_len = reader.metadata().map(|m| m.len()).unwrap_or(0);
    let mut remaining = total_file_len;

    loop {
        let to_read = (DEFAULT_CHUNK_SIZE as u64).min(remaining) as usize;
        let mut read_bytes = 0;
        if to_read > 0 {
            while read_bytes < to_read {
                let n = reader.read(&mut buffer[read_bytes..to_read]).map_err(|e| format!("读取源文件失败: {e}"))?;
                if n == 0 { break; }
                read_bytes += n;
            }
        }
        remaining = remaining.saturating_sub(read_bytes as u64);
        let is_last = if remaining == 0 { 1u8 } else { 0u8 };

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, &buffer[..read_bytes])
            .map_err(|e| format!("分块加密失败: {e}"))?;

        let chunk_len = (NONCE_LEN + ciphertext.len()) as u32;
        writer.write_all(&chunk_len.to_be_bytes()).map_err(|e| format!("写入块长度失败: {e}"))?;
        writer.write_all(&nonce_bytes).map_err(|e| format!("写入 nonce 失败: {e}"))?;
        writer.write_all(&ciphertext).map_err(|e| format!("写入密文块失败: {e}"))?;
        writer.write_all(&[is_last]).map_err(|e| format!("写入结束标记失败: {e}"))?;

        total_plain_bytes += read_bytes as u64;

        if is_last == 1 {
            break;
        }
    }

    writer.flush().map_err(|e| format!("刷新目标文件失败: {e}"))?;
    Ok(total_plain_bytes)
}

/// 超大文件流式解密：将 cipher_path 解密流式写入 dst。自动兼容分块流格式与历史老版单 blob 格式。
pub fn decrypt_file_stream(cipher_path: &Path, dst: &Path, key: &[u8; KEY_LEN]) -> Result<u64, String> {
    let mut reader = File::open(cipher_path).map_err(|e| format!("打开密文文件失败: {e}"))?;
    let mut writer = File::create(dst).map_err(|e| format!("创建目标解密文件失败: {e}"))?;

    let file_len = reader.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len >= 16 {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header).map_err(|e| format!("读取头部失败: {e}"))?;
        if &header[..12] == CHUNK_MAGIC {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
            let mut total_plain_bytes: u64 = 0;

            loop {
                let mut len_buf = [0u8; 4];
                if let Err(e) = reader.read_exact(&mut len_buf) {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        break;
                    }
                    return Err(format!("读取分块长度失败: {e}"));
                }
                let chunk_len = u32::from_be_bytes(len_buf) as usize;
                if chunk_len < NONCE_LEN + 16 {
                    return Err("分块密文长度无效".into());
                }

                let mut nonce_bytes = [0u8; NONCE_LEN];
                reader.read_exact(&mut nonce_bytes).map_err(|e| format!("读取分块 nonce 失败: {e}"))?;

                let cipher_data_len = chunk_len - NONCE_LEN;
                let mut cipher_buf = vec![0u8; cipher_data_len];
                reader.read_exact(&mut cipher_buf).map_err(|e| format!("读取分块密文失败: {e}"))?;

                let mut is_last_buf = [0u8; 1];
                reader.read_exact(&mut is_last_buf).map_err(|e| format!("读取分块标记失败: {e}"))?;

                let nonce = Nonce::from_slice(&nonce_bytes);
                let plain = cipher
                    .decrypt(nonce, cipher_buf.as_slice())
                    .map_err(|_| "分块解密失败，密钥错误或数据损坏".to_string())?;

                total_plain_bytes += plain.len() as u64;
                writer.write_all(&plain).map_err(|e| format!("写入解密文件失败: {e}"))?;

                if is_last_buf[0] == 1 {
                    break;
                }
            }

            writer.flush().map_err(|e| format!("刷新解密文件失败: {e}"))?;
            return Ok(total_plain_bytes);
        }
        reader.seek(SeekFrom::Start(0)).map_err(|e| format!("回退文件流失败: {e}"))?;
    }

    // 传统单 blob 解密（向下兼容历史老文件）
    let mut cipher_all = Vec::new();
    reader.read_to_end(&mut cipher_all).map_err(|e| format!("读取旧密文失败: {e}"))?;
    let plain = decrypt(&cipher_all, key)?;
    writer.write_all(&plain).map_err(|e| format!("写入解密文件失败: {e}"))?;
    writer.flush().map_err(|e| format!("刷新解密文件失败: {e}"))?;
    Ok(plain.len() as u64)
}

/// 解密文件到内存字节（适合解密 zip 文件夹）。自动识别分块流与单 blob 格式。
pub fn decrypt_file_to_bytes(cipher_path: &Path, key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    let mut reader = File::open(cipher_path).map_err(|e| format!("打开密文文件失败: {e}"))?;
    let file_len = reader.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len >= 16 {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header).map_err(|e| format!("读取头部失败: {e}"))?;
        if &header[..12] == CHUNK_MAGIC {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
            let mut out = Vec::new();

            loop {
                let mut len_buf = [0u8; 4];
                if let Err(e) = reader.read_exact(&mut len_buf) {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        break;
                    }
                    return Err(format!("读取分块长度失败: {e}"));
                }
                let chunk_len = u32::from_be_bytes(len_buf) as usize;
                if chunk_len < NONCE_LEN + 16 {
                    return Err("分块密文长度无效".into());
                }

                let mut nonce_bytes = [0u8; NONCE_LEN];
                reader.read_exact(&mut nonce_bytes).map_err(|e| format!("读取分块 nonce 失败: {e}"))?;

                let cipher_data_len = chunk_len - NONCE_LEN;
                let mut cipher_buf = vec![0u8; cipher_data_len];
                reader.read_exact(&mut cipher_buf).map_err(|e| format!("读取分块密文失败: {e}"))?;

                let mut is_last_buf = [0u8; 1];
                reader.read_exact(&mut is_last_buf).map_err(|e| format!("读取分块标记失败: {e}"))?;

                let nonce = Nonce::from_slice(&nonce_bytes);
                let plain = cipher
                    .decrypt(nonce, cipher_buf.as_slice())
                    .map_err(|_| "分块解密失败，密钥错误或数据损坏".to_string())?;

                out.extend_from_slice(&plain);

                if is_last_buf[0] == 1 {
                    break;
                }
            }
            return Ok(out);
        }
        reader.seek(SeekFrom::Start(0)).map_err(|e| format!("回退文件流失败: {e}"))?;
    }

    let mut cipher_all = Vec::new();
    reader.read_to_end(&mut cipher_all).map_err(|e| format!("读取旧密文失败: {e}"))?;
    decrypt(&cipher_all, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_slice() {
        let mut secret = [0x5au8; 32];
        zeroize_slice(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn test_recovery_code_format() {
        let code = generate_recovery_code();
        // 24 个字符 + 5 个 '-' 分隔符 = 29
        assert_eq!(code.len(), 29);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 6);
        for part in parts {
            assert_eq!(part.len(), 4);
        }
    }

    #[test]
    fn test_normalize_recovery_code() {
        // 测试大小写混淆、破折号/空格过滤、易混淆字符替换
        // 注意：Crockford Base32 字母表不含 L，'l' 会被归一化替换为 '1'
        let input = " abcd-efgh jklm-npqr-stvw-xyza \n";
        let norm = normalize_recovery_code(input);
        assert_eq!(norm, "ABCDEFGHJK1MNPQRSTVWXYZA");

        // O -> 0, I/L -> 1, U -> V
        let confused = "OI LU";
        let norm_confused = normalize_recovery_code(confused);
        assert_eq!(norm_confused, "011V");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; KEY_LEN];
        let plain = b"Hello, encrypted vault!";
        let cipher = encrypt(plain, &key).expect("加密应成功");
        assert_ne!(cipher.as_slice(), plain);

        let decrypted = decrypt(&cipher, &key).expect("解密应成功");
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = [42u8; KEY_LEN];
        let key2 = [99u8; KEY_LEN];
        let plain = b"Sensitive document";
        let cipher = encrypt(plain, &key1).expect("加密应成功");

        let res = decrypt(&cipher, &key2);
        assert!(res.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = [42u8; KEY_LEN];
        let mut cipher = encrypt(b"test data", &key).expect("加密应成功");
        // 破坏密文字节
        let last = cipher.len() - 1;
        cipher[last] ^= 0xFF;
        assert!(decrypt(&cipher, &key).is_err());

        // 截断密文
        assert!(decrypt(&cipher[..15], &key).is_err());
    }
}
