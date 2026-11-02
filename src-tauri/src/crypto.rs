use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// 旧版 keyring 未显式记录 `iterations` 时所使用的迭代次数（历史实现固定为 600,000）。
pub const LEGACY_PBKDF2_ITERATIONS: u32 = 600_000;
/// 当前新建保险箱与密钥升级目标使用的 PBKDF2-HMAC-SHA256 迭代次数。
/// 说明：曾有版本将其降至 100,000（低于 OWASP 建议的 600,000），此处恢复为 600,000；
/// 所有低于该值的旧库会在成功解锁后单向升级，绝不反向降级。
pub const PBKDF2_ITERATIONS: u32 = 600_000;
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

/// 用 PBKDF2-HMAC-SHA256 从密码 + 盐派生 32 字节密钥（默认迭代次数见 [`PBKDF2_ITERATIONS`]）。
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

/// 用归一化后的恢复码派生密钥（使用默认 KDF 参数）。
pub fn derive_key_recovery(code: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    derive_key_recovery_with_iter(code, salt, PBKDF2_ITERATIONS)
}

/// 用归一化后的恢复码派生密钥（显式指定迭代次数，用于兼容旧版本 keyring）。
pub fn derive_key_recovery_with_iter(code: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let normalized = normalize_recovery_code(code);
    derive_key_password_with_iter(&normalized, salt, iterations)
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

/// 历史 v1 分块格式魔数：`is_last` 为明文且未参与认证，仅用于兼容读取旧文件。
pub const CHUNK_MAGIC_V1: &[u8; 12] = b"FLCK_CHUNK\x01\x00";
/// 当前 v2 分块格式魔数：每块通过 AAD 绑定块大小、分块序号与结束标记，防止重排与截断。
pub const CHUNK_MAGIC: &[u8; 12] = b"FLCK_CHUNK\x02\x00";
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB chunk
/// 允许的最大分块明文长度，用于拒绝恶意头部诱导的超大内存分配。
pub const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// 构造 v2 分块 AAD：块大小(4) || 分块序号(8) || 结束标记(1)。
/// 任一字段被篡改（包括重排分块、改写 is_last）都会导致 GCM 认证失败。
fn chunk_aad(chunk_size: u32, chunk_index: u64, is_last: bool) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..4].copy_from_slice(&chunk_size.to_be_bytes());
    aad[4..12].copy_from_slice(&chunk_index.to_be_bytes());
    aad[12] = u8::from(is_last);
    aad
}

/// 从 16 字节头部解析并校验 v2 分块明文大小。
fn parse_v2_chunk_size(header: &[u8; 16]) -> Result<u32, String> {
    let chunk_size = u32::from_be_bytes(
        header[12..16].try_into().expect("头部长度固定为 16"),
    );
    if chunk_size == 0 || chunk_size as usize > MAX_CHUNK_SIZE {
        return Err("分块大小头部无效".into());
    }
    Ok(chunk_size)
}

/// 一个尚未解密的分块原始数据。
struct RawChunk {
    nonce_bytes: [u8; NONCE_LEN],
    cipher_buf: Vec<u8>,
    is_last: bool,
}

/// 读取一个分块的原始字段（不解密，因为 AAD 需要用到 `is_last`）。
/// `max_chunk_len` 限制单块密文长度，防止恶意头部诱导的超大内存分配。
/// 流在没有读到结束标记前提前结束会被判定为截断，而不是静默接受。
fn read_chunk<R: Read>(reader: &mut R, max_chunk_len: usize) -> Result<RawChunk, String> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            "密文流被截断：缺少结束分块".to_string()
        } else {
            format!("读取分块长度失败: {e}")
        }
    })?;
    let chunk_len = u32::from_be_bytes(len_buf) as usize;
    if chunk_len < NONCE_LEN + 16 {
        return Err("分块密文长度无效".into());
    }
    if chunk_len > max_chunk_len {
        return Err("分块密文长度超出上限".into());
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    reader
        .read_exact(&mut nonce_bytes)
        .map_err(|e| format!("读取分块 nonce 失败: {e}"))?;

    let cipher_data_len = chunk_len - NONCE_LEN;
    let mut cipher_buf = vec![0u8; cipher_data_len];
    reader
        .read_exact(&mut cipher_buf)
        .map_err(|e| format!("读取分块密文失败: {e}"))?;

    let mut is_last_buf = [0u8; 1];
    reader
        .read_exact(&mut is_last_buf)
        .map_err(|e| format!("读取分块标记失败: {e}"))?;
    let is_last = match is_last_buf[0] {
        0 => false,
        1 => true,
        _ => return Err("分块结束标记无效".into()),
    };

    Ok(RawChunk {
        nonce_bytes,
        cipher_buf,
        is_last,
    })
}

/// 认证并解密一个分块；`aad` 为空表示兼容 v1 未认证格式。
fn decrypt_chunk(
    cipher: &Aes256Gcm,
    nonce_bytes: &[u8; NONCE_LEN],
    cipher_buf: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: cipher_buf, aad })
        .map_err(|_| "分块解密失败，密钥错误或数据损坏".to_string())
}

/// 读取结束后确认没有多余尾部数据（防止在合法结束块后追加内容）。
fn ensure_stream_end<R: Read>(reader: &mut R) -> Result<(), String> {
    let mut extra = [0u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err("密文尾部存在多余数据".into()),
        Err(e) => Err(format!("读取密文尾部失败: {e}")),
    }
}

/// 超大文件流式分块加密：将 src 文件按 2MB 依次分块加密写入 dst，峰值内存占用稳定在 ~4MB，支持任意 GB 级超大文件。
/// 写出 v2 格式：每块的 AAD 绑定块大小、分块序号与结束标记，任何重排/截断/改写都会认证失败。
/// 失败时删除已写出的半成品文件，避免残留不完整密文。
pub fn encrypt_file_stream(src: &Path, dst: &Path, key: &[u8; KEY_LEN]) -> Result<u64, String> {
    match encrypt_file_stream_inner(src, dst, key) {
        Ok(n) => Ok(n),
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            Err(e)
        }
    }
}

fn encrypt_file_stream_inner(src: &Path, dst: &Path, key: &[u8; KEY_LEN]) -> Result<u64, String> {
    let mut reader = File::open(src).map_err(|e| format!("打开源文件失败: {e}"))?;
    let mut writer = File::create(dst).map_err(|e| format!("创建目标密文文件失败: {e}"))?;

    let chunk_size = DEFAULT_CHUNK_SIZE;
    writer.write_all(CHUNK_MAGIC).map_err(|e| format!("写入头部失败: {e}"))?;
    writer
        .write_all(&(chunk_size as u32).to_be_bytes())
        .map_err(|e| format!("写入分块大小失败: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
    // 多读 1 字节用于判断当前块之后是否还有数据，从而在不依赖文件元数据的前提下判定 is_last。
    let mut buffer = vec![0u8; chunk_size + 1];
    let mut carry: Option<u8> = None;
    let mut chunk_index: u64 = 0;
    let mut total_plain_bytes: u64 = 0;

    loop {
        let mut filled = 0usize;
        if let Some(b) = carry.take() {
            buffer[0] = b;
            filled = 1;
        }
        while filled < buffer.len() {
            let n = reader
                .read(&mut buffer[filled..])
                .map_err(|e| format!("读取源文件失败: {e}"))?;
            if n == 0 {
                break;
            }
            filled += n;
        }

        let is_last = filled <= chunk_size;
        let plain_len = if is_last { filled } else { chunk_size };
        if !is_last {
            carry = Some(buffer[chunk_size]);
        }

        let aad = chunk_aad(chunk_size as u32, chunk_index, is_last);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &buffer[..plain_len],
                    aad: &aad,
                },
            )
            .map_err(|e| format!("分块加密失败: {e}"))?;

        let chunk_len = (NONCE_LEN + ciphertext.len()) as u32;
        writer
            .write_all(&chunk_len.to_be_bytes())
            .map_err(|e| format!("写入块长度失败: {e}"))?;
        writer
            .write_all(&nonce_bytes)
            .map_err(|e| format!("写入 nonce 失败: {e}"))?;
        writer
            .write_all(&ciphertext)
            .map_err(|e| format!("写入密文块失败: {e}"))?;
        writer
            .write_all(&[u8::from(is_last)])
            .map_err(|e| format!("写入结束标记失败: {e}"))?;

        total_plain_bytes += plain_len as u64;
        chunk_index += 1;

        if is_last {
            break;
        }
    }

    writer.flush().map_err(|e| format!("刷新目标文件失败: {e}"))?;
    Ok(total_plain_bytes)
}

/// 解析分块流头部，返回 (是否 v2 格式, 块大小上限)。
fn parse_chunk_header(header: &[u8; 16], file_len: u64) -> Result<(bool, usize), String> {
    let is_v2 = &header[..12] == CHUNK_MAGIC;
    if is_v2 {
        let chunk_size = parse_v2_chunk_size(header)?;
        // 剩余字节至少要能容纳一个分块（长度4 + nonce12 + tag16 + 标记1）。
        if file_len < 16 + 4 + NONCE_LEN as u64 + 16 + 1 {
            return Err("密文流被截断：缺少结束分块".into());
        }
        Ok((true, NONCE_LEN + chunk_size as usize + 16))
    } else {
        // v1 头部未参与认证，块大小不可信，只能按全局上限约束。
        Ok((false, NONCE_LEN + MAX_CHUNK_SIZE + 16))
    }
}

/// 超大文件流式解密：将 cipher_path 解密流式写入 dst。自动兼容 v2/v1 分块流与历史老版单 blob 格式。
/// 失败时删除已写出的半成品文件，避免残留不完整明文。
pub fn decrypt_file_stream(cipher_path: &Path, dst: &Path, key: &[u8; KEY_LEN]) -> Result<u64, String> {
    match decrypt_file_stream_inner(cipher_path, dst, key) {
        Ok(n) => Ok(n),
        Err(e) => {
            let _ = std::fs::remove_file(dst);
            Err(e)
        }
    }
}

fn decrypt_file_stream_inner(cipher_path: &Path, dst: &Path, key: &[u8; KEY_LEN]) -> Result<u64, String> {
    let mut reader = File::open(cipher_path).map_err(|e| format!("打开密文文件失败: {e}"))?;
    let mut writer = File::create(dst).map_err(|e| format!("创建目标解密文件失败: {e}"))?;

    let file_len = reader.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len >= 16 {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header).map_err(|e| format!("读取头部失败: {e}"))?;
        if &header[..12] == CHUNK_MAGIC || &header[..12] == CHUNK_MAGIC_V1 {
            let (is_v2, max_chunk_len) = parse_chunk_header(&header, file_len)?;
            let chunk_size = if is_v2 {
                parse_v2_chunk_size(&header)?
            } else {
                0
            };
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
            let mut total_plain_bytes: u64 = 0;
            let mut chunk_index: u64 = 0;

            loop {
                let chunk = read_chunk(&mut reader, max_chunk_len)?;
                let aad = if is_v2 {
                    Some(chunk_aad(chunk_size, chunk_index, chunk.is_last))
                } else {
                    None
                };
                let plain = decrypt_chunk(
                    &cipher,
                    &chunk.nonce_bytes,
                    &chunk.cipher_buf,
                    aad.as_ref().map(|a| a.as_slice()).unwrap_or(&[]),
                )?;

                total_plain_bytes += plain.len() as u64;
                writer
                    .write_all(&plain)
                    .map_err(|e| format!("写入解密文件失败: {e}"))?;

                chunk_index += 1;
                if chunk.is_last {
                    break;
                }
            }

            ensure_stream_end(&mut reader)?;
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

/// 解密文件到内存字节（适合解密 zip 文件夹）。自动识别 v2/v1 分块流与单 blob 格式。
pub fn decrypt_file_to_bytes(cipher_path: &Path, key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    let mut reader = File::open(cipher_path).map_err(|e| format!("打开密文文件失败: {e}"))?;
    let file_len = reader.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len >= 16 {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header).map_err(|e| format!("读取头部失败: {e}"))?;
        if &header[..12] == CHUNK_MAGIC || &header[..12] == CHUNK_MAGIC_V1 {
            let (is_v2, max_chunk_len) = parse_chunk_header(&header, file_len)?;
            let chunk_size = if is_v2 {
                parse_v2_chunk_size(&header)?
            } else {
                0
            };
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥初始化失败: {e}"))?;
            let mut out = Vec::new();
            let mut chunk_index: u64 = 0;

            loop {
                let chunk = read_chunk(&mut reader, max_chunk_len)?;
                let aad = if is_v2 {
                    Some(chunk_aad(chunk_size, chunk_index, chunk.is_last))
                } else {
                    None
                };
                let plain = decrypt_chunk(
                    &cipher,
                    &chunk.nonce_bytes,
                    &chunk.cipher_buf,
                    aad.as_ref().map(|a| a.as_slice()).unwrap_or(&[]),
                )?;

                out.extend_from_slice(&plain);

                chunk_index += 1;
                if chunk.is_last {
                    break;
                }
            }

            ensure_stream_end(&mut reader)?;
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

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("flck_{}_{}", rand::random::<u64>(), name))
    }

    /// 按历史 v1 格式（无 AAD、明文 is_last）手工写出一个单块密文流。
    fn write_v1_stream(path: &Path, plain: &[u8], key: &[u8; KEY_LEN]) {
        let cipher = Aes256Gcm::new_from_slice(key).expect("密钥初始化应成功");
        let mut out = Vec::new();
        out.extend_from_slice(CHUNK_MAGIC_V1);
        out.extend_from_slice(&(DEFAULT_CHUNK_SIZE as u32).to_be_bytes());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plain)
            .expect("加密应成功");
        out.extend_from_slice(&((NONCE_LEN + ciphertext.len()) as u32).to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out.push(1);
        std::fs::write(path, out).expect("写入 v1 密文应成功");
    }

    #[test]
    fn test_stream_v1_compatible_read() {
        let key = [7u8; KEY_LEN];
        let plain = b"legacy v1 chunked payload".to_vec();
        let enc = temp_path("v1.enc");
        write_v1_stream(&enc, &plain, &key);

        let dec = temp_path("v1.dec");
        let n = decrypt_file_stream(&enc, &dec, &key).expect("v1 密文应可解密");
        assert_eq!(n, plain.len() as u64);
        assert_eq!(std::fs::read(&dec).unwrap(), plain);
        assert_eq!(decrypt_file_to_bytes(&enc, &key).unwrap(), plain);

        let _ = std::fs::remove_file(&enc);
        let _ = std::fs::remove_file(&dec);
    }

    #[test]
    fn test_stream_roundtrip_cross_chunks() {
        let key = [9u8; KEY_LEN];
        // 恰好两块整块 + 一块不完整，覆盖多分块与结束判定
        let plain = vec![0x5Au8; DEFAULT_CHUNK_SIZE * 2 + 12345];
        let src = temp_path("src.bin");
        let enc = temp_path("src.enc");
        let dec = temp_path("src.dec");
        std::fs::write(&src, &plain).unwrap();

        let n = encrypt_file_stream(&src, &enc, &key).unwrap();
        assert_eq!(n, plain.len() as u64);
        assert_eq!(&std::fs::read(&enc).unwrap()[..12], CHUNK_MAGIC);

        let n = decrypt_file_stream(&enc, &dec, &key).unwrap();
        assert_eq!(n, plain.len() as u64);
        assert_eq!(std::fs::read(&dec).unwrap(), plain);
        assert_eq!(decrypt_file_to_bytes(&enc, &key).unwrap(), plain);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
        let _ = std::fs::remove_file(&dec);
    }

    #[test]
    fn test_stream_rejects_truncation_and_removes_partial() {
        let key = [3u8; KEY_LEN];
        let plain = vec![0x11u8; DEFAULT_CHUNK_SIZE + 4096];
        let src = temp_path("trunc_src.bin");
        let enc = temp_path("trunc.enc");
        std::fs::write(&src, &plain).unwrap();
        encrypt_file_stream(&src, &enc, &key).unwrap();

        let mut bytes = std::fs::read(&enc).unwrap();
        bytes.truncate(bytes.len() - 10);
        std::fs::write(&enc, &bytes).unwrap();

        let dec = temp_path("trunc.dec");
        assert!(decrypt_file_stream(&enc, &dec, &key).is_err());
        assert!(!dec.exists(), "失败后应删除半成品明文");
        assert!(decrypt_file_to_bytes(&enc, &key).is_err());

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
    }

    #[test]
    fn test_stream_rejects_reordered_and_trailing_data() {
        let key = [5u8; KEY_LEN];
        let plain = vec![0x22u8; DEFAULT_CHUNK_SIZE * 2 + 1];
        let src = temp_path("reorder_src.bin");
        let enc = temp_path("reorder.enc");
        std::fs::write(&src, &plain).unwrap();
        encrypt_file_stream(&src, &enc, &key).unwrap();
        let bytes = std::fs::read(&enc).unwrap();

        // 交换前两个完整分块（长度相同），AAD 中的序号绑定应使解密失败
        let block = 4 + NONCE_LEN + DEFAULT_CHUNK_SIZE + 16 + 1;
        let mut swapped = bytes.clone();
        let first = 16..16 + block;
        let second = 16 + block..16 + block * 2;
        swapped[first.clone()].copy_from_slice(&bytes[second.clone()]);
        swapped[second].copy_from_slice(&bytes[first]);
        let enc_swapped = temp_path("swapped.enc");
        std::fs::write(&enc_swapped, &swapped).unwrap();
        assert!(decrypt_file_to_bytes(&enc_swapped, &key).is_err());

        // 合法结束块后追加字节应被拒绝
        let mut trailing = bytes.clone();
        trailing.push(0);
        let enc_trailing = temp_path("trailing.enc");
        std::fs::write(&enc_trailing, &trailing).unwrap();
        assert!(decrypt_file_to_bytes(&enc_trailing, &key).is_err());

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
        let _ = std::fs::remove_file(&enc_swapped);
        let _ = std::fs::remove_file(&enc_trailing);
    }
}
