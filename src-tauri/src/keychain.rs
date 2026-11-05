use std::sync::atomic::{AtomicBool, Ordering};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use keyring::Entry;
use rand::RngCore;

static KEYCHAIN_DENIED: AtomicBool = AtomicBool::new(false);

/// 检查当前应用运行周期中用户是否已拒绝过钥匙串授权
pub fn is_keychain_denied() -> bool {
    KEYCHAIN_DENIED.load(Ordering::Relaxed)
}

/// 标记当前会话已拒绝钥匙串授权，避免同一周期内重复弹出系统授权弹窗
pub fn mark_keychain_denied() {
    KEYCHAIN_DENIED.store(true, Ordering::Relaxed);
}

/// 重置拒绝状态（例如用户主动点击“使用已记住的密码解锁”时重新尝试）
pub fn reset_keychain_denied() {
    KEYCHAIN_DENIED.store(false, Ordering::Relaxed);
}

const DEFAULT_SERVICE: &str = "com.filelocker.vault";
const ACCOUNT: &str = "password";
const GENERATION_ACCOUNT: &str = "index-generation";
const METADATA_ACCOUNT: &str = "metadata-key";
const DEVICE_KEY_ACCOUNT: &str = "device-key";
const LOCKOUT_ACCOUNT: &str = "lockout-anchor";
const GUARD_HMAC_ACCOUNT: &str = "guard-hmac-key";

fn service_for_vault(vault_id: &str) -> String {
    if vault_id == "default" || vault_id.is_empty() {
        DEFAULT_SERVICE.to_string()
    } else {
        format!("{DEFAULT_SERVICE}.{vault_id}")
    }
}

fn entry(vault_id: &str) -> Result<Entry, String> {
    let service = service_for_vault(vault_id);
    Entry::new(&service, ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

/// 将主密码写入系统钥匙串。
///
/// 说明：这里只是「操作系统凭据存储」，**不包含生物识别门控**。
/// 是否能免密读取取决于系统对钥匙串访问控制的设置，应用本身不再做指纹/Face ID 校验。
pub fn save_password(vault_id: &str, pwd: &str) -> Result<(), String> {
    reset_keychain_denied();
    let en = entry(vault_id)?;
    let _ = en.delete_password();
    en.set_password(pwd)
        .map_err(|e| format!("保存密码到钥匙串失败: {e}"))
}

pub fn load_password(vault_id: &str) -> Result<String, String> {
    if is_keychain_denied() {
        return Err("钥匙串访问已被用户在此次运行中拒绝".into());
    }
    let en = entry(vault_id)?;
    en.get_password().map_err(|e| {
        if !matches!(e, keyring::Error::NoEntry) {
            mark_keychain_denied();
        }
        format!("从钥匙串读取密码失败: {e}")
    })
}

pub fn delete_password(vault_id: &str) -> Result<(), String> {
    if let Ok(en) = entry(vault_id) {
        let _ = en.delete_password();
    }
    Ok(())
}

pub fn has_saved_password(vault_id: &str) -> bool {
    if is_keychain_denied() {
        return false;
    }
    // 优先检测新版设备密钥
    if has_device_key(vault_id) {
        return true;
    }
    match entry(vault_id) {
        Ok(en) => match en.get_password() {
            Ok(_) => true,
            Err(keyring::Error::NoEntry) => false,
            Err(_) => {
                // 用户点击拒绝或授权失败，标记当前会话已拒绝，后续流程不再重复弹窗
                mark_keychain_denied();
                false
            }
        },
        Err(_) => false,
    }
}

fn device_key_entry(vault_id: &str) -> Result<Entry, String> {
    let service = service_for_vault(vault_id);
    Entry::new(&service, DEVICE_KEY_ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

/// 保存设备密钥到系统钥匙串（32 字节高熵随机数，绝不存用户主密码明文）。
pub fn save_device_key(vault_id: &str, device_key: &[u8; 32]) -> Result<(), String> {
    reset_keychain_denied();
    let en = device_key_entry(vault_id)?;
    let _ = en.delete_password();
    en.set_password(&STANDARD.encode(device_key))
        .map_err(|e| format!("保存设备密钥到钥匙串失败: {e}"))
}

pub fn load_device_key(vault_id: &str) -> Result<[u8; 32], String> {
    if is_keychain_denied() {
        return Err("钥匙串访问已被用户在此次运行中拒绝".into());
    }
    let en = device_key_entry(vault_id)?;
    let raw = en.get_password().map_err(|e| {
        if !matches!(e, keyring::Error::NoEntry) {
            mark_keychain_denied();
        }
        format!("从钥匙串读取设备密钥失败: {e}")
    })?;
    let bytes = STANDARD
        .decode(raw.trim())
        .map_err(|e| format!("设备密钥格式无效: {e}"))?;
    if bytes.len() != 32 {
        return Err("设备密钥长度无效".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn delete_device_key(vault_id: &str) -> Result<(), String> {
    if let Ok(en) = device_key_entry(vault_id) {
        let _ = en.delete_password();
    }
    Ok(())
}

pub fn has_device_key(vault_id: &str) -> bool {
    if is_keychain_denied() {
        return false;
    }
    match device_key_entry(vault_id) {
        Ok(en) => match en.get_password() {
            Ok(_) => true,
            Err(keyring::Error::NoEntry) => false,
            Err(_) => {
                mark_keychain_denied();
                false
            }
        },
        Err(_) => false,
    }
}

fn generation_entry(vault_id: &str) -> Result<Entry, String> {
    let service = service_for_vault(vault_id);
    Entry::new(&service, GENERATION_ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

/// 读取索引代次锚点。锚点存放在应用数据目录之外，用于识别「旧索引被替换回来」。
pub fn load_index_generation(vault_id: &str) -> Result<u64, String> {
    if is_keychain_denied() {
        return Err("钥匙串访问已被用户拒绝".into());
    }
    let en = generation_entry(vault_id)?;
    let raw = en.get_password().map_err(|e| {
        if !matches!(e, keyring::Error::NoEntry) {
            mark_keychain_denied();
        }
        format!("读取索引代次失败: {e}")
    })?;
    raw.parse::<u64>()
        .map_err(|e| format!("索引代次格式无效: {e}"))
}

pub fn store_index_generation(vault_id: &str, generation: u64) -> Result<(), String> {
    if is_keychain_denied() {
        return Ok(()); // 钥匙串已拒绝时静默跳过锚点写入
    }
    let en = generation_entry(vault_id)?;
    en.set_password(&generation.to_string())
        .map_err(|e| format!("保存索引代次失败: {e}"))
}

pub fn delete_index_generation(vault_id: &str) -> Result<(), String> {
    if let Ok(en) = generation_entry(vault_id) {
        let _ = en.delete_password();
    }
    Ok(())
}

fn metadata_entry() -> Result<Entry, String> {
    Entry::new(DEFAULT_SERVICE, METADATA_ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

/// 读取或创建用于加密本地元数据（vaults.json / config.json）的 32 字节密钥。
///
/// 首次调用生成随机密钥并以 base64 存入系统钥匙串。钥匙串不可用时返回 `Err`，
/// 调用方应回退为明文存储，保证应用在无 Secret Service 的环境仍能启动。
pub fn load_or_create_metadata_key() -> Result<[u8; 32], String> {
    if is_keychain_denied() {
        return Err("钥匙串访问已被用户拒绝".into());
    }
    let en = metadata_entry()?;
    match en.get_password() {
        Ok(raw) => {
            let bytes = STANDARD
                .decode(raw.trim())
                .map_err(|e| format!("元数据密钥格式无效: {e}"))?;
            if bytes.len() != 32 {
                return Err("元数据密钥长度无效".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            en.set_password(&STANDARD.encode(key)).map_err(|e| {
                mark_keychain_denied();
                format!("保存元数据密钥失败: {e}")
            })?;
            Ok(key)
        }
        Err(e) => {
            mark_keychain_denied();
            Err(format!("读取元数据密钥失败: {e}"))
        }
    }
}

fn lockout_entry(vault_id: &str) -> Result<Entry, String> {
    let service = service_for_vault(vault_id);
    Entry::new(&service, LOCKOUT_ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

/// 将防爆破锁定时间戳存入钥匙串锚点（位于数据目录外部，防本地删除 security.json 绕过锁定）。
pub fn store_lockout_anchor(vault_id: &str, lockout_until: i64) -> Result<(), String> {
    if is_keychain_denied() {
        return Ok(());
    }
    let en = lockout_entry(vault_id)?;
    en.set_password(&lockout_until.to_string())
        .map_err(|e| format!("保存锁定锚点失败: {e}"))
}

pub fn load_lockout_anchor(vault_id: &str) -> Option<i64> {
    if is_keychain_denied() {
        return None;
    }
    let en = lockout_entry(vault_id).ok()?;
    let raw = en.get_password().ok()?;
    raw.trim().parse::<i64>().ok()
}

pub fn clear_lockout_anchor(vault_id: &str) {
    if let Ok(en) = lockout_entry(vault_id) {
        let _ = en.delete_password();
    }
}

fn guard_hmac_entry() -> Result<Entry, String> {
    Entry::new(DEFAULT_SERVICE, GUARD_HMAC_ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

/// 读取或生成用于防篡改 security.json 的 HMAC 密钥。
pub fn load_or_create_guard_hmac_key() -> Result<[u8; 32], String> {
    if is_keychain_denied() {
        return Err("钥匙串访问已被用户拒绝".into());
    }
    let en = guard_hmac_entry()?;
    match en.get_password() {
        Ok(raw) => {
            let bytes = STANDARD
                .decode(raw.trim())
                .map_err(|e| format!("HMAC 密钥格式无效: {e}"))?;
            if bytes.len() != 32 {
                return Err("HMAC 密钥长度无效".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            en.set_password(&STANDARD.encode(key)).map_err(|e| {
                mark_keychain_denied();
                format!("保存 HMAC 密钥失败: {e}")
            })?;
            Ok(key)
        }
        Err(e) => {
            mark_keychain_denied();
            Err(format!("读取 HMAC 密钥失败: {e}"))
        }
    }
}
