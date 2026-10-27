use keyring::Entry;

const SERVICE: &str = "com.filelocker.vault";
const ACCOUNT: &str = "password";

fn entry() -> Result<Entry, String> {
    Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("钥匙串访问失败: {e}"))
}

pub fn save_password(pwd: &str, _use_biometry: bool) -> Result<(), String> {
    let en = entry()?;
    let _ = en.delete_password();
    en.set_password(pwd)
        .map_err(|e| format!("保存密码到钥匙串失败: {e}"))
}

pub fn load_password() -> Result<String, String> {
    let en = entry()?;
    en.get_password()
        .map_err(|e| format!("从钥匙串读取密码失败: {e}"))
}

pub fn delete_password() -> Result<(), String> {
    if let Ok(en) = entry() {
        let _ = en.delete_password();
    }
    Ok(())
}

pub fn has_saved_password() -> bool {
    match entry() {
        Ok(en) => en.get_password().is_ok(),
        Err(_) => false,
    }
}
