use keyring::Entry;

const DEFAULT_SERVICE: &str = "com.filelocker.vault";
const ACCOUNT: &str = "password";

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

pub fn save_password(vault_id: &str, pwd: &str, _use_biometry: bool) -> Result<(), String> {
    let en = entry(vault_id)?;
    let _ = en.delete_password();
    en.set_password(pwd)
        .map_err(|e| format!("保存密码到钥匙串失败: {e}"))
}

pub fn load_password(vault_id: &str) -> Result<String, String> {
    let en = entry(vault_id)?;
    en.get_password()
        .map_err(|e| format!("从钥匙串读取密码失败: {e}"))
}

pub fn delete_password(vault_id: &str) -> Result<(), String> {
    if let Ok(en) = entry(vault_id) {
        let _ = en.delete_password();
    }
    Ok(())
}

pub fn has_saved_password(vault_id: &str) -> bool {
    match entry(vault_id) {
        Ok(en) => en.get_password().is_ok(),
        Err(_) => false,
    }
}
