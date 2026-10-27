pub mod crypto;
pub mod fs;
pub mod keychain;
pub mod models;
pub mod vault;

use std::sync::Mutex;
use tauri::State;

use crate::models::VaultEntry;
use crate::vault::VaultManager;

type VaultState = Mutex<VaultManager>;

// ---------- Tauri Commands ----------

#[tauri::command]
fn vault_exists(state: State<VaultState>) -> bool {
    state.lock().map(|v| v.vault_exists()).unwrap_or(false)
}

#[tauri::command]
fn setup_password(
    password: String,
    remember: bool,
    use_biometry: bool,
    state: State<VaultState>,
) -> Result<String, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.set_password(&password, remember, use_biometry)
}

#[tauri::command]
fn unlock(
    password: String,
    remember: bool,
    use_biometry: bool,
    state: State<VaultState>,
) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.unlock(&password, remember, use_biometry)
}

#[tauri::command]
fn lock(state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.lock();
    Ok(())
}

#[tauri::command]
fn is_unlocked(state: State<VaultState>) -> bool {
    state.lock().map(|v| v.is_unlocked).unwrap_or(false)
}

#[tauri::command]
fn has_saved_password(state: State<VaultState>) -> bool {
    state.lock().map(|v| v.has_saved_password()).unwrap_or(false)
}

#[tauri::command]
fn biometric_unlock(state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.biometric_unlock()
}

#[tauri::command]
fn list_entries(state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.list_entries()
}

#[tauri::command]
fn add_files(paths: Vec<String>, state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.add_files(paths)
}

#[tauri::command]
fn open_entry(id: String, state: State<VaultState>) -> Result<(), String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.open_entry(&id)
}

#[tauri::command]
fn export_entry(id: String, target_path: String, state: State<VaultState>) -> Result<(), String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.export_entry(&id, &target_path)
}

#[tauri::command]
fn export_entries_to_dir(
    ids: Vec<String>,
    dir: String,
    state: State<VaultState>,
) -> Result<(), String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.export_entries_to_dir(&ids, &dir)
}

#[tauri::command]
fn restore_entry(id: String, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.restore_entry(&id)
}

#[tauri::command]
fn delete_entry(id: String, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.delete_entry(&id)
}

#[tauri::command]
fn delete_entries(ids: Vec<String>, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.delete_entries(&ids)
}

#[tauri::command]
fn change_password(old: String, new: String, state: State<VaultState>) -> Result<String, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.change_password(&old, &new)
}

#[tauri::command]
fn recover_password(
    recovery_code: String,
    new_password: String,
    state: State<VaultState>,
) -> Result<String, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.recover_password(&recovery_code, &new_password)
}

#[tauri::command]
fn temporary_export_url(id: String, state: State<VaultState>) -> Result<String, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.temporary_export_url(&id)
}

#[tauri::command]
fn clear_temp(state: State<VaultState>) -> Result<(), String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.clear_temp()
}

#[tauri::command]
fn get_auto_lock_minutes(state: State<VaultState>) -> u64 {
    state
        .lock()
        .map(|v| v.get_auto_lock_minutes())
        .unwrap_or(5)
}

#[tauri::command]
fn set_auto_lock_minutes(mins: u64, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.set_auto_lock_minutes(mins);
    Ok(())
}

#[tauri::command]
fn reset_vault(state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.reset_vault()
}

#[tauri::command]
fn get_vault_size(state: State<VaultState>) -> Result<u64, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.get_vault_size()
}

/// Tauri 应用构建入口。main.rs 通过 `filelocker_lib::run()` 调用。
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init())
        .manage(Mutex::new(VaultManager::new()))
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            setup_password,
            unlock,
            lock,
            is_unlocked,
            has_saved_password,
            biometric_unlock,
            list_entries,
            add_files,
            open_entry,
            export_entry,
            export_entries_to_dir,
            restore_entry,
            delete_entry,
            delete_entries,
            change_password,
            recover_password,
            temporary_export_url,
            clear_temp,
            get_auto_lock_minutes,
            set_auto_lock_minutes,
            reset_vault,
            get_vault_size,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
