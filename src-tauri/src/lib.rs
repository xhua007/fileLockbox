pub mod crypto;
pub mod fs;
pub mod keychain;
pub mod models;
pub mod vault;

use std::sync::Mutex;
use std::time::Duration;
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::models::{CreateVaultResult, VaultEntry, VaultInfo};
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
    state: State<VaultState>,
) -> Result<String, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.set_password(&password, remember)
}

#[tauri::command]
fn unlock(
    password: String,
    remember: bool,
    state: State<VaultState>,
) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.unlock(&password, remember)
}

#[tauri::command]
fn lock(state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.lock();
    Ok(())
}

/// 用户活动心跳：前端在鼠标/键盘活动时调用，供 Rust 侧权威自动锁判断空闲。
#[tauri::command]
fn touch_activity(state: State<VaultState>) {
    if let Ok(v) = state.lock() {
        v.touch_activity();
    }
}

#[tauri::command]
fn is_unlocked(state: State<VaultState>) -> bool {
    state.lock().map(|v| v.is_unlocked).unwrap_or(false)
}

#[tauri::command]
fn has_saved_password(state: State<VaultState>) -> bool {
    state.lock().map(|v| v.has_saved_password()).unwrap_or(false)
}

/// 使用系统钥匙串中已记住的密码解锁（非生物识别）。
#[tauri::command]
fn unlock_with_keychain(state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.unlock_with_keychain()
}

#[tauri::command]
fn list_entries(state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.list_entries()
}

#[tauri::command]
fn rename_entry(
    id: String,
    new_name: String,
    state: State<VaultState>,
) -> Result<VaultEntry, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.rename_entry(&id, &new_name)
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
fn forget_saved_password(state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.forget_saved_password()
}

#[tauri::command]
fn get_vault_size(state: State<VaultState>) -> Result<u64, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.get_vault_size()
}

// 多保险箱命令
#[tauri::command]
fn get_current_vault(state: State<VaultState>) -> Result<VaultInfo, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    Ok(v.get_current_vault_info())
}

#[tauri::command]
fn list_vaults(state: State<VaultState>) -> Result<Vec<VaultInfo>, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.list_vaults()
}

#[tauri::command]
fn switch_vault(vault_id: String, state: State<VaultState>) -> Result<VaultInfo, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.switch_vault(&vault_id)
}

#[tauri::command]
fn create_vault(
    name: String,
    password: String,
    remember: bool,
    state: State<VaultState>,
) -> Result<CreateVaultResult, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.create_vault(&name, &password, remember)
}

#[tauri::command]
fn rename_vault(
    vault_id: String,
    new_name: String,
    state: State<VaultState>,
) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.rename_vault(&vault_id, &new_name)
}

#[tauri::command]
fn delete_vault(vault_id: String, state: State<VaultState>) -> Result<VaultInfo, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.delete_vault(&vault_id)
}

// ---------- 原生文件对话框（仅由 Rust 侧调用，前端无 dialog 权限）----------

#[tauri::command]
async fn pick_paths(
    app: tauri::AppHandle,
    directory: bool,
    multiple: bool,
) -> Result<Vec<String>, String> {
    let dialog = app.dialog().file().set_title(if directory {
        "选择文件夹"
    } else {
        "选择文件"
    });
    let picked: Vec<tauri_plugin_dialog::FilePath> = if directory {
        if multiple {
            dialog.blocking_pick_folders().unwrap_or_default()
        } else {
            dialog.blocking_pick_folder().into_iter().collect()
        }
    } else if multiple {
        dialog.blocking_pick_files().unwrap_or_default()
    } else {
        dialog.blocking_pick_file().into_iter().collect()
    };
    Ok(picked
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
        .collect())
}

#[tauri::command]
async fn pick_save_path(
    app: tauri::AppHandle,
    default_name: String,
) -> Result<Option<String>, String> {
    let picked = app
        .dialog()
        .file()
        .set_title("导出文件")
        .set_file_name(default_name)
        .blocking_save_file();
    Ok(picked
        .and_then(|p| p.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned()))
}

/// 单实例保护：在应用数据目录下绑定 Unix socket。
/// 返回 None 表示已有实例在运行；返回 Some 时监听器需一直持有到进程退出。
#[cfg(unix)]
fn acquire_single_instance() -> Option<std::os::unix::net::UnixListener> {
    use std::os::unix::net::{UnixListener, UnixStream};
    let path = vault::app_data_dir().join("instance.sock");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // 先探测是否已有活着的实例；socket 文件残留（上次崩溃）时清理后重绑
    if UnixStream::connect(&path).is_ok() {
        return None;
    }
    let _ = std::fs::remove_file(&path);
    UnixListener::bind(&path).ok()
}

/// Tauri 应用构建入口。main.rs 通过 `filelocker_lib::run()` 调用。
pub fn run() {
    #[cfg(unix)]
    let _instance_guard = match acquire_single_instance() {
        Some(listener) => listener,
        None => {
            eprintln!("已有 FileLocker 实例在运行，本次启动退出");
            return;
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(VaultManager::new()))
        .setup(|app| {
            // Rust 侧权威自动锁：不依赖前端计时器，前端被绕过也无法阻止空闲锁定。
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                let mut was_unlocked = false;
                loop {
                    std::thread::sleep(Duration::from_secs(10));
                    let unlocked = {
                        let state = handle.state::<VaultState>();
                        let result = match state.lock() {
                            Ok(mut v) => {
                                v.enforce_auto_lock();
                                v.is_unlocked
                            }
                            Err(_) => false,
                        };
                        result
                    };
                    if was_unlocked && !unlocked {
                        let _ = handle.emit("vault-auto-locked", ());
                    }
                    was_unlocked = unlocked;
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_paths,
            pick_save_path,
            vault_exists,
            setup_password,
            unlock,
            lock,
            touch_activity,
            is_unlocked,
            has_saved_password,
            unlock_with_keychain,
            list_entries,
            rename_entry,
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
            forget_saved_password,
            get_vault_size,
            get_current_vault,
            list_vaults,
            switch_vault,
            create_vault,
            rename_vault,
            delete_vault,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed = event {
                if let Some(state) = window.try_state::<Mutex<VaultManager>>() {
                    if let Ok(mut v) = state.lock() {
                        v.lock();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
