pub mod biometrics;
pub mod crypto;
pub mod fs;
pub mod keychain;
pub mod models;
pub mod vault;

use std::sync::Mutex;
use std::time::Duration;
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::models::{ActiveEditSession, CreateVaultResult, VaultEntry, VaultInfo};
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

#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
pub fn apply_privacy_screen_protection(
    window: &tauri::WebviewWindow,
    enabled: bool,
) -> Result<(), String> {
    use objc::{msg_send, sel, sel_impl};
    let ns_window_ptr = window
        .ns_window()
        .map_err(|e| format!("获取原生窗口指针失败: {e}"))?;
    // NSWindowSharingNone = 0, NSWindowSharingReadOnly = 1
    let sharing_type: usize = if enabled { 0 } else { 1 };
    unsafe {
        let () =
            msg_send![ns_window_ptr as *mut objc::runtime::Object, setSharingType: sharing_type];
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn apply_privacy_screen_protection(
    window: &tauri::WebviewWindow,
    enabled: bool,
) -> Result<(), String> {
    use std::ffi::c_void;
    if let Ok(hwnd) = window.hwnd() {
        // WDA_NONE = 0x00000000, WDA_EXCLUDEFROMCAPTURE = 0x00000011
        let affinity: u32 = if enabled { 0x00000011 } else { 0x00000000 };
        #[link(name = "user32")]
        extern "system" {
            fn SetWindowDisplayAffinity(hWnd: *mut c_void, dwAffinity: u32) -> i32;
        }
        unsafe {
            let _ = SetWindowDisplayAffinity(hwnd.0 as *mut c_void, affinity);
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn apply_privacy_screen_protection(
    _window: &tauri::WebviewWindow,
    _enabled: bool,
) -> Result<(), String> {
    Ok(())
}

#[tauri::command]
fn get_privacy_screen_protection(state: State<VaultState>) -> bool {
    state
        .lock()
        .map(|v| v.get_privacy_screen_protection())
        .unwrap_or(false)
}

#[tauri::command]
fn set_privacy_screen_protection(
    window: tauri::WebviewWindow,
    enabled: bool,
    state: State<VaultState>,
) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.set_privacy_screen_protection(enabled)?;
    apply_privacy_screen_protection(&window, enabled)?;
    Ok(())
}

#[tauri::command]
fn get_shred_source(state: State<VaultState>) -> bool {
    state.lock().map(|v| v.get_shred_source()).unwrap_or(true)
}

#[tauri::command]
fn set_shred_source(enabled: bool, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.set_shred_source(enabled)
}

#[tauri::command]
fn open_entry_for_edit(id: String, state: State<VaultState>) -> Result<String, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.open_entry_for_edit(&id)
}

#[tauri::command]
fn finish_entry_edit(id: String, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.finish_entry_edit(&id)
}

#[tauri::command]
fn list_active_edits(state: State<VaultState>) -> Result<Vec<ActiveEditSession>, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    Ok(v.list_active_edits())
}

#[tauri::command]
fn is_biometrics_available(state: State<VaultState>) -> bool {
    state
        .lock()
        .map(|v| v.is_biometrics_available())
        .unwrap_or(false)
}

#[tauri::command]
fn get_biometrics_enabled(state: State<VaultState>) -> bool {
    state
        .lock()
        .map(|v| v.get_biometrics_enabled())
        .unwrap_or(false)
}

#[tauri::command]
fn set_biometrics_enabled(enabled: bool, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.set_biometrics_enabled(enabled)
}

#[tauri::command]
fn unlock_with_biometrics(state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.unlock_with_biometrics()
}

/// 老板键 / 防窥急救锁：立即清空内存主密钥回归锁定态，并隐藏主窗口
#[tauri::command]
fn panic_lock(app: tauri::AppHandle, state: State<VaultState>) -> Result<(), String> {
    {
        let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
        v.lock();
    }
    let _ = app.emit("vault-auto-locked", ());
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    Ok(())
}

#[tauri::command]
fn has_saved_password(state: State<VaultState>) -> bool {
    state
        .lock()
        .map(|v| v.has_saved_password())
        .unwrap_or(false)
}

/// 使用系统钥匙串中已记住的密码解锁（非生物识别）。
#[tauri::command]
fn unlock_with_keychain(state: State<VaultState>) -> Result<Vec<VaultEntry>, String> {
    keychain::reset_keychain_denied();
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
fn add_files(
    paths: Vec<String>,
    app: tauri::AppHandle,
    state: State<VaultState>,
) -> Result<Vec<VaultEntry>, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    let total_files = paths.len();
    let app_handle = app.clone();
    let res = v.add_files_with_progress(paths, move |prog| {
        let _ = app_handle.emit("vault-operation-progress", prog);
    });
    let _ = app.emit(
        "vault-operation-progress",
        crate::models::OperationProgress {
            stage: "encrypt".to_string(),
            current_file: total_files,
            total_files,
            file_name: "".to_string(),
            processed_bytes: 0,
            total_bytes: 0,
            percent: 100.0,
            is_finished: true,
        },
    );
    res
}

#[tauri::command]
fn read_entry_preview(
    id: String,
    state: State<VaultState>,
) -> Result<models::EntryPreviewData, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.read_entry_preview(&id)
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
    app: tauri::AppHandle,
    state: State<VaultState>,
) -> Result<(), String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    let total_files = ids.len();
    let app_handle = app.clone();
    let res = v.export_entries_to_dir_with_progress(&ids, &dir, move |prog| {
        let _ = app_handle.emit("vault-operation-progress", prog);
    });
    let _ = app.emit(
        "vault-operation-progress",
        crate::models::OperationProgress {
            stage: "export".to_string(),
            current_file: total_files,
            total_files,
            file_name: "".to_string(),
            processed_bytes: 0,
            total_bytes: 0,
            percent: 100.0,
            is_finished: true,
        },
    );
    res
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
fn move_to_trash(ids: Vec<String>, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.move_to_trash(&ids)
}

#[tauri::command]
fn restore_from_trash(ids: Vec<String>, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.restore_from_trash(&ids)
}

#[tauri::command]
fn permanently_delete_entries(ids: Vec<String>, state: State<VaultState>) -> Result<(), String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.permanently_delete_entries(&ids)
}

#[tauri::command]
fn empty_trash(state: State<VaultState>) -> Result<usize, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.empty_trash()
}

#[tauri::command]
fn save_note(
    id: Option<String>,
    title: String,
    content: String,
    state: State<VaultState>,
) -> Result<models::VaultEntry, String> {
    let mut v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.save_note(id, &title, &content)
}

#[tauri::command]
fn read_note(id: String, state: State<VaultState>) -> Result<String, String> {
    let v = state.lock().map_err(|e| format!("状态锁已被污染: {e}"))?;
    v.read_note(&id)
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
    state.lock().map(|v| v.get_auto_lock_minutes()).unwrap_or(5)
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

static COPY_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 复制敏感文本（如恢复码）并配置剪贴板安全防护：
/// - macOS 上设置 NSPasteboard ConcealedType & AutoGeneratedType 防止第三方剪贴板记录软件捕获；
/// - 后台启动倒计时异步任务，在 timeout_secs（默认 30s）后自动清空剪贴板。
#[tauri::command]
fn copy_sensitive_text(text: String, timeout_secs: Option<u64>) -> Result<(), String> {
    let timeout = timeout_secs.unwrap_or(30);
    let seq = COPY_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"ObjC.import("AppKit");
var pb = $.NSPasteboard.generalPasteboard;
pb.clearContents;
pb.setStringForType($({}), $("public.utf8-plain-text"));
pb.setStringForType($(""), $("org.nspasteboard.ConcealedType"));
pb.setStringForType($(""), $("org.nspasteboard.AutoGeneratedType"));
"#,
            serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".to_string())
        );
        let mut child = std::process::Command::new("osascript")
            .arg("-l")
            .arg("JavaScript")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("写入系统剪贴板失败: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(script.as_bytes());
        }
        let _ = child.wait();
    }

    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "windows")]
        {
            windows_clipboard::set_sensitive_text(&text)?;
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if let Ok(mut child) = std::process::Command::new("wl-copy")
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
            } else if let Ok(mut child) = std::process::Command::new("xclip")
                .args(["-selection", "clipboard"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                if let Some(mut stdin) = child.stdin.take() {
                    use std::io::Write;
                    let _ = stdin.write_all(text.as_bytes());
                }
                let _ = child.wait();
            }
        }
    }

    // 后台定时清空剪贴板
    let expected_text = text;
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(timeout)).await;
        if COPY_SEQUENCE.load(std::sync::atomic::Ordering::SeqCst) == seq {
            #[cfg(target_os = "macos")]
            {
                if let Ok(output) = std::process::Command::new("pbpaste").output() {
                    if let Ok(curr) = String::from_utf8(output.stdout) {
                        if curr.trim() == expected_text.trim() {
                            let _ = std::process::Command::new("pbcopy")
                                .stdin(std::process::Stdio::null())
                                .status();
                        }
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                windows_clipboard::clear_clipboard_if_matches(&expected_text);
            }
        }
    });

    Ok(())
}

#[cfg(target_os = "windows")]
mod windows_clipboard {
    use std::ffi::c_void;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hWnd: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn RegisterClipboardFormatW(lpszFormat: *const u16) -> u32;
        fn SetClipboardData(uFormat: u32, hMem: *mut c_void) -> *mut c_void;
        fn GetClipboardData(uFormat: u32) -> *mut c_void;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> *mut c_void;
        fn GlobalLock(hMem: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(hMem: *mut c_void) -> i32;
        fn GlobalFree(hMem: *mut c_void) -> *mut c_void;
    }

    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// 将敏感文本写入剪贴板，同时附加 Windows 剪贴板历史记录与云同步排除标志。
    pub fn set_sensitive_text(text: &str) -> Result<(), String> {
        unsafe {
            if OpenClipboard(std::ptr::null_mut()) == 0 {
                return Err("无法打开 Windows 剪贴板".into());
            }
            EmptyClipboard();

            let wide = to_wide(text);
            let bytes_len = wide.len() * 2;
            let h_mem = GlobalAlloc(GMEM_MOVEABLE, bytes_len);
            if !h_mem.is_null() {
                let ptr = GlobalLock(h_mem) as *mut u16;
                if !ptr.is_null() {
                    std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                    GlobalUnlock(h_mem);
                    SetClipboardData(CF_UNICODETEXT, h_mem);
                } else {
                    GlobalFree(h_mem);
                }
            }

            // 注册格式并写入 DWORD 0，彻底阻止 Win+V 剪贴板历史记录与微软云剪贴板抓取
            let formats = [
                "Clipboard Viewer Ignore",
                "ExcludeClipboardContentFromMonitorProcessing",
                "CanIncludeInClipboardHistory",
                "CanUploadToCloudClipboard",
            ];
            for fmt_name in formats {
                let fmt_wide = to_wide(fmt_name);
                let format_id = RegisterClipboardFormatW(fmt_wide.as_ptr());
                if format_id != 0 {
                    let dword_mem = GlobalAlloc(GMEM_MOVEABLE, 4);
                    if !dword_mem.is_null() {
                        let ptr = GlobalLock(dword_mem) as *mut u32;
                        if !ptr.is_null() {
                            *ptr = 0;
                            GlobalUnlock(dword_mem);
                            SetClipboardData(format_id, dword_mem);
                        } else {
                            GlobalFree(dword_mem);
                        }
                    }
                }
            }

            CloseClipboard();
            Ok(())
        }
    }

    /// 若当前剪贴板内容与预期敏感文本一致，通过 Win32 API 彻底清空，无需唤起 cmd/clip 控制台黑窗
    pub fn clear_clipboard_if_matches(expected: &str) {
        unsafe {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                let h_data = GetClipboardData(CF_UNICODETEXT);
                if !h_data.is_null() {
                    let ptr = GlobalLock(h_data) as *const u16;
                    if !ptr.is_null() {
                        let mut len = 0;
                        while *ptr.add(len) != 0 {
                            len += 1;
                        }
                        let slice = std::slice::from_raw_parts(ptr, len);
                        let s = String::from_utf16_lossy(slice);
                        GlobalUnlock(h_data);
                        if s.trim() == expected.trim() {
                            EmptyClipboard();
                        }
                    }
                }
                CloseClipboard();
            }
        }
    }
}

/// Windows 命名互斥量单实例保护守卫
#[cfg(windows)]
struct WindowsInstanceGuard {
    handle: *mut std::ffi::c_void,
}

#[cfg(windows)]
unsafe impl Send for WindowsInstanceGuard {}
#[cfg(windows)]
unsafe impl Sync for WindowsInstanceGuard {}

#[cfg(windows)]
impl Drop for WindowsInstanceGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            #[link(name = "kernel32")]
            extern "system" {
                fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
            }
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// 单实例保护：在 Windows 上创建命名互斥量（Named Mutex），
/// 防止多实例并发启动造成索引写覆盖与数据损坏。
#[cfg(windows)]
fn acquire_single_instance() -> Option<WindowsInstanceGuard> {
    use std::ffi::c_void;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateMutexW(
            lpMutexAttributes: *mut c_void,
            bInitialOwner: i32,
            lpName: *const u16,
        ) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_ACCESS_DENIED: u32 = 5;

    let mutex_name: Vec<u16> = OsStr::new("Local\\FileLocker_SingleInstance_Mutex")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let handle = CreateMutexW(std::ptr::null_mut(), 1, mutex_name.as_ptr());
        if handle.is_null() {
            return None;
        }
        let err = GetLastError();
        if err == ERROR_ALREADY_EXISTS || err == ERROR_ACCESS_DENIED {
            #[link(name = "kernel32")]
            extern "system" {
                fn CloseHandle(hObject: *mut c_void) -> i32;
            }
            CloseHandle(handle);
            return None;
        }
        Some(WindowsInstanceGuard { handle })
    }
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
    let _instance_guard = match acquire_single_instance() {
        Some(guard) => guard,
        None => {
            eprintln!("已有 FileLocker 实例在运行，本次启动退出");
            return;
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(VaultManager::new()))
        .setup(|app| {
            // 系统托盘常驻与菜单初始化
            let tray_menu = tauri::menu::MenuBuilder::new(app)
                .text("show", "打开 FileLocker")
                .text("boss_lock", "⚡ 紧急防窥锁屏 (Boss Key)")
                .separator()
                .text("quit", "退出 FileLocker")
                .build()?;

            if let Some(icon) = app.default_window_icon().cloned() {
                let _ = tauri::tray::TrayIconBuilder::new()
                    .icon(icon)
                    .menu(&tray_menu)
                    .show_menu_on_left_click(false)
                    .tooltip("FileLocker 本地安全保险箱")
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            }
                        }
                        "boss_lock" => {
                            let state = app.state::<VaultState>();
                            if let Ok(mut v) = state.lock() {
                                v.lock();
                            }
                            let _ = app.emit("vault-auto-locked", ());
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.hide();
                            }
                        }
                        "quit" => {
                            let state = app.state::<VaultState>();
                            if let Ok(mut v) = state.lock() {
                                v.lock();
                            }
                            app.exit(0);
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let tauri::tray::TrayIconEvent::Click {
                            button: tauri::tray::MouseButton::Left,
                            button_state: tauri::tray::MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            if let Some(w) = app.get_webview_window("main") {
                                if let Ok(visible) = w.is_visible() {
                                    if visible {
                                        let _ = w.hide();
                                    } else {
                                        let _ = w.show();
                                        let _ = w.unminimize();
                                        let _ = w.set_focus();
                                    }
                                }
                            }
                        }
                    })
                    .build(app);
            }

            // 应用启动时自动恢复防录屏/防截屏窗口保护状态
            let privacy_protection = {
                let state = app.state::<VaultState>();
                state
                    .lock()
                    .map(|v| v.get_privacy_screen_protection())
                    .unwrap_or(false)
            };
            if let Some(main_win) = app.get_webview_window("main") {
                let _ = apply_privacy_screen_protection(&main_win, privacy_protection);
            }

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

            // 原地编辑后台自动同步监听协程（每 1.5 秒检查一次打开编辑的文件修改状态）
            let handle_sync = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_millis(1500));
                let synced_ids = {
                    let state = handle_sync.state::<VaultState>();
                    let result = match state.lock() {
                        Ok(mut v) => {
                            if v.is_unlocked && !v.active_edits.is_empty() {
                                v.check_and_sync_edits().unwrap_or_default()
                            } else {
                                Vec::new()
                            }
                        }
                        Err(_) => Vec::new(),
                    };
                    result
                };
                for id in synced_ids {
                    let _ = handle_sync.emit("vault-entry-auto-saved", id);
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
            read_entry_preview,
            open_entry,
            export_entry,
            export_entries_to_dir,
            restore_entry,
            delete_entry,
            delete_entries,
            move_to_trash,
            restore_from_trash,
            permanently_delete_entries,
            empty_trash,
            save_note,
            read_note,
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
            copy_sensitive_text,
            get_privacy_screen_protection,
            set_privacy_screen_protection,
            get_shred_source,
            set_shred_source,
            open_entry_for_edit,
            finish_entry_edit,
            list_active_edits,
            is_biometrics_available,
            get_biometrics_enabled,
            set_biometrics_enabled,
            unlock_with_biometrics,
            panic_lock,
        ])
        .on_window_event(|window, event| {
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    // 点击窗口关闭按钮 [X] 时，静默隐藏到系统托盘常驻，避免丢失后台监听
                    let _ = window.hide();
                    api.prevent_close();
                }
                tauri::WindowEvent::DragDrop(event) => {
                    match event {
                        tauri::DragDropEvent::Drop { paths, .. } => {
                            let string_paths: Vec<String> = paths
                                .iter()
                                .map(|p| p.to_string_lossy().to_string())
                                .collect();
                            let _ = window.emit("files-drag-dropped", string_paths);
                        }
                        tauri::DragDropEvent::Enter { .. } => {
                            let _ = window.emit("window-drag-entered", ());
                        }
                        tauri::DragDropEvent::Leave => {
                            let _ = window.emit("window-drag-left", ());
                        }
                        _ => {}
                    }
                }
                tauri::WindowEvent::Destroyed => {
                    if let Some(state) = window.try_state::<Mutex<VaultManager>>() {
                        if let Ok(mut v) = state.lock() {
                            v.lock();
                        }
                    }
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
