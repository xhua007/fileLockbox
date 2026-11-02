use std::path::Path;

/// 将文件/目录移入系统废纸篓（回收站）。
/// trash crate 跨平台支持 macOS Trash / Windows Recycle Bin / Linux 桌面回收站。
/// 若失败则回退为直接删除（按照需求，这是可接受的简化）。
pub fn move_to_trash<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(());
    }
    match trash::delete(p) {
        Ok(_) => Ok(()),
        Err(e) => {
            // 回退：直接删除。
            if p.is_dir() {
                std::fs::remove_dir_all(p)
                    .map_err(|err| format!("移入废纸篓失败，直接删除也失败: {e} / {err}"))?;
            } else {
                std::fs::remove_file(p)
                    .map_err(|err| format!("移入废纸篓失败，直接删除也失败: {e} / {err}"))?;
            }
            Ok(())
        }
    }
}

/// 用系统默认程序打开文件。
///
/// 各平台均以「参数数组」方式传路径，不经过 shell 解析，
/// 避免路径中的 `& | ^ % "` 等字符被二次解释成命令。
pub fn open_path<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("open")
            .arg(p)
            .status()
            .map_err(|e| format!("执行 open 命令失败: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("打开命令返回非零状态: {:?}", status.code()))
        }
    }

    #[cfg(target_os = "windows")]
    {
        // 直接调用 ShellExecuteW，不经 cmd.exe / start，路径不会被当作命令行再次解析。
        windows_shell_open(p)
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let status = std::process::Command::new("xdg-open")
            .arg(p)
            .status()
            .map_err(|e| format!("执行 xdg-open 失败: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("打开命令返回非零状态: {:?}", status.code()))
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_shell_open(p: &Path) -> Result<(), String> {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;

    // ShellExecuteW 的返回值为 HINSTANCE，> 32 表示成功。
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> *mut c_void;
    }

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    let operation = wide(OsStr::new("open"));
    let file = wide(p.as_os_str());
    // SW_SHOWNORMAL = 1
    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };
    if ret as isize > 32 {
        Ok(())
    } else {
        Err(format!("系统无法打开该文件（ShellExecuteW 返回 {}）", ret as isize))
    }
}

/// 格式化字节数为人类可读字符串（前端可选使用）。
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if size == 0 {
        return "0 B".to_string();
    }
    let mut s = size as f64;
    let mut i = 0;
    while s >= 1024.0 && i < UNITS.len() - 1 {
        s /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", size, UNITS[i])
    } else {
        format!("{:.2} {}", s, UNITS[i])
    }
}
