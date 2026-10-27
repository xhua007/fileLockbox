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
pub fn open_path<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open")
        .arg(p)
        .status()
        .map_err(|e| format!("执行 open 命令失败: {e}"))?;
    #[cfg(target_os = "windows")]
    let status = {
        // cmd /c start 对路径中空格/中文兼容较好；"" 是窗口标题占位。
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &p.to_string_lossy()])
            .status()
            .map_err(|e| format!("执行 start 命令失败: {e}"))?
    };
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
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
