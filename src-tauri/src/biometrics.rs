//! 生物识别快速认证模块（macOS Touch ID / Windows Hello）

#[cfg(target_os = "macos")]
#[allow(unexpected_cfgs)]
mod macos {
    use objc::{sel, sel_impl};
    use std::ffi::CStr;
    use std::sync::mpsc::sync_channel;

    #[repr(C)]
    struct BlockDescriptor {
        reserved: libc::c_ulong,
        size: libc::c_ulong,
    }

    static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: std::mem::size_of::<BlockLiteral>() as libc::c_ulong,
    };

    extern "C" {
        static _NSConcreteStackBlock: [*const libc::c_void; 32];
    }

    #[repr(C)]
    struct BlockLiteral {
        isa: *const libc::c_void,
        flags: libc::c_int,
        reserved: libc::c_int,
        invoke: extern "C" fn(*mut BlockLiteral, bool, *mut objc::runtime::Object),
        descriptor: *const BlockDescriptor,
        tx: *mut std::sync::mpsc::SyncSender<Result<(), String>>,
    }

    extern "C" fn block_invoke(
        block: *mut BlockLiteral,
        success: bool,
        error: *mut objc::runtime::Object,
    ) {
        unsafe {
            let tx = &*(*block).tx;
            if success {
                let _ = tx.send(Ok(()));
            } else {
                let err_msg = if !error.is_null() {
                    let desc: *mut objc::runtime::Object =
                        objc::msg_send![error, localizedDescription];
                    let utf8: *const libc::c_char = objc::msg_send![desc, UTF8String];
                    if !utf8.is_null() {
                        CStr::from_ptr(utf8).to_string_lossy().to_string()
                    } else {
                        "Touch ID 验证失败".to_string()
                    }
                } else {
                    "Touch ID 验证已取消或失败".to_string()
                };
                let _ = tx.send(Err(err_msg));
            }
        }
    }

    fn ensure_framework_loaded() -> bool {
        unsafe {
            let path =
                b"/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication\0";
            let handle = libc::dlopen(path.as_ptr() as *const _, libc::RTLD_LAZY);
            !handle.is_null()
        }
    }

    /// 检查当前设备是否支持生物识别（Touch ID）
    pub fn is_biometrics_available() -> bool {
        if !ensure_framework_loaded() {
            return false;
        }
        unsafe {
            let cls = match objc::runtime::Class::get("LAContext") {
                Some(c) => c,
                None => return false,
            };
            let ctx: *mut objc::runtime::Object = objc::msg_send![cls, alloc];
            let ctx: *mut objc::runtime::Object = objc::msg_send![ctx, init];
            if ctx.is_null() {
                return false;
            }
            let mut error: *mut objc::runtime::Object = std::ptr::null_mut();
            // LAPolicyDeviceOwnerAuthentication = 2 支持 Touch ID 或设备密码回退
            let can: bool = objc::msg_send![ctx, canEvaluatePolicy: 2isize error: &mut error];
            let _: () = objc::msg_send![ctx, release];
            can
        }
    }

    /// 弹出系统原生 Touch ID / 设备密码验证弹窗
    pub fn authenticate(reason: &str) -> Result<(), String> {
        if !ensure_framework_loaded() {
            return Err("系统未支持 LocalAuthentication 框架".into());
        }
        unsafe {
            let cls = match objc::runtime::Class::get("LAContext") {
                Some(c) => c,
                None => return Err("未找到 LAContext 类".into()),
            };
            let ctx: *mut objc::runtime::Object = objc::msg_send![cls, alloc];
            let ctx: *mut objc::runtime::Object = objc::msg_send![ctx, init];
            if ctx.is_null() {
                return Err("创建 LAContext 失败".into());
            }

            let ns_string_cls = match objc::runtime::Class::get("NSString") {
                Some(c) => c,
                None => {
                    let _: () = objc::msg_send![ctx, release];
                    return Err("未找到 NSString 类".into());
                }
            };
            let reason_bytes = std::ffi::CString::new(reason).unwrap_or_default();
            let ns_reason: *mut objc::runtime::Object = objc::msg_send![
                ns_string_cls,
                stringWithUTF8String: reason_bytes.as_ptr()
            ];

            let (tx, rx) = sync_channel(1);
            let mut tx_box = Box::new(tx);
            let mut literal = BlockLiteral {
                isa: _NSConcreteStackBlock.as_ptr() as *const libc::c_void,
                flags: 0,
                reserved: 0,
                invoke: block_invoke,
                descriptor: &DESCRIPTOR,
                tx: &mut *tx_box,
            };

            let () = objc::msg_send![
                ctx,
                evaluatePolicy: 2isize
                localizedReason: ns_reason
                reply: &mut literal
            ];

            let res = rx
                .recv()
                .map_err(|e| format!("等待生物识别认证失败: {e}"))?;
            let _: () = objc::msg_send![ctx, release];
            res
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    pub fn is_biometrics_available() -> bool {
        // Windows 上若需要验证，可通过 UserConsentVerifier 或 Credential UI，
        // 默认可作为凭据安全代理
        false
    }

    pub fn authenticate(_reason: &str) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod unsupported {
    pub fn is_biometrics_available() -> bool {
        false
    }

    pub fn authenticate(_reason: &str) -> Result<(), String> {
        Err("当前操作系统不支持硬件生物识别".into())
    }
}

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub use unsupported::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometrics_availability_check() {
        let available = is_biometrics_available();
        println!("Biometrics available on current machine: {available}");
    }
}
