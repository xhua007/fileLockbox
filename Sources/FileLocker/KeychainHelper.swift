import Foundation
import Security
import LocalAuthentication

/// 钥匙串存取 + 生物识别（Touch ID / Apple Watch）辅助。
enum KeychainHelper {

    private static let service = "com.filelocker.vault"
    private static let account = "password"

    // MARK: - 保存 / 读取 / 删除密码

    /// 将密码保存到钥匙串，标记为「需要生物识别才能取出」。
    /// - requiresBiometry: true 时必须 Touch ID/密码才能读；false 时为普通项，App 可直接读。
    static func savePassword(_ password: String, requiresBiometry: Bool) {
        deletePassword()
        guard let data = password.data(using: .utf8) else { return }

        let access: SecAccessControl?
        if requiresBiometry {
            // biometryCurrentSet：用户录入新指纹/面容后失效；不回退密码，更安全。
            access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                nil
            )
        } else {
            access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [],
                nil
            )
        }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecValueData: data,
            kSecAttrAccessControl: access as Any
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    /// 从钥匙串读取密码。若使用生物识别保护，会弹出系统验证框。
    static func loadPassword(reason: String = "使用 Touch ID 解锁文件保险箱", completion: @escaping (String?) -> Void) {
        let context = LAContext()
        context.localizedReason = reason
        // 不允许输入设备密码回退，避免生物识别失败后弹窗绕到系统密码。
        context.interactionNotAllowed = false

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: context,
            kSecAttrSynchronizable: false
        ]

        DispatchQueue.global(qos: .userInitiated).async {
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess,
                  let data = item as? Data,
                  let pwd = String(data: data, encoding: .utf8) else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            DispatchQueue.main.async { completion(pwd) }
        }
    }

    static func deletePassword() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// 检测本机是否已保存过密码（无需验证）。
    static func hasSavedPassword() -> Bool {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecReturnData: false,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// 检测当前设备是否支持生物识别。
    static func biometryAvailable() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
}
