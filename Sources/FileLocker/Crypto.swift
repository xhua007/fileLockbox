import CryptoKit
import Foundation
import Security

enum CryptoError: LocalizedError {
    case invalidData
    case decryptionFailed

    var errorDescription: String? {
        switch self {
        case .invalidData: return "数据格式无效"
        case .decryptionFailed: return "解密失败，密码可能不正确"
        }
    }
}

/// 使用 PBKDF2-HMAC-SHA256 从密码派生加密密钥。
func deriveKey(password: String, salt: Data, iterations: Int = 120_000, keyLength: Int = 32) -> Data {
    let passwordData = Data(password.utf8)
    var output = Data()
    var blockIndex = UInt32(1)

    while output.count < keyLength {
        var block = Data()
        block.append(salt)
        block.append(contentsOf: withUnsafeBytes(of: blockIndex.bigEndian) { Data($0) })

        var u = Data(HMAC<SHA256>.authenticationCode(for: block, using: SymmetricKey(data: passwordData)))
        var result = u

        for _ in 1..<iterations {
            u = Data(HMAC<SHA256>.authenticationCode(for: u, using: SymmetricKey(data: passwordData)))
            for i in 0..<result.count {
                result[i] ^= u[i]
            }
        }

        output.append(result)
        blockIndex += 1
    }

    return Data(output.prefix(keyLength))
}

func generateSalt(byteCount: Int = 16) -> Data {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
    return Data(bytes)
}

/// AES-GCM 加密，返回 combined(带 nonce 与 tag 的完整密文)。
func encryptData(_ data: Data, key: SymmetricKey) throws -> Data {
    let sealed = try AES.GCM.seal(data, using: key)
    guard let combined = sealed.combined else { throw CryptoError.invalidData }
    return combined
}

/// AES-GCM 解密，密码错误时抛错。
func decryptData(_ data: Data, key: SymmetricKey) throws -> Data {
    do {
        let sealed = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealed, using: key)
    } catch {
        throw CryptoError.decryptionFailed
    }
}
