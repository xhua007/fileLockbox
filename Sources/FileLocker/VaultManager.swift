import CryptoKit
import Foundation
import AppKit
import Security

enum EntryKind: String, Codable {
    case file
    case folder
}

struct VaultEntry: Identifiable, Codable, Hashable {
    let id: UUID
    var name: String
    var kind: EntryKind
    var size: Int
    var addedAt: Date
    var blobName: String
    /// 拖入前的完整路径，用于还原。
    var originalPath: String?
}

private struct IndexData: Codable {
    var entries: [VaultEntry]
}

/// 主密钥的两种包装：分别用「密码」和「恢复码」派生出的密钥加密。
/// 恢复码不会以明文形式落盘，因此本机无法绕过密码或恢复码取回数据。
private struct Keyring: Codable {
    var version: Int
    var passwordSalt: Data
    var passwordWrap: Data
    var recoverySalt: Data
    var recoveryWrap: Data
}

enum VaultError: LocalizedError {
    case passwordNotSet
    case folderZipFailed
    case notUnlocked
    case noRecoveryCode
    case invalidRecoveryCode

    var errorDescription: String? {
        switch self {
        case .passwordNotSet: return "尚未设置密码"
        case .folderZipFailed: return "文件夹压缩失败"
        case .notUnlocked: return "保险箱尚未解锁"
        case .noRecoveryCode: return "该保险箱没有恢复码"
        case .invalidRecoveryCode: return "恢复码无效，请检查后重试"
        }
    }
}

final class VaultManager: ObservableObject {
    @Published var isUnlocked = false
    @Published var entries: [VaultEntry] = []
    @Published var errorMessage: String?
    @Published var isBusy = false
    /// 操作成功的短暂提示，展示后自动消失。
    @Published var statusMessage: String?
    /// 新生成、尚未被用户确认保存的恢复码。
    @Published var pendingRecoveryCode: String?

    private var key: SymmetricKey?
    private var statusClearWorkItem: DispatchWorkItem?

    let vaultDir: URL
    private let dataDir: URL
    private let saltURL: URL
    private let indexURL: URL
    private let keyringURL: URL

    static let defaultVaultDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/FileLocker/vault")

    init(vaultDir: URL = VaultManager.defaultVaultDir) {
        self.vaultDir = vaultDir
        self.dataDir = vaultDir.appendingPathComponent("data")
        self.saltURL = vaultDir.appendingPathComponent("salt.bin")
        self.indexURL = vaultDir.appendingPathComponent("index.enc")
        self.keyringURL = vaultDir.appendingPathComponent("keyring.json")
    }

    /// 是否已初始化密码（存在索引文件即视为已设置）。
    var hasPassword: Bool {
        FileManager.default.fileExists(atPath: indexURL.path)
    }

    /// 是否支持恢复码找回（旧版本创建的保险箱没有 keyring）。
    var hasRecoveryCode: Bool {
        FileManager.default.fileExists(atPath: keyringURL.path)
    }

    // MARK: - 密码

    func setPassword(_ password: String) throws {
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)

        let masterKey = SymmetricKey(size: .bits256)
        let recoveryCode = Self.generateRecoveryCode()

        try writeKeyring(masterKey: masterKey, password: password, recoveryCode: recoveryCode)

        self.key = masterKey
        self.entries = []
        try saveIndex()
        self.isUnlocked = true
        self.pendingRecoveryCode = recoveryCode
    }

    func unlock(_ password: String) throws {
        guard FileManager.default.fileExists(atPath: indexURL.path) else {
            throw VaultError.passwordNotSet
        }

        if let keyring = try? loadKeyring() {
            let masterKey = try unwrapMasterKey(password: password, keyring: keyring)
            let index = try decryptIndex(key: masterKey)

            self.key = masterKey
            self.entries = index.entries
            self.isUnlocked = true
        } else {
            try unlockLegacyVault(password)
        }
    }

    /// 旧版本：密钥直接由密码派生。解锁成功后无损升级为双包装密钥体系。
    private func unlockLegacyVault(_ password: String) throws {
        let salt = try Data(contentsOf: saltURL)
        let masterKey = SymmetricKey(data: deriveKey(password: password, salt: salt))
        let index = try decryptIndex(key: masterKey)

        // 直接沿用旧密钥作为主密钥，无需重新加密任何已存入的文件。
        let recoveryCode = Self.generateRecoveryCode()
        try writeKeyring(masterKey: masterKey, password: password, recoveryCode: recoveryCode)

        self.key = masterKey
        self.entries = index.entries
        self.isUnlocked = true
        self.pendingRecoveryCode = recoveryCode
    }

    func lock() {
        key = nil
        entries = []
        isUnlocked = false
        clearDragTempFiles()
    }

    // MARK: - 恢复码

    /// 验证恢复码是否可解开主密钥。
    func validateRecoveryCode(_ code: String) -> Bool {
        guard let keyring = try? loadKeyring() else { return false }
        return (try? unwrapMasterKey(recoveryCode: code, keyring: keyring)) != nil
    }

    /// 已解锁状态下修改密码，主密钥不变，重新包装密码层并生成新恢复码。
    @discardableResult
    func changePassword(oldPassword: String, newPassword: String) throws -> String {
        guard let masterKey = key else { throw VaultError.notUnlocked }

        // 先验证旧密码正确：用 keyring 里的 passwordWrap 做校验。
        if let keyring = try? loadKeyring() {
            _ = try unwrapMasterKey(password: oldPassword, keyring: keyring)
        } else {
            // 旧格式保险箱：用密码派生尝试解密索引。
            let salt = try Data(contentsOf: saltURL)
            let checkKey = SymmetricKey(data: deriveKey(password: oldPassword, salt: salt))
            _ = try decryptIndex(key: checkKey)
        }

        let newRecoveryCode = Self.generateRecoveryCode()
        try writeKeyring(masterKey: masterKey, password: newPassword, recoveryCode: newRecoveryCode)
        return newRecoveryCode
    }

    /// 用恢复码重设密码，返回新生成的恢复码（旧恢复码随即失效）。
    @discardableResult
    func resetPassword(recoveryCode code: String, newPassword: String) throws -> String {
        let keyring = try loadKeyring()
        let masterKey = try unwrapMasterKey(recoveryCode: code, keyring: keyring)
        _ = try decryptIndex(key: masterKey)

        let newRecoveryCode = Self.generateRecoveryCode()
        try writeKeyring(masterKey: masterKey, password: newPassword, recoveryCode: newRecoveryCode)

        self.key = masterKey
        self.entries = try decryptIndex(key: masterKey).entries
        self.isUnlocked = true
        return newRecoveryCode
    }

    private func writeKeyring(masterKey: SymmetricKey, password: String, recoveryCode: String) throws {
        let masterKeyData = masterKey.withUnsafeBytes { Data($0) }

        let passwordSalt = generateSalt()
        let passwordKEK = SymmetricKey(data: deriveKey(password: password, salt: passwordSalt))
        let passwordWrap = try encryptData(masterKeyData, key: passwordKEK)

        let recoverySalt = generateSalt()
        let recoveryKEK = SymmetricKey(data: deriveKey(password: Self.normalizeRecoveryCode(recoveryCode), salt: recoverySalt))
        let recoveryWrap = try encryptData(masterKeyData, key: recoveryKEK)

        let keyring = Keyring(
            version: 2,
            passwordSalt: passwordSalt,
            passwordWrap: passwordWrap,
            recoverySalt: recoverySalt,
            recoveryWrap: recoveryWrap
        )

        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(keyring)
        try data.write(to: keyringURL, options: .atomic)

        // 保留 salt.bin 以便识别旧格式，密码盐以 keyring 为准。
        try? passwordSalt.write(to: saltURL, options: .atomic)
    }

    private func loadKeyring() throws -> Keyring {
        guard FileManager.default.fileExists(atPath: keyringURL.path) else {
            throw VaultError.noRecoveryCode
        }
        let data = try Data(contentsOf: keyringURL)
        return try JSONDecoder().decode(Keyring.self, from: data)
    }

    private func unwrapMasterKey(password: String, keyring: Keyring) throws -> SymmetricKey {
        let kek = SymmetricKey(data: deriveKey(password: password, salt: keyring.passwordSalt))
        let data = try decryptData(keyring.passwordWrap, key: kek)
        return SymmetricKey(data: data)
    }

    private func unwrapMasterKey(recoveryCode: String, keyring: Keyring) throws -> SymmetricKey {
        let normalized = Self.normalizeRecoveryCode(recoveryCode)
        let kek = SymmetricKey(data: deriveKey(password: normalized, salt: keyring.recoverySalt))
        let data = try decryptData(keyring.recoveryWrap, key: kek)
        return SymmetricKey(data: data)
    }

    /// 排除易混字符的 Crockford Base32 字母表。
    private static let recoveryAlphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    /// 生成 24 位恢复码，形如 ABCD-EFGH-JKLM-NPQR-STUV-WXYZ。
    static func generateRecoveryCode() -> String {
        var bytes = [UInt8](repeating: 0, count: 15)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        var chars: [Character] = []
        var buffer: UInt32 = 0
        var bits = 0

        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                let index = Int((buffer >> UInt32(bits - 5)) & 0x1F)
                chars.append(recoveryAlphabet[index])
                bits -= 5
            }
        }

        var code = ""
        for (offset, char) in chars.enumerated() {
            if offset > 0 && offset % 4 == 0 { code.append("-") }
            code.append(char)
        }
        return code
    }

    /// 统一大小写、去掉分隔符，并纠正易混字符。
    static func normalizeRecoveryCode(_ code: String) -> String {
        var result = ""
        for char in code.uppercased() {
            switch char {
            case "-", " ", "\t", "\n":
                continue
            case "O":
                result.append("0")
            case "I", "L":
                result.append("1")
            case "U":
                result.append("V")
            default:
                result.append(char)
            }
        }
        return result
    }

    // MARK: - 添加

    func addItems(urls: [URL]) {
        guard let key else {
            errorMessage = VaultError.notUnlocked.errorDescription
            return
        }

        isBusy = true
        let dataDir = self.dataDir
        let vaultDir = self.vaultDir
        let existing = entries

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                var added: [VaultEntry] = []
                var skipped = 0
                for url in urls {
                    // 从列表里拖回窗口的是本应用解密的临时副本，不应重复入库。
                    if url.path.hasPrefix(Self.dragDir.path) {
                        skipped += 1
                        continue
                    }

                    let prepared = try Self.prepareItem(at: url, key: key)

                    // 同名同大小视为已存在，避免重复添加。
                    let isDuplicate = (existing + added).contains {
                        $0.name == prepared.entry.name && $0.size == prepared.entry.size
                    }
                    if isDuplicate {
                        skipped += 1
                        continue
                    }

                    let blobURL = dataDir.appendingPathComponent(prepared.entry.blobName)
                    try prepared.encrypted.write(to: blobURL, options: .atomic)
                    added.append(prepared.entry)

                    // 入库成功后把原文件移到废纸篓（保险箱目录内的文件除外）。
                    if !url.path.hasPrefix(vaultDir.path) {
                        Self.discardOriginal(url)
                    }
                }
                DispatchQueue.main.async {
                    if !added.isEmpty {
                        self.entries.append(contentsOf: added)
                        try? self.saveIndex()
                    }
                    self.isBusy = false
                    if skipped > 0 {
                        self.showStatus(added.isEmpty
                            ? "已在保险箱中，未重复添加"
                            : "已添加 \(added.count) 项，跳过 \(skipped) 项重复文件")
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isBusy = false
                }
            }
        }
    }

    /// 把原始文件移入废纸篓，失败时尝试直接删除。
    private static func discardOriginal(_ url: URL) {
        do {
            try FileManager.default.trashItem(at: url, resultingItemURL: nil)
        } catch {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private static func prepareItem(at url: URL, key: SymmetricKey) throws -> (entry: VaultEntry, encrypted: Data) {
        let isDir = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? url.hasDirectoryPath
        let data: Data
        if isDir {
            let zipURL = try Self.zipDirectory(url)
            data = try Data(contentsOf: zipURL)
            try? FileManager.default.removeItem(at: zipURL)
        } else {
            data = try Data(contentsOf: url)
        }

        let encrypted = try encryptData(data, key: key)
        let entry = VaultEntry(
            id: UUID(),
            name: url.lastPathComponent,
            kind: isDir ? .folder : .file,
            size: data.count,
            addedAt: Date(),
            blobName: UUID().uuidString + ".bin",
            originalPath: url.path
        )
        return (entry, encrypted)
    }

    // MARK: - 删除

    /// 从保险箱删除：原文件解密后放入废纸篓，废纸篓不可用时直接移除密文。
    func delete(_ entry: VaultEntry) {
        isBusy = true
        DispatchQueue.global(qos: .userInitiated).async {
            var trashed = false
            do {
                let tmp = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString)
                try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
                let restored = try self.restore(entry: entry, to: tmp)
                try FileManager.default.trashItem(at: restored, resultingItemURL: nil)
                try? FileManager.default.removeItem(at: tmp)
                trashed = true
            } catch {
                trashed = false
            }

            DispatchQueue.main.async {
                self.removeStoredItem(entry)
                self.isBusy = false
                if !trashed {
                    self.errorMessage = "「\(entry.name)」无法移入废纸篓，已从保险箱中移除"
                }
            }
        }
    }

    /// 仅移除本地密文与索引，不涉及废纸篓。
    private func removeStoredItem(_ entry: VaultEntry) {
        let blob = dataDir.appendingPathComponent(entry.blobName)
        try? FileManager.default.removeItem(at: blob)
        entries.removeAll { $0.id == entry.id }
        try? saveIndex()
    }

    // MARK: - 打开 / 导出 / 还原

    func open(_ entry: VaultEntry) {
        isBusy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let tmp = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString)
                try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
                let restored = try self.restore(entry: entry, to: tmp)
                DispatchQueue.main.async {
                    NSWorkspace.shared.open(restored)
                    self.isBusy = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isBusy = false
                }
            }
        }
    }

    func export(_ entry: VaultEntry) {
        isBusy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let data = try self.decryptedData(for: entry)
                let suggested = entry.kind == .folder ? entry.name + ".zip" : entry.name
                DispatchQueue.main.async {
                    let panel = NSSavePanel()
                    panel.nameFieldStringValue = suggested
                    panel.begin { response in
                        guard response == .OK, let url = panel.url else {
                            self.isBusy = false
                            return
                        }
                        self.writeExportData(data, to: url, entryName: entry.name)
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isBusy = false
                }
            }
        }
    }

    /// 直接导出到指定 URL（用于批量导出/还原）。
    func export(_ entry: VaultEntry, to url: URL) {
        isBusy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let data = try self.decryptedData(for: entry)
                self.writeExportData(data, to: url, entryName: entry.name, closeBusy: false)
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isBusy = false
                }
            }
        }
    }

    private func writeExportData(_ data: Data, to url: URL, entryName: String, closeBusy: Bool = true) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try data.write(to: url, options: .atomic)
                DispatchQueue.main.async {
                    if closeBusy { self.isBusy = false }
                    self.showStatus("已导出：\(entryName)")
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    if closeBusy { self.isBusy = false }
                }
            }
        }
    }

    /// 展示一条自动消失的成功提示。
    func showStatus(_ text: String) {
        statusClearWorkItem?.cancel()
        statusMessage = text

        let item = DispatchWorkItem { [weak self] in
            self?.statusMessage = nil
        }
        statusClearWorkItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5, execute: item)
    }

    /// 拖拽导出用的临时目录：解密出的明文只在这里短暂存在，锁定或退出时清除。
    private static let dragDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("FileLockerDrag", isDirectory: true)

    /// 为「拖到 Finder」准备解密后的文件，返回临时文件地址。
    func temporaryExportURL(for entry: VaultEntry) -> URL? {
        do {
            let data = try decryptedData(for: entry)
            try FileManager.default.createDirectory(at: Self.dragDir, withIntermediateDirectories: true)
            let name = entry.kind == .folder ? entry.name + ".zip" : entry.name
            let url = Self.dragDir.appendingPathComponent(name)
            try? FileManager.default.removeItem(at: url)
            try data.write(to: url)
            return url
        } catch {
            errorMessage = error.localizedDescription
            return nil
        }
    }

    func clearDragTempFiles() {
        try? FileManager.default.removeItem(at: Self.dragDir)
    }

    /// 还原到原目录；原目录已不存在时放到「文稿」。
    func restore(_ entry: VaultEntry) {
        isBusy = true
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let dir = try Self.restoreDirectory(for: entry)
                let fileURL = try self.restore(entry: entry, to: dir)
                DispatchQueue.main.async {
                    self.removeStoredItem(entry)
                    NSWorkspace.shared.activateFileViewerSelecting([fileURL])
                    self.isBusy = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isBusy = false
                }
            }
        }
    }

    private static func restoreDirectory(for entry: VaultEntry) throws -> URL {
        if let path = entry.originalPath {
            let parent = URL(fileURLWithPath: path).deletingLastPathComponent()
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: parent.path, isDirectory: &isDir), isDir.boolValue {
                return parent
            }
        }
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents")
        try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        return documents
    }

    // MARK: - 工具

    private func decryptedData(for entry: VaultEntry) throws -> Data {
        guard let key else { throw VaultError.notUnlocked }
        let blob = dataDir.appendingPathComponent(entry.blobName)
        let encrypted = try Data(contentsOf: blob)
        return try decryptData(encrypted, key: key)
    }

    private func restore(entry: VaultEntry, to dir: URL) throws -> URL {
        let data = try decryptedData(for: entry)
        let target = uniqueURL(in: dir, name: entry.name)

        if entry.kind == .folder {
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
            let zipURL = tmp.appendingPathComponent("archive.zip")
            try data.write(to: zipURL)
            try Self.unzipDirectory(zipURL, to: tmp)
            try? FileManager.default.removeItem(at: zipURL)
            try FileManager.default.moveItem(at: tmp.appendingPathComponent(entry.name), to: target)
            try? FileManager.default.removeItem(at: tmp)
            return target
        } else {
            try data.write(to: target)
            return target
        }
    }

    /// 目标位置已有同名文件时，追加序号避免覆盖。
    private func uniqueURL(in dir: URL, name: String) -> URL {
        var candidate = dir.appendingPathComponent(name)
        guard FileManager.default.fileExists(atPath: candidate.path) else { return candidate }

        let nsName = name as NSString
        let base = nsName.deletingPathExtension
        let ext = nsName.pathExtension
        var index = 2

        while true {
            let newName = ext.isEmpty ? "\(base) \(index)" : "\(base) \(index).\(ext)"
            candidate = dir.appendingPathComponent(newName)
            if !FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            index += 1
        }
    }

    private func saveIndex() throws {
        guard let key else { throw VaultError.notUnlocked }
        let index = IndexData(entries: entries)
        let json = try JSONEncoder().encode(index)
        let encrypted = try encryptData(json, key: key)
        try encrypted.write(to: indexURL, options: .atomic)
    }

    /// 用指定主密钥解密索引；密码或恢复码不对时会抛错。
    private func decryptIndex(key: SymmetricKey) throws -> IndexData {
        let encrypted = try Data(contentsOf: indexURL)
        let json = try decryptData(encrypted, key: key)
        return try JSONDecoder().decode(IndexData.self, from: json)
    }

    private static func zipDirectory(_ dir: URL) throws -> URL {
        let zipURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".zip")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-c", "-k", "--sequesterRsrc", "--keepParent", dir.path, zipURL.path]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw VaultError.folderZipFailed }
        return zipURL
    }

    private static func unzipDirectory(_ zipURL: URL, to destination: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-x", "-k", zipURL.path, destination.path]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw VaultError.folderZipFailed }
    }
}
