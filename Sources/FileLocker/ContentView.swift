import SwiftUI
import UniformTypeIdentifiers
import AppKit

struct ContentView: View {
    @EnvironmentObject var vault: VaultManager
    @State private var showForgotPassword = false

    var body: some View {
        Group {
            if vault.isUnlocked {
                VaultView()
            } else if vault.hasPassword {
                LockView(mode: .unlock) { showForgotPassword = true }
            } else {
                LockView(mode: .setup)
            }
        }
        .alert("提示", isPresented: errorBinding) {
            Button("好", role: .cancel) {}
        } message: {
            Text(vault.errorMessage ?? "")
        }
        .overlay(alignment: .bottom) {
            if let status = vault.statusMessage {
                Label(status, systemImage: "checkmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(.regularMaterial, in: Capsule())
                    .overlay(
                        Capsule().strokeBorder(Color.green.opacity(0.45))
                    )
                    .shadow(color: .black.opacity(0.15), radius: 8, y: 3)
                    .padding(.bottom, 28)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.2), value: vault.statusMessage)
        .sheet(item: sheetBinding) { sheet in
            switch sheet {
            case .recoveryCode(let code):
                RecoveryCodeView(code: code) {
                    vault.pendingRecoveryCode = nil
                }
                .interactiveDismissDisabled()
            case .forgotPassword:
                ForgotPasswordView()
            }
        }
    }

    private enum ActiveSheet: Identifiable {
        case recoveryCode(String)
        case forgotPassword

        var id: String {
            switch self {
            case .recoveryCode(let code): return "recovery-\(code)"
            case .forgotPassword: return "forgot-password"
            }
        }
    }

    private var activeSheet: ActiveSheet? {
        if showForgotPassword { return .forgotPassword }
        if let code = vault.pendingRecoveryCode { return .recoveryCode(code) }
        return nil
    }

    private var sheetBinding: Binding<ActiveSheet?> {
        Binding(
            get: { activeSheet },
            set: { newValue in
                guard newValue == nil else { return }
                showForgotPassword = false
                vault.pendingRecoveryCode = nil
            }
        )
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { vault.errorMessage != nil },
            set: { if !$0 { vault.errorMessage = nil } }
        )
    }
}

// MARK: - 锁定 / 设置密码

struct LockView: View {
    enum Mode {
        case setup, unlock
    }

    let mode: Mode
    var onForgotPassword: (() -> Void)?
    @EnvironmentObject var vault: VaultManager

    @State private var password = ""
    @State private var confirm = ""
    @State private var error: String?
    @State private var rememberPassword = true
    @State private var useBiometry = KeychainHelper.biometryAvailable()
    @State private var biometryTrying = false

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 56))
                .foregroundStyle(.blue)

            Text(mode == .setup ? "设置保险箱密码" : "输入密码解锁")
                .font(.title2.bold())

            Text(mode == .setup
                 ? "密码用于加密本地文件，请务必牢记。"
                 : "解锁后可拖拽、查看与导出文件。")
                .font(.callout)
                .foregroundStyle(.secondary)

            SecureField("密码", text: $password)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)

            if mode == .setup {
                SecureField("确认密码", text: $confirm)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)
            }

            Toggle(isOn: $rememberPassword) {
                Text(useBiometry ? "记住密码并启用 Touch ID" : "记住密码")
                    .font(.callout)
            }
            .frame(maxWidth: 320)
            .toggleStyle(.checkbox)

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            Button(mode == .setup ? "创建并解锁" : "解锁") {
                submit()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)

            if mode == .unlock && KeychainHelper.hasSavedPassword() && KeychainHelper.biometryAvailable() {
                Button {
                    triggerBiometricUnlock()
                } label: {
                    Label(biometryTrying ? "验证中…" : "使用 Touch ID 解锁", systemImage: "touchid")
                }
                .buttonStyle(.bordered)
                .disabled(biometryTrying)
            }

            if mode == .unlock, let onForgotPassword {
                Button("忘记密码？用恢复码找回") {
                    onForgotPassword()
                }
                .buttonStyle(.link)
                .font(.callout)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            // 解锁页：若钥匙串已有密码且支持 Touch ID，自动触发一次生物识别。
            if mode == .unlock, KeychainHelper.hasSavedPassword(), KeychainHelper.biometryAvailable() {
                triggerBiometricUnlock()
            }
        }
    }

    private func submit() {
        error = nil
        do {
            if mode == .setup {
                guard !password.isEmpty else { error = "密码不能为空"; return }
                guard password == confirm else { error = "两次输入的密码不一致"; return }
                try vault.setPassword(password)
                if rememberPassword {
                    KeychainHelper.savePassword(password, requiresBiometry: useBiometry)
                } else {
                    KeychainHelper.deletePassword()
                }
            } else {
                try vault.unlock(password)
                if rememberPassword {
                    KeychainHelper.savePassword(password, requiresBiometry: useBiometry)
                }
            }
        } catch let caughtError {
            error = caughtError.localizedDescription
        }
    }

    private func triggerBiometricUnlock() {
        guard !biometryTrying else { return }
        biometryTrying = true
        error = nil
        KeychainHelper.loadPassword { saved in
            biometryTrying = false
            guard let pwd = saved else {
                error = "Touch ID 验证失败，请输入密码。"
                return
            }
            do {
                try vault.unlock(pwd)
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}

// MARK: - 忘记密码 / 恢复码

struct ForgotPasswordView: View {
    @EnvironmentObject var vault: VaultManager
    @Environment(\.dismiss) private var dismiss

    private enum Step {
        case enterCode, setPassword, finished
    }

    @State private var step: Step = .enterCode
    @State private var code = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var newRecoveryCode = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label("用恢复码找回", systemImage: "key.horizontal.fill")
                    .font(.title3.bold())
                Spacer()
                Button("关闭") { dismiss() }
                    .buttonStyle(.link)
            }

            if !vault.hasRecoveryCode {
                noRecoveryNotice
            } else {
                switch step {
                case .enterCode: codeStep
                case .setPassword: passwordStep
                case .finished: finishedStep
                }
            }
        }
        .padding(24)
        .frame(width: 480, alignment: .leading)
    }

    private var noRecoveryNotice: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("这个保险箱由旧版本创建，还没有设置恢复码，因此无法找回密码。")
                .font(.callout)
            Text("请先用正确密码解锁一次，应用会自动补齐恢复码；若密码已完全遗忘，只能删除下面的目录重新开始：")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text(vault.vaultDir.path)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("输入设置保险箱时保存的恢复码，共 24 位字符，分隔符可省略。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            TextField("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", text: $code)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("下一步") { checkCode() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var passwordStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("恢复码验证通过，请设置新密码。保险箱内已加密的文件不会受任何影响。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            SecureField("新密码", text: $newPassword)
                .textFieldStyle(.roundedBorder)
            SecureField("确认新密码", text: $confirmPassword)
                .textFieldStyle(.roundedBorder)

            if let error {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("上一步") {
                    error = nil
                    step = .enterCode
                }
                Spacer()
                Button("重设密码") { applyNewPassword() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var finishedStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("密码已重设，保险箱已解锁", systemImage: "checkmark.seal.fill")
                .font(.callout)
                .foregroundStyle(.green)

            Text("旧恢复码已失效，请保存新的恢复码：")
                .font(.callout)

            CodeBox(code: newRecoveryCode)

            HStack {
                Spacer()
                Button("完成") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func checkCode() {
        error = nil
        guard !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            error = "请先输入恢复码"
            return
        }
        if vault.validateRecoveryCode(code) {
            step = .setPassword
        } else {
            error = "恢复码无效，请检查后重试"
        }
    }

    private func applyNewPassword() {
        error = nil
        guard !newPassword.isEmpty else {
            error = "新密码不能为空"
            return
        }
        guard newPassword == confirmPassword else {
            error = "两次输入的密码不一致"
            return
        }
        do {
            newRecoveryCode = try vault.resetPassword(recoveryCode: code, newPassword: newPassword)
            step = .finished
        } catch let caughtError {
            error = caughtError.localizedDescription
        }
    }
}

/// 首次设置密码 / 旧版升级后展示恢复码。
struct RecoveryCodeView: View {
    let code: String
    let onDone: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("请保存你的恢复码", systemImage: "key.horizontal.fill")
                .font(.title3.bold())

            Text("忘记密码时，恢复码是找回已加密文件的唯一方式。恢复码只显示这一次，不会保存在本机，丢失后无法找回。")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            CodeBox(code: code)

            Text("建议抄写下来或存进密码管理器。")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Spacer()
                Button("我已保存") { onDone() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 480, alignment: .leading)
    }
}

/// 等宽字体展示的恢复码，支持选中与复制。
struct CodeBox: View {
    let code: String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(code)
                .font(.system(.title3, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 12)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.secondary.opacity(0.35))
                )

            HStack {
                Spacer()
                Button(copied ? "已复制" : "复制恢复码") { copyCode() }
            }
        }
    }

    private func copyCode() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(code, forType: .string)
        copied = true
    }
}

// MARK: - 修改密码

struct ChangePasswordView: View {
    @EnvironmentObject var vault: VaultManager
    @Environment(\.dismiss) private var dismiss
    @State private var oldPwd = ""
    @State private var newPwd = ""
    @State private var confirmPwd = ""
    @State private var errorMsg: String?
    @State private var newRecoveryCode: String?
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let code = newRecoveryCode {
                HStack {
                    Label("密码已修改", systemImage: "checkmark.shield.fill")
                        .font(.title3.bold())
                        .foregroundStyle(.green)
                    Spacer()
                }
                Text("新恢复码如下，请妥善保存，旧恢复码已失效：")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                CodeBox(code: code)
                HStack {
                    Spacer()
                    Button(copied ? "已复制" : "复制恢复码") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(code, forType: .string)
                        copied = true
                    }
                    Button("完成") { dismiss() }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                HStack {
                    Label("修改密码", systemImage: "key.horizontal.fill")
                        .font(.title3.bold())
                    Spacer()
                }
                SecureField("当前密码", text: $oldPwd)
                    .textFieldStyle(.roundedBorder)
                Divider().opacity(0)
                SecureField("新密码", text: $newPwd)
                    .textFieldStyle(.roundedBorder)
                SecureField("确认新密码", text: $confirmPwd)
                    .textFieldStyle(.roundedBorder)
                if let err = errorMsg {
                    Text(err).foregroundStyle(.red).font(.callout)
                }
                HStack {
                    Button("取消") { dismiss() }
                    Spacer()
                    Button("确认修改") { change() }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(oldPwd.isEmpty || newPwd.isEmpty || newPwd != confirmPwd)
                }
            }
        }
        .padding(24)
        .frame(width: 420)
    }

    private func change() {
        guard newPwd == confirmPwd else {
            errorMsg = "两次输入的新密码不一致"
            return
        }
        do {
            let code = try vault.changePassword(oldPassword: oldPwd, newPassword: newPwd)
            newRecoveryCode = code
            vault.pendingRecoveryCode = nil
        } catch {
            errorMsg = error.localizedDescription
        }
    }
}

// MARK: - 保险箱主界面

struct VaultView: View {
    @EnvironmentObject var vault: VaultManager
    @State private var isTargeted = false

    private enum SortKey: String, CaseIterable, Identifiable {
        case category = "分类"
        case addedAt = "时间"
        case size = "大小"

        var id: String { rawValue }
    }

    @State private var sortKey: SortKey = .addedAt
    @State private var ascending = false
    @State private var searchText = ""
    @FocusState private var isSearchFocused: Bool
    @State private var showChangePassword = false
    @State private var showSettings = false
    /// 多选：选中的 entry id（仅在多选模式下使用）
    @State private var selectedIDs = Set<UUID>()
    @State private var multiSelectMode = false
    @State private var idleTimer: Timer?
    @State private var idleMonitor: IdleMonitor?
    /// 自动锁定：用户设置的空闲分钟数，0 表示关闭
    @AppStorage("autoLockMinutes") private var autoLockMinutes: Int = 0

    var body: some View {
        VStack(spacing: 0) {
            header
            if !vault.entries.isEmpty {
                searchAndSortBar
            }
            if multiSelectMode && !selectedIDs.isEmpty {
                selectionBar
            }
            Divider()
            content
        }
        .onAppear { startIdleMonitor() }
        .onDisappear { stopIdleMonitor() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            resetIdleTimer()
        }
        .onChange(of: vault.isUnlocked) { unlocked in
            if unlocked { resetIdleTimer() } else { stopIdleMonitor() }
        }
        .sheet(isPresented: $showChangePassword) {
            ChangePasswordView()
                .environmentObject(vault)
        }
        .background(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(
                    isTargeted ? Color.blue : Color.gray.opacity(0.35),
                    style: StrokeStyle(lineWidth: 2, dash: isTargeted ? [] : [8, 6])
                )
                .padding(10)
        )
        .onDrop(of: [.fileURL], delegate: FileDropDelegate(isTargeted: $isTargeted) { urls in
            vault.addItems(urls: urls)
        })
        .overlay {
            if vault.isBusy {
                ProgressView("处理中…")
                    .padding(20)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    private var header: some View {
        HStack {
            Label("文件保险箱", systemImage: "lock.shield.fill")
                .font(.title3.bold())

            Spacer()

            Text("\(multiSelectMode && !selectedIDs.isEmpty ? "已选 \(selectedIDs.count) / " : "")\(vault.entries.count) 项")
                .foregroundStyle(.secondary)

            if !multiSelectMode {
                Button {
                    multiSelectMode = true
                } label: {
                    Image(systemName: "checkmark.circle")
                }
                .help("多选模式")
            } else {
                Button {
                    multiSelectMode = false
                    selectedIDs.removeAll()
                } label: {
                    Text("完成")
                }
                .help("退出多选")
            }

            Menu {
                Button {
                    showChangePassword = true
                } label: {
                    Label("修改密码", systemImage: "key")
                }
                Divider()
                Menu("自动锁定") {
                    Button("关闭", action: { autoLockMinutes = 0 })
                    ForEach([1, 3, 5, 10, 30], id: \.self) { m in
                        Button("\(m) 分钟", action: { autoLockMinutes = m })
                    }
                }
            } label: {
                Image(systemName: "gearshape")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("设置")

            Button {
                vault.lock()
            } label: {
                Label("锁定", systemImage: "lock")
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var searchAndSortBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("搜索文件", text: $searchText)
                    .textFieldStyle(.plain)
                    .focused($isSearchFocused)
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))

            HStack(spacing: 8) {
                Text("排序")
                    .font(.callout)
                    .foregroundStyle(.secondary)

                Picker("排序", selection: $sortKey) {
                    ForEach(SortKey.allCases) { key in
                        Text(key.rawValue).tag(key)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()

                Button {
                    ascending.toggle()
                } label: {
                    Image(systemName: ascending ? "arrow.up" : "arrow.down")
                }
                .buttonStyle(.borderless)
                .help(ascending ? "升序（点击切换为降序）" : "降序（点击切换为升序）")

                Spacer()
            }
        }
        .padding(.horizontal, 20)
        .padding(.bottom, 10)
    }

    private var selectionBar: some View {
        HStack(spacing: 10) {
            Button(role: .destructive) {
                for id in selectedIDs {
                    if let e = vault.entries.first(where: { $0.id == id }) {
                        vault.delete(e)
                    }
                }
                selectedIDs.removeAll()
                multiSelectMode = false
            } label: {
                Label("删除", systemImage: "trash")
            }

            Button {
                // 批量导出：全部导出到一个选择的目录
                let panel = NSOpenPanel()
                panel.canChooseFiles = false
                panel.canChooseDirectories = true
                panel.canCreateDirectories = true
                panel.prompt = "导出到这里"
                panel.message = "选择导出位置，所有选中文件将被导出到该文件夹。"
                if panel.runModal() == .OK, let dir = panel.url {
                    for id in selectedIDs {
                        guard let e = vault.entries.first(where: { $0.id == id }) else { continue }
                        vault.export(e, to: dir.appendingPathComponent(e.name))
                    }
                    selectedIDs.removeAll()
                    multiSelectMode = false
                }
            } label: {
                Label("导出", systemImage: "square.and.arrow.up")
            }

            Spacer()

            Button {
                selectedIDs.removeAll()
            } label: {
                Text("取消选择")
            }
            .buttonStyle(.borderless)
        }
        .padding(.horizontal, 20)
        .padding(.bottom, 8)
    }

    private func resetIdleTimer() {
        idleTimer?.invalidate()
        guard autoLockMinutes > 0, vault.isUnlocked else { return }
        idleTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(autoLockMinutes * 60), repeats: false) { _ in
            DispatchQueue.main.async { vault.lock() }
        }
    }

    private func startIdleMonitor() {
        stopIdleMonitor()
        guard autoLockMinutes > 0, vault.isUnlocked else { return }
        idleMonitor = IdleMonitor(onActivity: { [self] in
            resetIdleTimer()
        }, onIdle: { [weak vault] in
            DispatchQueue.main.async { vault?.lock() }
        })
        // 把超时时间告诉 monitor（通过通知或直接设置）：这里用事件回调自己 reset 即可。
        resetIdleTimer()
    }

    private func stopIdleMonitor() {
        idleTimer?.invalidate()
        idleTimer = nil
        idleMonitor = nil
    }

    private var filteredEntries: [VaultEntry] {
        let q = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if q.isEmpty { return vault.entries }
        return vault.entries.filter { $0.name.localizedCaseInsensitiveContains(q) }
    }

    private var sortedEntries: [VaultEntry] {
        let items = filteredEntries.sorted { lhs, rhs in
            switch sortKey {
            case .category:
                let a = FileCategory(entry: lhs)
                let b = FileCategory(entry: rhs)
                if a != b { return a.sortIndex < b.sortIndex }
                return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
            case .addedAt:
                return lhs.addedAt < rhs.addedAt
            case .size:
                return lhs.size < rhs.size
            }
        }
        return ascending ? items : Array(items.reversed())
    }

    private var content: some View {
        ZStack {
            if vault.entries.isEmpty {
                emptyState
            } else if sortedEntries.isEmpty {
                noResultsState
            } else {
                fileList
            }
        }
        .padding(.horizontal, 12)
        .padding(.bottom, 14)
    }

    private var noResultsState: some View {
        VStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text("没有找到匹配的文件")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var fileList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(sortedEntries) { entry in
                    EntryRow(entry: entry, showCheckbox: multiSelectMode, selectedIDs: $selectedIDs)
                        .background(Color(nsColor: .controlBackgroundColor))
                        .contentShape(Rectangle())
                        .contextMenu {
                            Button { vault.open(entry) } label: { Label("打开", systemImage: "eye") }
                            Button { vault.export(entry) } label: { Label("导出…", systemImage: "square.and.arrow.up") }
                            Button { vault.restore(entry) } label: { Label("还原到原位置", systemImage: "arrow.uturn.backward") }
                            Divider()
                            Button(role: .destructive) { vault.delete(entry) } label: { Label("删除", systemImage: "trash") }
                        }
                    Divider().padding(.leading, 40)
                }
            }
            .padding(.vertical, 4)
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "tray.and.arrow.down.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)

            Text("将文件或文件夹拖拽到这里")
                .font(.title3.weight(.medium))

            Text("文件会被加密后保存在本机，原文件移入废纸篓。")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - 文件分类

enum FileCategory: Int, CaseIterable {
    case folder
    case image
    case document
    case archive
    case media
    case other

    var sortIndex: Int { rawValue }

    var title: String {
        switch self {
        case .folder: return "文件夹"
        case .image: return "图片"
        case .document: return "文档"
        case .archive: return "压缩包"
        case .media: return "音视频"
        case .other: return "其他"
        }
    }

    init(entry: VaultEntry) {
        if entry.kind == .folder {
            self = .folder
            return
        }

        let ext = (entry.name as NSString).pathExtension.lowercased()
        switch ext {
        case "png", "jpg", "jpeg", "gif", "webp", "heic", "heif", "tiff", "bmp", "svg", "ico":
            self = .image
        case "pdf", "doc", "docx", "txt", "md", "rtf", "pages", "xls", "xlsx", "numbers",
             "ppt", "pptx", "key", "html", "htm", "css", "js", "json", "xml", "csv":
            self = .document
        case "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "dmg", "iso":
            self = .archive
        case "mp4", "mov", "m4v", "avi", "mkv", "mp3", "wav", "m4a", "aac", "flac":
            self = .media
        default:
            self = .other
        }
    }
}

// MARK: - 列表项

struct EntryRow: View {
    let entry: VaultEntry
    let showCheckbox: Bool
    @Binding var selectedIDs: Set<UUID>
    @EnvironmentObject var vault: VaultManager
    @State private var showDeleteConfirm = false
    @State private var hovering = false

    init(entry: VaultEntry, showCheckbox: Bool = false, selectedIDs: Binding<Set<UUID>> = .constant([])) {
        self.entry = entry
        self.showCheckbox = showCheckbox
        self._selectedIDs = selectedIDs
    }

    private var isSelected: Bool { selectedIDs.contains(entry.id) }

    var body: some View {
        HStack(spacing: 12) {
            if showCheckbox {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isSelected ? .blue : .secondary)
                    .font(.title3)
                    .onTapGesture {
                        if isSelected { selectedIDs.remove(entry.id) }
                        else { selectedIDs.insert(entry.id) }
                    }
            }

            Image(systemName: entry.kind == .folder ? "folder.fill" : "doc.fill")
                .font(.title3)
                .foregroundStyle(entry.kind == .folder ? .blue : .gray)

            VStack(alignment: .leading, spacing: 3) {
                Text(entry.name)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text("\(FileCategory(entry: entry).title) · \(formattedSize) · \(formattedDate)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            HStack(spacing: 10) {
                rowButton("还原到原位置", systemImage: "arrow.uturn.backward", tint: .blue) {
                    vault.restore(entry)
                }
                rowButton("打开", systemImage: "eye") { vault.open(entry) }
                rowButton("导出", systemImage: "square.and.arrow.up") { vault.export(entry) }
                rowButton("删除", systemImage: "trash", tint: .red) { showDeleteConfirm = true }
            }
            .opacity(hovering ? 1 : 0.65)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(
                    isSelected ? Color.blue.opacity(0.15)
                    : hovering ? Color.primary.opacity(0.06)
                    : Color.clear
                )
        )
        .padding(.horizontal, 4)
        .onHover { hovering = $0 }
        .onDrag {
            guard let url = vault.temporaryExportURL(for: entry) else { return NSItemProvider() }
            return NSItemProvider(contentsOf: url) ?? NSItemProvider()
        }
        .help("可直接拖到 Finder 或其他位置导出")
        .alert("确定删除「\(entry.name)」？", isPresented: $showDeleteConfirm) {
            Button("取消", role: .cancel) {}
            Button("移入废纸篓", role: .destructive) { vault.delete(entry) }
        } message: {
            Text("该文件会从保险箱中移出，并放入废纸篓，可随时从废纸篓恢复。")
        }
    }

    private func rowButton(_ title: String, systemImage: String, tint: Color = .secondary, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .labelStyle(.iconOnly)
        }
        .buttonStyle(.borderless)
        .help(title)
        .foregroundStyle(tint)
    }

    private var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: Int64(entry.size), countStyle: .file)
    }

    private var formattedDate: String {
        entry.addedAt.formatted(date: .abbreviated, time: .shortened)
    }
}

// MARK: - 拖拽

struct FileDropDelegate: DropDelegate {
    @Binding var isTargeted: Bool
    let onDrop: ([URL]) -> Void

    func dropEntered(info: DropInfo) {
        isTargeted = true
    }

    func dropExited(info: DropInfo) {
        isTargeted = false
    }

    func performDrop(info: DropInfo) -> Bool {
        isTargeted = false
        let providers = info.itemProviders(for: [UTType.fileURL])
        guard !providers.isEmpty else { return false }

        var urls: [URL] = []
        let group = DispatchGroup()

        for provider in providers {
            group.enter()
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
                if let data = item as? Data,
                   let url = URL(dataRepresentation: data, relativeTo: nil) {
                    urls.append(url)
                } else if let url = item as? URL {
                    urls.append(url)
                }
                group.leave()
            }
        }

        group.notify(queue: .main) {
            onDrop(urls)
        }
        return true
    }
}

// MARK: - 空闲监控

/// 监听本应用内的鼠标/键盘活动，触发回调，用于空闲自动锁定。
/// 实际超时计时由调用方通过 Timer 控制，这里只负责「有活动就重置」。
final class IdleMonitor {
    private var monitor: Any?
    let onActivity: () -> Void
    let onIdle: () -> Void

    init(onActivity: @escaping () -> Void, onIdle: @escaping () -> Void) {
        self.onActivity = onActivity
        self.onIdle = onIdle
        monitor = NSEvent.addLocalMonitorForEvents(
            matching: [.mouseMoved, .leftMouseDown, .rightMouseDown, .keyDown, .scrollWheel]
        ) { [weak self] event in
            self?.onActivity()
            return event
        }
    }

    deinit {
        if let m = monitor {
            NSEvent.removeMonitor(m)
        }
    }
}
