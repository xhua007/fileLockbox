import SwiftUI

@main
struct FileLockerApp: App {
    @StateObject private var vault = VaultManager()

    var body: some Scene {
        WindowGroup("文件保险箱") {
            ContentView()
                .environmentObject(vault)
                .frame(minWidth: 640, minHeight: 480)
        }
        .windowResizability(.contentMinSize)
    }
}
