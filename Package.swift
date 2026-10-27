// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "FileLocker",
    platforms: [
        .macOS(.v13)
    ],
    targets: [
        .executableTarget(
            name: "FileLocker",
            path: "Sources/FileLocker"
        )
    ]
)
