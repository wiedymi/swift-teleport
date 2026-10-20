// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "swift-teleport",
    platforms: [.iOS("16.1"), .macOS("13.3")],
    products: [
        .library(name: "TeleportKit", targets: ["TeleportKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.104.0"),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.46.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.28.0"),
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.39.0"),
    ],
    targets: [
        .target(name: "TeleportCore"),
        .target(name: "TeleportKit", dependencies: [
            "TeleportCore",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOFoundationCompat", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOHTTP1", package: "swift-nio"),
            .product(name: "NIOTLS", package: "swift-nio"),
            .product(name: "NIOHTTP2", package: "swift-nio-http2"),
            .product(name: "NIOHPACK", package: "swift-nio-http2"),
            .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
            .product(name: "SwiftProtobuf", package: "swift-protobuf"),
        ]),
        .testTarget(name: "TeleportCoreTests", dependencies: ["TeleportCore"]),
        .testTarget(name: "TeleportKitTests", dependencies: [
            "TeleportKit",
            .product(name: "NIOEmbedded", package: "swift-nio"),
            .product(name: "NIOHTTP2", package: "swift-nio-http2"),
            .product(name: "NIOHPACK", package: "swift-nio-http2"),
        ]),
    ],
    swiftLanguageModes: [.v6]
)
