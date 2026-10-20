// swift-tools-version: 6.0
import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment
let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let defaultVendor = packageDirectory
    .appendingPathComponent("../../../../vivy-company/vvterm/Vendor/libssh2")
    .standardizedFileURL.path
let vendor = environment["TELEPORT_LIBSSH2_ROOT"] ?? defaultVendor
let headers = environment["TELEPORT_LIBSSH2_INCLUDE"] ?? "\(vendor)/include"
let sshLibrary = environment["TELEPORT_LIBSSH2_LIBRARY"] ?? "\(vendor)/macos/lib/libssh2.a"
let cryptoLibrary = environment["TELEPORT_LIBCRYPTO_LIBRARY"] ?? "\(vendor)/macos/lib/libcrypto.a"
let sslLibrary = environment["TELEPORT_LIBSSL_LIBRARY"] ?? "\(vendor)/macos/lib/libssl.a"

let package = Package(
    name: "TeleportE2E",
    platforms: [.macOS("13.3")],
    products: [.executable(name: "TeleportE2E", targets: ["TeleportE2E"])],
    dependencies: [.package(name: "swift-teleport", path: "../..")],
    targets: [
        .target(
            name: "CTeleportSSHEngine",
            path: ".",
            exclude: ["Sources", "build-engine.sh", "run-engine-proof.sh",
                      "build-apple-engines.sh",
                      "engine-tests.py", "engine-proof.c", "host-import-tests.c",
                      "failed-setup-cleanup-test.c", "adapter-input-tests.c"],
            sources: ["TeleportSSHEngine.c"],
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-I", headers])],
            linkerSettings: [
                .unsafeFlags([sshLibrary, sslLibrary, cryptoLibrary]),
                .linkedLibrary("z")
            ]
        ),
        .executableTarget(
            name: "TeleportE2E",
            dependencies: [
                "CTeleportSSHEngine",
                .product(name: "TeleportKit", package: "swift-teleport")
            ],
            path: "Sources/TeleportE2E"
        )
    ]
)
