// swift-tools-version: 6.0
import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment
let engineRoot = environment["TELEPORT_LIBSSH2_ROOT"]
guard let headers = environment["TELEPORT_LIBSSH2_INCLUDE"] ?? engineRoot.map({ "\($0)/include" }),
      let sshLibrary = environment["TELEPORT_LIBSSH2_LIBRARY"] ?? engineRoot.map({ "\($0)/lib/libssh2.a" }) else {
    fatalError("Supply a compatible upstream engine with TELEPORT_LIBSSH2_ROOT, or both TELEPORT_LIBSSH2_INCLUDE and TELEPORT_LIBSSH2_LIBRARY.")
}
guard let cryptoLibrary = environment["TELEPORT_LIBCRYPTO_LIBRARY"] else {
    fatalError("Supply the matching static OpenSSL archive with TELEPORT_LIBCRYPTO_LIBRARY.")
}

let package = Package(
    name: "TeleportE2E",
    platforms: [.macOS("13.3")],
    products: [.executable(name: "TeleportE2E", targets: ["TeleportE2E"])],
    dependencies: [.package(name: "swift-teleport", path: "../..")],
    targets: [
        .target(
            name: "CTeleportSSHEngine",
            path: ".",
            exclude: ["Sources", "run-engine-proof.sh", "engine-tests.py",
                      "engine-proof.c", "adapter-input-tests.c"],
            sources: ["TeleportSSHEngine.c"],
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-I", headers])],
            linkerSettings: [
                .unsafeFlags([sshLibrary, cryptoLibrary]),
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
