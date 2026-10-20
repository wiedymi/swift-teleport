import SwiftUI
import CryptoKit
import TeleportKit

private struct SmokeConfig: Decodable, Sendable {
    struct Credentials: Decodable, Sendable { let username: String; let password: String; let totpSeed: String }
    struct Node: Decodable, Sendable { let name: String; let id: String; let authorized: Bool }
    let proxyURL: URL
    let clusterName: String
    let serverVersion: String
    let httpsCA: Data
    let credentials: Credentials
    let nodes: [Node]
}

@main struct TeleportSmokeApp: App {
    @StateObject private var report = SmokeReport()
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Native Teleport test").font(.title2)
                        Text("The app uses the package API and the test SSH adapter.").font(.subheadline)
                        ForEach(Array(report.lines.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        }
                        Button(report.isRunning ? "Test is running" : "Run test") { Task { await report.run() } }
                            .buttonStyle(.borderedProminent).disabled(report.isRunning)
                    }.frame(maxWidth: .infinity, alignment: .leading).padding()
                }.navigationTitle("Teleport Smoke")
                    .task {
                        if ProcessInfo.processInfo.arguments.contains("--run-smoke") { await report.run() }
                    }
            }
        }
    }
}

@MainActor private final class SmokeReport: ObservableObject {
    private enum State { case waiting, running([String]), finished([String]) }
    @Published private var state = State.waiting
    var isRunning: Bool { if case .running = state { true } else { false } }
    var lines: [String] {
        switch state { case .waiting: ["Ready."]; case .running(let lines), .finished(let lines): lines }
    }
    func run() async {
        guard !isRunning else { return }
        state = .running(["Test started."])
        do {
            guard let url = Bundle.main.url(forResource: "SmokeConfig", withExtension: "json"),
                  (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= 1_048_576 else { throw SmokeFailure("Add the ignored SmokeConfig.json file before building.") }
            let config = try JSONDecoder().decode(SmokeConfig.self, from: Data(contentsOf: url))
            try await SmokeRunner.run(config) { line in await self.append(line) }
            state = .finished(lines + ["PASS all native checks"])
        } catch {
            let safe: String
            if let error = error as? TeleportError { safe = error.description }
            else if let error = error as? SmokeFailure { safe = error.message }
            else { let error = error as NSError; safe = "Native error code \(error.code)." }
            state = .finished(lines + ["FAIL " + safe])
        }
        let text = lines.joined(separator: "\n") + "\n"
        if let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            try? Data(text.utf8).write(to: directory.appendingPathComponent("smoke-report.txt"), options: .atomic)
        }
    }
    private func append(_ line: String) { state = .running(lines + [line]) }
}

private struct SmokeFailure: Error { let message: String; init(_ message: String) { self.message = message } }
private struct CommandResult: Sendable { let code: Int; let output: Data; let exitStatus: Int32 }
private final class HostCheck: @unchecked Sendable {
    let connection: TeleportConnection
    init(_ connection: TeleportConnection) { self.connection = connection }
}
private let verifyHost: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?) -> Int32 = { bytes, length, context in
    guard let bytes, let context, (1...262_144).contains(length) else { return 1 }
    let check = Unmanaged<HostCheck>.fromOpaque(context).takeUnretainedValue()
    do { try check.connection.verifyHostCertificate(Data(bytes: bytes, count: length)); return 0 }
    catch { return 1 }
}

private enum SmokeRunner {
    static func run(_ config: SmokeConfig, report: @escaping @Sendable (String) async -> Void) async throws {
        let proxy = try TeleportProxy(url: config.proxyURL, httpsCACertificatesDER: [config.httpsCA])
        let client = TeleportClient(proxy: proxy)
        let discovery = try await client.discover()
        try require(discovery.clusterName == config.clusterName && discovery.serverVersion == config.serverVersion, "Discovery did not match the fixture.")
        await report("PASS HTTPS discovery")
        let code = try totp(config.credentials.totpSeed)
        async let first = client.login(username: config.credentials.username, password: config.credentials.password, otp: code)
        async let second = client.login(username: config.credentials.username, password: config.credentials.password, otp: code)
        let (a, b) = try await (first, second)
        try require(a.tlsCertificateDER == b.tlsCertificateDER && a.isUsable(), "Concurrent login did not share one identity.")
        await report("PASS TOTP login, shared identity, and certificate validation")
        try require(!a.tlsCACertificatesDER.isEmpty && !a.tlsCACertificatesDER.contains(config.httpsCA), "The fixture must use different public HTTPS and internal TLS CAs.")
        let wrongProxy = try TeleportProxy(url: config.proxyURL, httpsCACertificatesDER: a.tlsCACertificatesDER)
        do {
            _ = try await TeleportClient(proxy: wrongProxy).discover()
            throw SmokeFailure("The wrong HTTPS CA was accepted.")
        } catch let error as URLError where error.code == .cancelled {
            await report("PASS rejected wrong HTTPS CA")
        }
        let nodes = try await client.nodes().nodes
        try require(Set(nodes.map(\.id)) == Set(config.nodes.filter(\.authorized).map(\.id)), "Node permissions did not match the fixture.")
        await report("PASS mTLS node lookup and role filtering")
        guard let node = nodes.first else { throw SmokeFailure("No allowed node is available.") }
        let connection = try await client.connect(to: node, login: "teleport-test")
        let commandResult = try await command(connection, command: "printf APPLE_SMOKE_OK; exit 7")
        await connection.close()
        try require(commandResult.code == 0 && commandResult.exitStatus == 7 && commandResult.output == Data("APPLE_SMOKE_OK".utf8), "SSH stdout or exit status failed.")
        let errorConnection = try await client.connect(to: node, login: "teleport-test")
        let errorResult = try await command(errorConnection, command: "printf APPLE_STDERR >&2; exit 9")
        await errorConnection.close()
        try require(errorResult.code == 0 && errorResult.exitStatus == 9 && errorResult.output == Data("APPLE_STDERR".utf8), "SSH stderr or exit status failed.")
        await report("PASS ProxySSH, host CA, user certificate, stdout, stderr, and exit status")
        let terminal = try await client.connect(to: node, login: "teleport-test")
        let terminalResult = try await command(terminal, command: "sh -c 'test \"$(stty size)\" = \"24 80\" || exit 99; trap \"stty size; exit\" WINCH; printf \"<teleport-pty-ready>\"; while :; do read -r ignored; done'", operation: TELEPORT_SSH_PTY_RESIZE)
        await terminal.close()
        try require(terminalResult.code == 0 && String(decoding: terminalResult.output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == "43 121", "PTY resize failed.")
        await report("PASS PTY and resize")
        let file = try await client.connect(to: node, login: "teleport-test")
        let payload = Data((0..<262_144).map { UInt8($0 & 255) })
        let fileResult = try await command(file, command: "", operation: TELEPORT_SSH_SFTP_ROUNDTRIP, input: payload, path: "/tmp/teleport-apple-" + UUID().uuidString)
        await file.close()
        try require(fileResult.code == 0 && fileResult.output == payload, "SFTP data check failed.")
        await report("PASS SFTP upload, download, and file cleanup")
        try await client.signOut()
        await report("PASS local sign-out")
    }

    private static func require(_ condition: Bool, _ message: String) throws { if !condition { throw SmokeFailure(message) } }
    private static func totp(_ seed: String) throws -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var key = Data(), accumulator: UInt32 = 0, bits = 0
        for character in seed.uppercased().utf8 where character != 61 {
            guard let digit = alphabet.firstIndex(of: character) else { throw SmokeFailure("Invalid test TOTP seed.") }
            accumulator = (accumulator << 5) | UInt32(digit); bits += 5
            if bits >= 8 { bits -= 8; key.append(UInt8((accumulator >> bits) & 255)); accumulator &= (1 << bits) - 1 }
        }
        guard !key.isEmpty else { throw SmokeFailure("Empty test TOTP seed.") }
        var counter = UInt64(Date().timeIntervalSince1970 / 30).bigEndian
        let digest = withUnsafeBytes(of: &counter) { Array(HMAC<Insecure.SHA1>.authenticationCode(for: Data($0), using: SymmetricKey(data: key))) }
        let offset = Int(digest.last! & 15)
        let value = ((UInt32(digest[offset]) & 127) << 24) | (UInt32(digest[offset + 1]) << 16) | (UInt32(digest[offset + 2]) << 8) | UInt32(digest[offset + 3])
        return String(format: "%06u", value % 1_000_000)
    }

    private static func command(_ connection: TeleportConnection, command: String, operation: TeleportSSHOperation = TELEPORT_SSH_EXEC,
                                input: Data = Data(), path: String = "") async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let descriptor = try connection.takeSocketDescriptor(), check = HostCheck(connection)
                    var output = [UInt8](repeating: 0, count: 1_048_576), length = 0, exitStatus: Int32 = -1, native: Int32 = 0
                    let status = connection.login.withCString { login in
                        connection.sshCertificateOpenSSH.withCString { certificate in
                            connection.sshPrivateKeyPEM.withCString { key in
                                command.withCString { command in
                                    path.withCString { path in
                                        input.withUnsafeBytes { input in
                                            var request = TeleportSSHCommand()
                                            request.operation = operation; request.username = login
                                            request.user_certificate = certificate; request.user_certificate_length = strlen(certificate)
                                            request.private_key = key; request.private_key_length = strlen(key)
                                            request.command = command; request.sftp_path = path
                                            request.input = input.bindMemory(to: UInt8.self).baseAddress; request.input_length = input.count
                                            request.timeout_milliseconds = 20_000
                                            request.verify_host = verifyHost; request.verify_context = Unmanaged.passUnretained(check).toOpaque()
                                            return withExtendedLifetime(check) {
                                                teleport_ssh_run_command(descriptor, &request, &output, 1_048_576, &length, &exitStatus, &native)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continuation.resume(returning: CommandResult(code: Int(status.rawValue), output: Data(output.prefix(length)), exitStatus: exitStatus))
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}
