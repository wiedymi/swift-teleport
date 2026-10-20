import Foundation
import CryptoKit
import TeleportKit
import CTeleportSSHEngine

struct Fixture: Decodable, Sendable {
    struct Node: Decodable, Sendable { let name: String; let id: String; let authorized: Bool }
    let schemaVersion: Int
    let proxyURL: URL
    let clusterName: String
    let serverVersion: String
    let httpsCAFile: String
    let nodes: [Node]
    let localCredentialsFile: String?
}
struct LocalCredentials: Decodable { let username: String; let password: String; let totpSeed: String }
struct HarnessFailure: Error, CustomStringConvertible { let description: String }
struct SSHResult: Sendable { let code: Int; let output: Data; let exit: Int32; let native: Int32 }
final class HostVerifier: @unchecked Sendable {
    let connection: TeleportConnection
    let reject: Bool
    init(_ connection: TeleportConnection, reject: Bool) { self.connection = connection; self.reject = reject }
}
let verifier: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?) -> Int32 = { bytes, length, context in
    guard let bytes, let context, length > 0, length <= 262_144 else { return 1 }
    let check = Unmanaged<HostVerifier>.fromOpaque(context).takeUnretainedValue()
    if check.reject { return 1 }
    do { try check.connection.verifyHostCertificate(Data(bytes: bytes, count: length)); return 0 }
    catch {
        FileHandle.standardError.write(Data("Host certificate check failed: \(error)\n".utf8))
        return 1
    }
}

func readFile(_ path: String, maximum: Int = 4_194_304) throws -> Data {
    let url = URL(fileURLWithPath: path)
    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
    guard size <= maximum else { throw HarnessFailure(description: "Fixture exceeds the file limit") }
    return try Data(contentsOf: url)
}
func pem(_ data: Data, label: String) throws -> Data {
    guard let text = String(data: data, encoding: .utf8),
          let start = text.range(of: "-----BEGIN \(label)-----"),
          let end = text.range(of: "-----END \(label)-----", range: start.upperBound..<text.endIndex),
          let value = Data(base64Encoded: text[start.upperBound..<end.lowerBound].filter { !$0.isWhitespace }) else {
        throw HarnessFailure(description: "Invalid PEM fixture")
    }
    return value
}
func totp(_ seed: String) throws -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
    var key = Data(), accumulator: UInt32 = 0, bits = 0
    for char in seed.uppercased().utf8 where char != 61 {
        guard let digit = alphabet.firstIndex(of: char) else { throw HarnessFailure(description: "Invalid TOTP fixture") }
        accumulator = (accumulator << 5) | UInt32(digit); bits += 5
        if bits >= 8 { bits -= 8; key.append(UInt8((accumulator >> bits) & 255)); accumulator &= (1 << bits) - 1 }
    }
    var counter = UInt64(Date().timeIntervalSince1970 / 30).bigEndian
    let message = withUnsafeBytes(of: &counter) { Data($0) }
    let digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    let offset = Int(digest.last! & 15)
    let value = ((UInt32(digest[offset]) & 127) << 24) | (UInt32(digest[offset + 1]) << 16) | (UInt32(digest[offset + 2]) << 8) | UInt32(digest[offset + 3])
    return String(format: "%06u", value % 1_000_000)
}
func runSSH(_ connection: TeleportConnection, command: String, rejectHost: Bool = false,
            operation: TeleportSSHOperation = TELEPORT_SSH_EXEC, input: Data = Data(), sftpPath: String = "") async throws -> SSHResult {
    try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let fd = try connection.takeSocketDescriptor()
                let hostCheck = HostVerifier(connection, reject: rejectHost)
                var output = [UInt8](repeating: 0, count: 2_097_152)
                var length = 0, exit: Int32 = -1, native: Int32 = 0
                let status = connection.login.withCString { user in
                    connection.sshCertificateOpenSSH.withCString { certificate in
                        connection.sshPrivateKeyPEM.withCString { key in
                            command.withCString { command in
                                return sftpPath.withCString { path in
                                  input.withUnsafeBytes { inputBytes in
                                var request = TeleportSSHCommand()
                                request.operation = operation
                                request.sftp_path = path
                                request.input = inputBytes.bindMemory(to: UInt8.self).baseAddress
                                request.input_length = input.count
                                request.username = user
                                request.user_certificate = certificate
                                request.user_certificate_length = strlen(certificate)
                                request.private_key = key
                                request.private_key_length = strlen(key)
                                request.command = command
                                request.timeout_milliseconds = 20_000
                                request.verify_host = verifier
                                request.verify_context = Unmanaged.passUnretained(hostCheck).toOpaque()
                                return withExtendedLifetime(hostCheck) {
                                    teleport_ssh_run_command(fd, &request, &output, 2_097_152, &length, &exit, &native)
                                }
                                  }
                                }
                            }
                        }
                    }
                }
                continuation.resume(returning: SSHResult(code: Int(status.rawValue), output: Data(output.prefix(length)), exit: exit, native: native))
            } catch { continuation.resume(throwing: error) }
        }
    }
}
func require(_ condition: Bool, _ message: String) throws {
    guard condition else { throw HarnessFailure(description: message) }
}

@main struct Main {
    static func main() async {
        do { try await run() }
        catch { FileHandle.standardError.write(Data("Native test failed: \(error)\n".utf8)); Foundation.exit(1) }
    }
    static func run() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let fixturePath = env["TELEPORT_E2E_FIXTURE"] else { throw HarnessFailure(description: "Set TELEPORT_E2E_FIXTURE") }
        let fixture = try JSONDecoder().decode(Fixture.self, from: readFile(fixturePath))
        try require(fixture.schemaVersion == 1, "Unsupported fixture version")
        let ca = try pem(readFile(fixture.httpsCAFile), label: "CERTIFICATE")
        let proxy = try TeleportProxy(url: fixture.proxyURL, httpsCACertificatesDER: [ca])
        let store = MemoryIdentityStore()
        let client = TeleportClient(proxy: proxy, identityStore: store)
        let discovery = try await client.discover()
        try require(discovery.clusterName == fixture.clusterName && discovery.serverVersion == fixture.serverVersion,
                    "Discovery did not match the pinned fixture")
        print("PASS native HTTPS discovery")
        if CommandLine.arguments.dropFirst().first == "discover" { return }
        guard let credentialsPath = fixture.localCredentialsFile else { throw HarnessFailure(description: "The native suite needs a real enrolled local user") }
        let credentials = try JSONDecoder().decode(LocalCredentials.self, from: readFile(credentialsPath))
        let start = ContinuousClock.now
        let identity: TeleportIdentity
        if CommandLine.arguments.contains("--reuse-identity") {
            guard let path = env["TELEPORT_E2E_IDENTITY_FILE"] else { throw HarnessFailure(description: "Set the explicit identity file for transport probes") }
            identity = try JSONDecoder().decode(TeleportIdentity.self, from: readFile(path))
            try require(identity.proxy == proxy && identity.isUsable(), "Stored test identity")
            await store.replace(with: identity)
            print("PASS validated native identity import (login not run)")
        } else {
            let code = try totp(credentials.totpSeed)
            async let firstLogin = client.login(username: credentials.username, password: credentials.password, otp: code)
            async let secondLogin = client.login(username: credentials.username, password: credentials.password, otp: code)
            let shared = try await (firstLogin, secondLogin)
            try require(shared.0.tlsCertificateDER == shared.1.tlsCertificateDER, "Two tabs did not share one login")
            identity = shared.0
            print("PASS native password/TOTP login, certificate validation, and two shared callers (\(start.duration(to: .now)))")
            if let path = env["TELEPORT_E2E_IDENTITY_FILE"] {
                let data = try JSONEncoder().encode(identity)
                guard FileManager.default.createFile(atPath: path, contents: data, attributes: [.posixPermissions: 0o600]) else {
                    throw HarnessFailure(description: "Cannot save the private native test record")
                }
            }
        }
        try require(identity.isUsable() && identity.clusterName == fixture.clusterName && identity.allowedLogins.contains("vvterm-test"), "Issued identity validation")
        // This roundtrip verifies the public atomic-store record, not tctl output.
        let decoded = try JSONDecoder().decode(TeleportIdentity.self, from: JSONEncoder().encode(identity))
        try require(decoded.tlsCertificateDER == identity.tlsCertificateDER, "Identity storage roundtrip")
        await store.replace(with: decoded)
        if CommandLine.arguments.dropFirst().first == "login" { return }
        let nodes = try await client.nodes().nodes
        let allowed = fixture.nodes.filter(\.authorized)
        try require(nodes.count == allowed.count && Set(nodes.map(\.id)) == Set(allowed.map(\.id)), "Restricted node list")
        print("PASS native mTLS node discovery and role filtering")
        if CommandLine.arguments.contains("benchmark") {
            guard let node = nodes.first else { throw HarnessFailure(description: "No benchmark node") }
            try await runBenchmarks(client: client, node: node)
            return
        }
        for fixtureNode in allowed {
            guard let node = nodes.first(where: { $0.id == fixtureNode.id }) else { throw HarnessFailure(description: "Expected node missing") }
            let connection = try await client.connect(to: node, login: "vvterm-test")
            let result = try await runSSH(connection, command: "printf VVTERM_NATIVE_OK; exit 7")
            await connection.close()
            try require(result.code == 0 && result.exit == 7 && result.output == Data("VVTERM_NATIVE_OK".utf8),
                        "SSH command failed (result \(result.code), native \(result.native), exit \(result.exit))")
            let errorConnection = try await client.connect(to: node, login: "vvterm-test")
            let errorResult = try await runSSH(errorConnection, command: "printf VVTERM_STDERR >&2; exit 9")
            await errorConnection.close()
            try require(errorResult.code == 0 && errorResult.exit == 9 && errorResult.output == Data("VVTERM_STDERR".utf8),
                        "SSH stderr command failed (result \(errorResult.code), native \(errorResult.native), exit \(errorResult.exit))")
            print("PASS native ProxySSH, host CA, user certificate, command, stderr and exit status: \(fixtureNode.name)")
        }
        guard let node = nodes.first else { throw HarnessFailure(description: "No allowed node") }
        let terminal = try await client.connect(to: node, login: "vvterm-test")
        let pty = try await runSSH(terminal, command: "sh -c 'test \"$(stty size)\" = \"24 80\" || exit 99; trap \"stty size; exit\" WINCH; printf \"<teleport-pty-ready>\"; while :; do read -r ignored; done'", operation: TELEPORT_SSH_PTY_RESIZE)
        await terminal.close()
        try require(pty.code == 0 && String(decoding: pty.output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == "43 121", "PTY resize (result \(pty.code), native \(pty.native), output \(String(reflecting: String(decoding: pty.output, as: UTF8.self))))")
        print("PASS native PTY and resize")
        let fileConnection = try await client.connect(to: node, login: "vvterm-test")
        let payload = Data((0..<262_144).map { UInt8($0 & 255) })
        let file = try await runSSH(fileConnection, command: "", operation: TELEPORT_SSH_SFTP_ROUNDTRIP,
                                   input: payload, sftpPath: "/tmp/teleport-native-" + UUID().uuidString)
        await fileConnection.close()
        try require(file.code == 0 && file.output == payload, "SFTP roundtrip or cleanup")
        print("PASS native SFTP 256 KiB write/read/remove")
        let concurrentA = try await client.connect(to: node, login: "vvterm-test")
        let concurrentB = try await client.connect(to: node, login: "vvterm-test")
        async let resultA = runSSH(concurrentA, command: "printf SHARED_A")
        async let resultB = runSSH(concurrentB, command: "printf SHARED_B")
        let results = try await (resultA, resultB)
        await concurrentA.close(); await concurrentB.close()
        try require(results.0.code == 0 && results.1.code == 0 && results.0.output == Data("SHARED_A".utf8) && results.1.output == Data("SHARED_B".utf8), "Concurrent SSH streams")
        print("PASS concurrent streams with one identity")

        do { _ = try await client.connect(to: node, login: "root"); throw HarnessFailure(description: "Disallowed principal was accepted") }
        catch TeleportError.invalidConfiguration { print("PASS disallowed principal") }
        let rejection = try await client.connect(to: node, login: "vvterm-test")
        let rejected = try await runSSH(rejection, command: "printf SHOULD_NOT_RUN", rejectHost: true)
        await rejection.close()
        try require(rejected.code == Int(TELEPORT_SSH_HOST_TRUST.rawValue) && rejected.output.isEmpty, "Host trust rejection")
        print("PASS host trust rejection before user authentication")
        guard let denied = fixture.nodes.first(where: { !$0.authorized }) else { throw HarnessFailure(description: "No denied-node fixture") }
        let deniedNode = try TeleportNode(id: denied.id, name: denied.name, clusterName: fixture.clusterName)
        do {
            let connection = try await client.connect(to: deniedNode, login: "vvterm-test")
            let result = try await runSSH(connection, command: "printf SHOULD_NOT_RUN")
            await connection.close()
            try require(result.code == Int(TELEPORT_SSH_AUTH.rawValue) && result.output.isEmpty,
                        "Denied node did not return an SSH authentication denial (result \(result.code), native \(result.native))")
        } catch let error as HarnessFailure { throw error }
        catch TeleportError.accessDenied { /* The proxy can reject the route before SSH authentication. */ }
        print("PASS denied-node authorization")
        try await client.signOut()
        do { _ = try await client.identity(); throw HarnessFailure(description: "Sign-out retained identity") }
        catch TeleportError.authenticationRequired { print("PASS sign-out") }
        print("PASS complete native public-API path")
    }
}
