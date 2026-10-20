import XCTest
import Foundation
import CryptoKit
import TeleportKit

final class BrowserMFALiveTests: XCTestCase, @unchecked Sendable {
    @MainActor
    func testPinnedServerPasswordTOTPAndBrowserMFACertificates() async throws {
        #if os(macOS)
        guard let path = ProcessInfo.processInfo.environment["TELEPORT_BROWSER_MFA_FIXTURE"] else {
            throw XCTSkip("Set TELEPORT_BROWSER_MFA_FIXTURE to a lab created with --browser-mfa.")
        }
        let fixtureURL = URL(fileURLWithPath: path)
        let fixture = try JSONDecoder().decode(LiveFixture.self, from: Self.read(fixtureURL))
        guard fixture.schemaVersion == 1, fixture.browserMFA == true else {
            throw LiveFailure.invalidFixture
        }
        let credentials = try JSONDecoder().decode(LocalCredentials.self, from: Self.read(URL(fileURLWithPath: fixture.localCredentialsFile)))
        let ca = try Self.certificatePEM(Self.read(URL(fileURLWithPath: fixture.httpsCAFile)))
        let proxy = try TeleportProxy(url: fixture.proxyURL, httpsCACertificatesDER: [ca])
        let store = MemoryIdentityStore()
        let client = TeleportClient(proxy: proxy, identityStore: store)
        let discovery = try await client.discover()
        XCTAssertEqual(discovery.clusterName, fixture.clusterName)
        XCTAssertEqual(discovery.serverVersion, fixture.serverVersion)

        let previous = try await client.login(username: credentials.username, password: credentials.password,
                                              otp: Self.totp(credentials.totpSeed))
        XCTAssertTrue(previous.isUsable())
        XCTAssertEqual(previous.username, credentials.username)
        try await client.signOut()

        let browser = LabBrowserPresenter(fixtureURL: fixtureURL)
        async let first = client.login(username: credentials.username, password: credentials.password, browser: browser)
        async let second = client.login(username: credentials.username, password: credentials.password, browser: browser)
        let identities = try await (first, second)
        XCTAssertEqual(browser.openCount, 1)
        XCTAssertEqual(identities.0.tlsCertificateDER, identities.1.tlsCertificateDER)
        XCTAssertNotEqual(identities.0.tlsCertificateDER, previous.tlsCertificateDER)
        XCTAssertTrue(identities.0.isUsable())
        XCTAssertEqual(identities.0.username, credentials.username)
        XCTAssertEqual(identities.0.clusterName, fixture.clusterName)
        XCTAssertTrue(identities.0.allowedLogins.contains("teleport-test"))
        let restored = try JSONDecoder().decode(TeleportIdentity.self, from: JSONEncoder().encode(identities.0))
        XCTAssertEqual(restored.tlsCertificateDER, identities.0.tlsCertificateDER)
        let stored = try await client.identity()
        XCTAssertEqual(stored.sshCertificateOpenSSH, identities.0.sshCertificateOpenSSH)
        try await client.signOut()
        do { _ = try await client.identity(); XCTFail("Identity remained after sign-out") }
        catch TeleportError.authenticationRequired {}
        #else
        throw XCTSkip("The Docker browser relay runs only on the native macOS host.")
        #endif
    }

    private struct LiveFixture: Decodable {
        let schemaVersion: Int
        let browserMFA: Bool?
        let proxyURL: URL
        let clusterName: String
        let serverVersion: String
        let httpsCAFile: String
        let localCredentialsFile: String
    }
    private struct LocalCredentials: Decodable { let username: String; let password: String; let totpSeed: String }
    private enum LiveFailure: Error { case invalidFixture }
    private static func read(_ url: URL) throws -> Data {
        guard let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 1_048_576 else {
            throw LiveFailure.invalidFixture
        }
        return try Data(contentsOf: url)
    }
    private static func certificatePEM(_ bytes: Data) throws -> Data {
        guard let text = String(data: bytes, encoding: .utf8),
              let start = text.range(of: "-----BEGIN CERTIFICATE-----"),
              let end = text.range(of: "-----END CERTIFICATE-----", range: start.upperBound..<text.endIndex),
              let value = Data(base64Encoded: text[start.upperBound..<end.lowerBound].filter { !$0.isWhitespace }) else {
            throw LiveFailure.invalidFixture
        }
        return value
    }
    private static func totp(_ seed: String) throws -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var key = Data(), accumulator: UInt32 = 0, bits = 0
        for char in seed.uppercased().utf8 where char != 61 {
            guard let digit = alphabet.firstIndex(of: char) else { throw LiveFailure.invalidFixture }
            accumulator = (accumulator << 5) | UInt32(digit); bits += 5
            if bits >= 8 { bits -= 8; key.append(UInt8((accumulator >> bits) & 255)); accumulator &= (1 << bits) - 1 }
        }
        var counter = UInt64(Date().timeIntervalSince1970 / 30).bigEndian
        let digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: withUnsafeBytes(of: &counter) { Data($0) }, using: SymmetricKey(data: key)))
        let offset = Int(digest.last! & 15)
        let value = ((UInt32(digest[offset]) & 127) << 24) | (UInt32(digest[offset + 1]) << 16) | (UInt32(digest[offset + 2]) << 8) | UInt32(digest[offset + 3])
        return String(format: "%06u", value % 1_000_000)
    }
}

#if os(macOS)
@MainActor private final class LabBrowserPresenter: TeleportBrowserPresenter {
    let fixtureURL: URL
    private(set) var openCount = 0
    init(fixtureURL: URL) { self.fixtureURL = fixtureURL }
    func open(_ url: URL) async throws {
        openCount += 1
        let directory = fixtureURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("browser-mfa")
        let request = directory.appendingPathComponent("request.json")
        let bytes = try JSONSerialization.data(withJSONObject: ["url": url.absoluteString])
        guard FileManager.default.createFile(atPath: request.path, contents: bytes, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { try? FileManager.default.removeItem(at: request) }
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", root.appendingPathComponent("IntegrationTests/Scripts/browser_mfa.py").path, fixtureURL.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try process.run()
            if Task.isCancelled { process.terminate() }
            let status = await Task.detached { process.waitUntilExit(); return process.terminationStatus }.value
            try Task.checkCancellation()
            guard status == 0 else { throw CocoaError(.executableRuntimeMismatch) }
        } onCancel: {
            if process.isRunning { process.terminate() }
        }
    }
}
#endif
