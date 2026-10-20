import XCTest
import Foundation
import CryptoKit
@testable import TeleportKit
#if os(macOS)
import Vision
#endif

/// Real server wire checks with an injected software key. This does not test Apple biometrics.
final class DeviceCredentialLiveTests: XCTestCase, @unchecked Sendable {
    func testPinnedServerRegistrationAndDeviceCredentialCertificates() async throws {
        #if os(macOS)
        guard let path = ProcessInfo.processInfo.environment["TELEPORT_DEVICE_CREDENTIAL_FIXTURE"] else {
            throw XCTSkip("Set TELEPORT_DEVICE_CREDENTIAL_FIXTURE to a new lab created with --auth-only.")
        }
        let fixture = try JSONDecoder().decode(Fixture.self, from: Self.read(URL(fileURLWithPath: path)))
        guard fixture.schemaVersion == 1, fixture.authOnly else { throw LiveFailure.invalidFixture }
        let invitation = try JSONDecoder().decode(Invitation.self, from: Self.read(URL(fileURLWithPath: fixture.enrollmentInvitationFile)))
        let ca = try Self.certificatePEM(Self.read(URL(fileURLWithPath: fixture.httpsCAFile)))
        let proxy = try TeleportProxy(url: fixture.proxyURL, httpsCACertificatesDER: [ca])
        let seed = try await Self.enroll(invitation: invitation, proxy: proxy)
        let password = Self.password(invitation: invitation)
        let store = LiveDeviceCredentialStore()
        let identityStore = MemoryIdentityStore()
        let client = TeleportClient(proxy: proxy, identityStore: identityStore,
                                    deviceCredentialStorage: store, deviceKeyOperations: LiveSoftwareKeyOperations())
        let discovery = try await client.discover()
        XCTAssertEqual(discovery.serverVersion, fixture.serverVersion)
        XCTAssertEqual(discovery.clusterName, fixture.clusterName)

        let previous = try await client.login(username: invitation.username, password: password, otp: Self.totp(seed))
        XCTAssertTrue(previous.isUsable())
        XCTAssertEqual(previous.username, invitation.username)
        try await Self.nextOTPPeriod()
        try await client.registerSecureEnclaveCredential(name: "test-device-key", otp: Self.totp(seed), prompt: "Register test device")
        let registered = await store.load(username: invitation.username)
        let credential = try XCTUnwrap(registered)
        XCTAssertEqual(credential.clusterName, fixture.clusterName)
        XCTAssertFalse(credential.credentialID.isEmpty)
        try await client.signOut()

        let identity = try await client.loginWithSecureEnclave(username: invitation.username, password: password, prompt: "Authenticate test device")
        XCTAssertTrue(identity.isUsable())
        XCTAssertEqual(identity.username, invitation.username)
        XCTAssertEqual(identity.clusterName, fixture.clusterName)
        XCTAssertTrue(identity.allowedLogins.contains("teleport-test"))
        XCTAssertTrue(identity.tlsCertificateDER != previous.tlsCertificateDER)
        XCTAssertTrue(identity.tlsPrivateKeyDER != credential.protectedKey)
        let stored = try await client.identity()
        XCTAssertTrue(stored.sshCertificateOpenSSH == identity.sshCertificateOpenSSH)

        do {
            _ = try await client.loginWithSecureEnclave(username: invitation.username, password: "incorrect-test-password", prompt: "Authenticate test device")
            XCTFail("Device login accepted the wrong password")
        } catch let error as TeleportError {
            XCTAssertEqual(error, .httpStatus(403))
        }
        let afterRejection = try await client.identity()
        XCTAssertTrue(afterRejection.tlsCertificateDER == identity.tlsCertificateDER)

        try await client.deleteSecureEnclaveCredential(username: invitation.username)
        let deleted = await store.load(username: invitation.username)
        XCTAssertNil(deleted)
        do {
            _ = try await client.loginWithSecureEnclave(username: invitation.username, password: password, prompt: "Authenticate test device")
            XCTFail("Login succeeded after local credential deletion")
        } catch let error as TeleportError {
            XCTAssertEqual(error, .deviceCredentialMissing)
        }
        let retained = try await client.identity()
        XCTAssertTrue(retained.tlsCertificateDER == identity.tlsCertificateDER)
        try await client.signOut()
        #else
        throw XCTSkip("The native auth-only fixture uses macOS Vision for test enrollment.")
        #endif
    }

    private struct Fixture: Decodable {
        let schemaVersion: Int
        let authOnly: Bool
        let proxyURL: URL
        let clusterName: String
        let serverVersion: String
        let httpsCAFile: String
        let enrollmentInvitationFile: String
    }
    private struct Invitation: Decodable { let username: String; let token: String }
    private struct EnrollmentChallenge: Decodable { let qrCode: Data }
    private enum LiveFailure: Error { case invalidFixture, invalidEnrollment }

    private static func read(_ url: URL) throws -> Data {
        guard let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 1_048_576 else {
            throw LiveFailure.invalidFixture
        }
        return try Data(contentsOf: url)
    }

    private static func certificatePEM(_ data: Data) throws -> Data {
        guard let text = String(data: data, encoding: .utf8),
              let begin = text.range(of: "-----BEGIN CERTIFICATE-----"),
              let end = text.range(of: "-----END CERTIFICATE-----", range: begin.upperBound..<text.endIndex),
              let certificate = Data(base64Encoded: text[begin.upperBound..<end.lowerBound].filter { !$0.isWhitespace }) else {
            throw LiveFailure.invalidFixture
        }
        return certificate
    }

    // The invitation is a fresh random secret in a private disposable fixture. This derived
    // test password stays in memory and is never added to a fixture or a process argument.
    private static func password(invitation: Invitation) -> String {
        SHA256.hash(data: Data(invitation.token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    #if os(macOS)
    private static func enroll(invitation: Invitation, proxy: TeleportProxy) async throws -> String {
        do { return try await performEnrollment(invitation: invitation, proxy: proxy) }
        catch is CancellationError { throw CancellationError() }
        catch { throw LiveFailure.invalidEnrollment }
    }

    private static func performEnrollment(invitation: Invitation, proxy: TeleportProxy) async throws -> String {
        guard !invitation.token.isEmpty, invitation.token.utf8.count <= 256,
              invitation.token.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }) else {
            throw LiveFailure.invalidFixture
        }
        let data = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/users/password/token/" + invitation.token)
        let challenge = try JSONDecoder().decode(EnrollmentChallenge.self, from: data)
        guard challenge.qrCode.count <= 1_048_576 else { throw LiveFailure.invalidEnrollment }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try VNImageRequestHandler(data: challenge.qrCode).perform([request])
        guard let value = request.results?.first?.payloadStringValue,
              let uri = URLComponents(string: value), uri.scheme == "otpauth", uri.host == "totp",
              let seed = uri.queryItems?.first(where: { $0.name == "secret" })?.value,
              !seed.isEmpty, seed.utf8.count <= 256 else { throw LiveFailure.invalidEnrollment }
        let body = try JSONSerialization.data(withJSONObject: [
            "token": invitation.token,
            "password": Data(password(invitation: invitation).utf8).base64EncodedString(),
            "second_factor_token": totp(seed),
            "deviceName": "test-totp",
        ])
        _ = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/users/password/token", body: body, method: "PUT")
        try await nextOTPPeriod()
        return seed
    }
    #endif

    private static func nextOTPPeriod() async throws {
        let wait = 31 - Date().timeIntervalSince1970.truncatingRemainder(dividingBy: 30)
        try await Task.sleep(for: .seconds(wait))
    }

    private static func totp(_ seed: String) throws -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var key = Data(), accumulator: UInt32 = 0, bits = 0
        for char in seed.uppercased().utf8 where char != 61 {
            guard let digit = alphabet.firstIndex(of: char) else { throw LiveFailure.invalidEnrollment }
            accumulator = (accumulator << 5) | UInt32(digit); bits += 5
            if bits >= 8 { bits -= 8; key.append(UInt8((accumulator >> bits) & 255)); accumulator &= (1 << bits) - 1 }
        }
        guard !key.isEmpty else { throw LiveFailure.invalidEnrollment }
        var counter = UInt64(Date().timeIntervalSince1970 / 30).bigEndian
        let hash = Array(HMAC<Insecure.SHA1>.authenticationCode(for: withUnsafeBytes(of: &counter) { Data($0) }, using: SymmetricKey(data: key)))
        let offset = Int(hash.last! & 15)
        let value = ((UInt32(hash[offset]) & 127) << 24) | (UInt32(hash[offset + 1]) << 16) | (UInt32(hash[offset + 2]) << 8) | UInt32(hash[offset + 3])
        return String(format: "%06u", value % 1_000_000)
    }
}

private struct LiveSoftwareKeyOperations: DeviceKeyOperations {
    func create(prompt: String) async throws -> DeviceKeyMaterial {
        let key = P256.Signing.PrivateKey()
        return DeviceKeyMaterial(protectedKey: key.rawRepresentation, publicKeyX963: key.publicKey.x963Representation)
    }
    func sign(_ data: Data, protectedKey: Data, prompt: String) async throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: protectedKey).signature(for: data).derRepresentation
    }
}

private actor LiveDeviceCredentialStore: DeviceCredentialStorage {
    private var credentials: [String: DeviceCredential] = [:]
    func load(username: String) -> DeviceCredential? { credentials[username] }
    func add(_ credential: DeviceCredential, username: String) throws {
        guard credentials[username] == nil else { throw TeleportError.deviceCredentialExists }
        credentials[username] = credential
    }
    func delete(username: String) { credentials[username] = nil }
}
