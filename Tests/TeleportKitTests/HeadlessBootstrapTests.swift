import Foundation
import XCTest
@testable import TeleportKit

final class HeadlessBootstrapTests: XCTestCase, @unchecked Sendable {
    func testRequestIDMatchesIndependentSHA256UUIDVectorsAndKeepsTrailingNewline() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG9wZW5haS10ZXN0LWtleQ=="
        // Python hashlib.sha256(bytes(16) + key), first 16 bytes, UUID version 5 and variant bits.
        XCTAssertEqual(HeadlessBootstrap.requestID(sshPublicKey: Data()), "374708ff-f771-5dd5-979e-c875d56cd228")
        XCTAssertEqual(HeadlessBootstrap.requestID(sshPublicKey: Data((key + "\n").utf8)), "6e6b9b47-4d26-58b1-b0b1-675a52f3f2b2")
        XCTAssertEqual(HeadlessBootstrap.requestID(sshPublicKey: Data(key.utf8)), "996e827f-6f1e-5676-8744-a9714be0cfd2")
    }

    func testUnsupportedPoliciesFailBeforeBrowserOrCertificateRequest() async throws {
        for (auth, expected) in [
            (["allow_headless": false], TeleportError.unsupportedPolicy(.headless)),
            (["type": "oidc"], .unsupportedPolicy(.headless)),
            (["allow_passwordless": false], .unsupportedPolicy(.passwordless)),
            (["private_key_policy": "hardware_key"], .unsupportedPolicy(.hardwareKey)),
            (["device_trust": ["auto_enroll": true]], .unsupportedPolicy(.deviceTrust)),
        ] as [([String: Any], TeleportError)] {
            var fields: [String: Any] = ["type": "local", "allow_headless": true, "allow_passwordless": true]
            fields.merge(auth) { _, new in new }
            let ping = try JSONSerialization.data(withJSONObject: [
                "auth": fields, "cluster_name": "cluster", "server_version": "18.11.4",
                "proxy": ["tls_routing_enabled": true]
            ])
            let fixture = try HeadlessFixture(ping: ping)
            do { _ = try await bootstrap(fixture); XCTFail("unsupported setup policy was accepted") }
            catch let error as TeleportError { XCTAssertEqual(error, expected) }
            let snapshot = await fixture.snapshot()
            XCTAssertEqual(snapshot.paths, ["v1/webapi/ping"])
            XCTAssertNil(snapshot.browserURL)
            XCTAssertNil(snapshot.body)
        }
    }

    func testBrowserFailureCancellationAndTimeoutCancelThePendingRequest() async throws {
        for failure in [HeadlessFixture.BrowserFailure.failed, .cancelled, .timeout] {
            let fixture = try HeadlessFixture(browserFailure: failure)
            do { _ = try await bootstrap(fixture); XCTFail("failed browser approval returned an identity") }
            catch is CancellationError { XCTAssertEqual(failure, .cancelled) }
            catch let error as TeleportError {
                XCTAssertEqual(error, failure == .timeout ? .transport("browser login timeout") : .transport("test browser failed"))
            }
            let snapshot = await fixture.snapshot()
            XCTAssertTrue(snapshot.requestCancelled)
            XCTAssertEqual(snapshot.paths, ["v1/webapi/ping", "v1/webapi/headless/login"])
        }
    }

    func testTaskCancellationCancelsPendingApprovalRequest() async throws {
        let fixture = try HeadlessFixture()
        let task = Task { try await self.bootstrap(fixture) }
        await fixture.waitForBrowser()
        task.cancel()
        do { _ = try await task.value; XCTFail("cancelled setup returned an identity") }
        catch is CancellationError {}
        let snapshot = await fixture.snapshot()
        XCTAssertTrue(snapshot.requestCancelled)
        XCTAssertEqual(snapshot.paths, ["v1/webapi/ping", "v1/webapi/headless/login"])
    }

    func testCertificateRequestTimeoutDoesNotFetchTrustOrReturnAnIdentity() async throws {
        let fixture = try HeadlessFixture(response: .failure(.transport("headless login timeout")))
        do { _ = try await bootstrap(fixture); XCTFail("timed-out setup returned an identity") }
        catch let error as TeleportError { XCTAssertEqual(error, .transport("headless login timeout")) }
        let snapshot = await fixture.snapshot()
        XCTAssertEqual(snapshot.paths, ["v1/webapi/ping", "v1/webapi/headless/login"])
    }

    #if os(macOS)
    func testBrowserApprovedIdentityUsesExactWireFieldsAndRequestedKeys() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let fixture = try HeadlessFixture(exports: issuer.authorityExports(), response: .issue {
            try issuer.response(to: $0, sshValidity: "-1m:+1m")
        })
        let identity = try await bootstrap(fixture)
        XCTAssertEqual(identity.proxy, try proxy())
        XCTAssertEqual(identity.username, "alice")
        XCTAssertEqual(identity.clusterName, "cluster")
        XCTAssertTrue(identity.isUsable())
        XCTAssertLessThanOrEqual(identity.validBefore.timeIntervalSinceNow, 120)
        XCTAssertFalse(identity.tlsPrivateKeyDER.isEmpty)
        XCTAssertFalse(identity.sshPrivateKeyPEM.isEmpty)

        let snapshot = await fixture.snapshot()
        let body = try XCTUnwrap(snapshot.body)
        let request = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(Set(request.keys), ["user", "headless_id", "ssh_pub_key", "tls_pub_key", "ttl"])
        XCTAssertEqual(request["user"] as? String, "alice")
        XCTAssertEqual(request["ttl"] as? Int64, 60_000_000_000)
        let ssh = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request["ssh_pub_key"] as? String)))
        let tls = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request["tls_pub_key"] as? String)))
        let key = try CredentialKey(privateDER: identity.tlsPrivateKeyDER)
        XCTAssertEqual(ssh, Data(key.sshPublicKey.utf8))
        XCTAssertEqual(tls, Data(key.tlsPublicKeyPEM.utf8))
        let id = HeadlessBootstrap.requestID(sshPublicKey: ssh)
        XCTAssertEqual(request["headless_id"] as? String, id)
        XCTAssertEqual(snapshot.browserURL?.absoluteString, "https://proxy.example:8443/web/headless/" + id)
        XCTAssertEqual(snapshot.paths.filter { $0 == "v1/webapi/headless/login" }.count, 1)
        XCTAssertEqual(snapshot.exportTypes, Set(["tls-user", "user"]))
    }

    func testWrongAccountClusterAndCertificateKeysAreRejected() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        for fault in [BrowserMFACertificateIssuer.Fault.account, .cluster, .sshKey, .tlsKey] {
            let fixture = try HeadlessFixture(exports: issuer.authorityExports(), response: .issue {
                try issuer.response(to: $0, fault: fault, sshValidity: "-1m:+1m")
            })
            do { _ = try await bootstrap(fixture); XCTFail("certificate binding failure was accepted") }
            catch let error as TeleportError {
                switch error {
                case .invalidResponse, .invalidCertificate: break
                default: XCTFail("unexpected binding failure")
                }
            }
        }
    }

    func testSetupRejectsACertificateThatExceedsItsShortLifetime() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let fixture = try HeadlessFixture(exports: issuer.authorityExports(), response: .issue {
            try issuer.response(to: $0)
        })
        do { _ = try await bootstrap(fixture); XCTFail("long-lived setup certificate was accepted") }
        catch let error as TeleportError { XCTAssertEqual(error, .invalidCertificate("new identity validity")) }
    }
    #endif

    private func bootstrap(_ fixture: HeadlessFixture) async throws -> TeleportIdentity {
        try await HeadlessBootstrap.perform(proxy: proxy(), username: "alice", presenter: HeadlessPresenter(fixture: fixture)) {
            try await fixture.request(path: $0, query: $1, body: $2)
        }
    }

    private func proxy() throws -> TeleportProxy {
        try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example:8443")))
    }
}

private struct HeadlessPresenter: TeleportBrowserPresenter {
    let fixture: HeadlessFixture
    @MainActor func open(_ url: URL) async throws { try await fixture.open(url) }
}

private actor HeadlessFixture {
    enum BrowserFailure: Sendable, Equatable { case none, failed, cancelled, timeout }
    enum Response: Sendable {
        case wait
        case failure(TeleportError)
        case issue(@Sendable (Data) throws -> Data)
    }
    struct Snapshot: Sendable {
        let paths: [String]
        let body: Data?
        let browserURL: URL?
        let requestCancelled: Bool
        let exportTypes: Set<String>
    }

    private let ping: Data
    private let exports: [String: Data]
    private let response: Response
    private let browserFailure: BrowserFailure
    private var paths: [String] = []
    private var body: Data?
    private var browserURL: URL?
    private var requestCancelled = false
    private var exportTypes: Set<String> = []
    private var requestWaiters: [CheckedContinuation<Void, Never>] = []
    private var browserWaiters: [CheckedContinuation<Void, Never>] = []

    init(ping: Data? = nil, browserFailure: BrowserFailure = .none,
         exports: [String: Data] = [:], response: Response = .wait) throws {
        self.ping = ping ?? Data(#"{"auth":{"type":"local","allow_headless":true,"allow_passwordless":true},"cluster_name":"cluster","server_version":"18.11.4","proxy":{"tls_routing_enabled":true}}"#.utf8)
        self.exports = exports; self.response = response; self.browserFailure = browserFailure
    }

    func request(path: String, query: [URLQueryItem], body: Data?) async throws -> Data {
        paths.append(path)
        switch path {
        case "v1/webapi/ping":
            XCTAssertTrue(query.isEmpty); XCTAssertNil(body)
            return ping
        case "v1/webapi/headless/login":
            XCTAssertTrue(query.isEmpty)
            self.body = try XCTUnwrap(body)
            requestWaiters.forEach { $0.resume() }; requestWaiters.removeAll()
            switch response {
            case .wait:
                do { try await Task.sleep(for: .seconds(60)); throw TeleportError.transport("test request exceeded wait") }
                catch { requestCancelled = Task.isCancelled; throw error }
            case .failure(let error):
                await waitForBrowser()
                throw error
            case .issue(let issue):
                await waitForBrowser()
                return try issue(XCTUnwrap(body))
            }
        case "v1/webapi/auth/export":
            XCTAssertNil(body)
            XCTAssertEqual(Set(query.map(\.name)), Set(["type", "format"]))
            XCTAssertEqual(query.first(where: { $0.name == "format" })?.value, "json")
            let type = try XCTUnwrap(query.first(where: { $0.name == "type" })?.value)
            exportTypes.insert(type)
            return try XCTUnwrap(exports[type])
        default:
            throw TeleportError.transport("unexpected test request")
        }
    }

    func open(_ url: URL) async throws {
        if body == nil { await withCheckedContinuation { requestWaiters.append($0) } }
        browserURL = url
        browserWaiters.forEach { $0.resume() }; browserWaiters.removeAll()
        switch browserFailure {
        case .none: break
        case .failed: throw TeleportError.transport("test browser failed")
        case .cancelled: throw CancellationError()
        case .timeout: throw TeleportError.transport("browser login timeout")
        }
    }

    func waitForBrowser() async {
        if browserURL == nil { await withCheckedContinuation { browserWaiters.append($0) } }
    }

    func snapshot() -> Snapshot {
        Snapshot(paths: paths, body: body, browserURL: browserURL,
                 requestCancelled: requestCancelled, exportTypes: exportTypes)
    }
}
