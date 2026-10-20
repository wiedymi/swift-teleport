import XCTest
import Foundation
import CryptoKit
@testable import TeleportKit

final class BrowserMFATests: XCTestCase, @unchecked Sendable {
    private let requestID = "86a9e814-26f3-41d1-b7ed-934a2e07f790"

    func testPublicBrowserMFALoginRejectsInvalidInputBeforeOpeningBrowser() async throws {
        let fixture = BrowserMFAHTTPFixture(approval: .wait)
        let client = TeleportClient(proxy: try proxy())
        for (username, password, ttl) in [
            ("", "test-password", 3600.0),
            ("alice", "", 3600.0),
            (String(repeating: "a", count: 1025), "test-password", 3600.0),
            ("alice", String(repeating: "a", count: 65_537), 3600.0),
            ("alice", "test-password", .nan),
            ("alice", "test-password", .infinity),
            ("alice", "test-password", 59.0),
            ("alice", "test-password", 43_201.0),
        ] {
            do {
                _ = try await client.login(username: username, password: password,
                                           browser: BrowserMFATestPresenter(fixture: fixture), ttl: ttl)
                XCTFail("invalid browser login input was accepted")
            } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("login input")) }
        }
        let snapshot = await fixture.snapshot()
        XCTAssertNil(snapshot.browserURL)
    }

    func testDiscoveryReportsWebAuthnConfigurationWithoutGuessingBrowserMFAAvailability() throws {
        for relyingParty in [nil, "", "proxy.example"] {
            var auth: [String: Any] = ["type": "local", "second_factor": "otp"]
            if let relyingParty { auth["webauthn"] = ["rp_id": relyingParty] }
            let bytes = try JSONSerialization.data(withJSONObject: ["auth": auth, "cluster_name": "cluster",
                                                                    "server_version": "18.11.4", "proxy": ["tls_routing_enabled": true]])
            let ping = try JSONDecoder().decode(ProxyPing.self, from: bytes)
            try ping.validate()
            XCTAssertEqual(ping.discovery.webAuthnConfigured, relyingParty == "proxy.example")
            XCTAssertEqual(ping.discovery.secondFactor, "otp")
        }
    }

    func testBrowserAssertionAcceptsPaddingAndRejectsMismatchedIDsNoncanonicalBitsAndLongUserHandle() throws {
        var valid = BrowserMFAHTTPFixture.assertion
        valid["id"] = "AQI="; valid["rawId"] = "AQI"
        valid["response"] = ["clientDataJSON": "e30=", "authenticatorData": "AQI=", "signature": "BAU=", "userHandle": "BwgJ"]
        func assertion(_ value: [String: Any]) throws -> BrowserMFAAssertion {
            try JSONDecoder().decode(BrowserMFAAssertion.self, from: JSONSerialization.data(withJSONObject: value))
        }
        try assertion(valid).validate()
        var mismatched = valid; mismatched["rawId"] = "AQID"
        var noncanonical = valid; noncanonical["id"] = "AQJ="; noncanonical["rawId"] = "AQJ"
        var longHandle = valid
        var response = try XCTUnwrap(valid["response"] as? [String: String])
        response["userHandle"] = Data(repeating: 7, count: 65).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").filter { $0 != "=" }
        longHandle["response"] = response
        for invalid in [mismatched, noncanonical, longHandle] { XCTAssertThrowsError(try assertion(invalid).validate()) }
    }

    func testAbsentOrInvalidBrowserChallengeDoesNotOpenBrowserOrRequestCertificates() async throws {
        for challenge in [
            "{\"totp_challenge\":true}",
            "{\"browser_challenge\":{\"requestId\":\"\"}}",
            "{\"browser_challenge\":{\"requestId\":\"../other\"}}",
            "{\"browser_challenge\":{\"requestId\":17}}",
        ] {
            let fixture = BrowserMFAHTTPFixture(challenge: Data(challenge.utf8))
            let store = BrowserMFARecordingStore()
            do {
                _ = try await login(fixture, store: store)
                XCTFail("invalid browser challenge was accepted")
            } catch is TeleportError {}
            let snapshot = await fixture.snapshot()
            XCTAssertNil(snapshot.browserURL)
            XCTAssertNil(snapshot.finish)
            let writes = await store.writeCount
            XCTAssertEqual(writes, 0)
        }
    }

    func testInvalidAuthenticatedBrowserAssertionsDoNotRequestOrStoreCertificates() async throws {
        let valid = BrowserMFAHTTPFixture.assertion
        var emptyID = valid; emptyID["id"] = ""
        var wrongType = valid; wrongType["type"] = "other"
        var invalidBase64 = valid; invalidBase64["response"] = ["clientDataJSON": "e30", "authenticatorData": "AQID", "signature": "not+url/base64"]
        var oversized = valid; oversized["response"] = ["clientDataJSON": "e30", "authenticatorData": "AQID", "signature": String(repeating: "A", count: 90_000)]
        for assertion in [nil, emptyID, wrongType, invalidBase64, oversized] {
            let payload = try JSONSerialization.data(withJSONObject: assertion.map { ["browser_mfa_webauthn_response": $0] } ?? [:])
            let fixture = BrowserMFAHTTPFixture(payload: payload)
            let store = BrowserMFARecordingStore()
            do {
                _ = try await login(fixture, store: store)
                XCTFail("invalid browser assertion was accepted")
            } catch is TeleportError {}
            let snapshot = await fixture.snapshot()
            XCTAssertNotNil(snapshot.browserURL)
            XCTAssertNil(snapshot.finish)
            let writes = await store.writeCount
            XCTAssertEqual(writes, 0)
        }
    }

    func testCancelWhileBrowserIsOpenDoesNotRequestOrStoreCertificates() async throws {
        let fixture = BrowserMFAHTTPFixture(approval: .wait)
        let store = BrowserMFARecordingStore()
        let task = Task { try await self.login(fixture, store: store) }
        await fixture.waitForBrowser()
        task.cancel()
        do { _ = try await task.value; XCTFail("canceled browser login succeeded") }
        catch is CancellationError {}
        let snapshot = await fixture.snapshot()
        XCTAssertNil(snapshot.finish)
        let writes = await store.writeCount
        XCTAssertEqual(writes, 0)
    }

    func testBrowserCallbackTimeoutEndsPendingWait() async throws {
        let callback = try BrowserCallback(timeout: 0.05)
        defer { callback.close() }
        _ = try await callback.start()
        do { _ = try await callback.wait(); XCTFail("callback did not time out") }
        catch let error as TeleportError { XCTAssertEqual(error, .transport("browser login timeout")) }
    }

    #if os(macOS)
    func testBrowserMFAStoresCertificatesOnlyAfterBindingThemToRequestedKeysAccountAndCluster() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let fixture = BrowserMFAHTTPFixture(approval: .tamperedThenValid, exports: try issuer.authorityExports(),
                                           finish: { try issuer.response(to: $0) })
        let store = BrowserMFARecordingStore()
        let identity = try await login(fixture, store: store)
        XCTAssertEqual(identity.username, "alice")
        XCTAssertEqual(identity.clusterName, "cluster")
        XCTAssertEqual(identity.allowedLogins, ["alice"])
        XCTAssertTrue(identity.isUsable())
        let writes = await store.writeCount
        XCTAssertEqual(writes, 1)
        let stored = await store.load()
        XCTAssertEqual(stored?.tlsCertificateDER, identity.tlsCertificateDER)
        let snapshot = await fixture.snapshot()
        XCTAssertEqual(snapshot.browserURL?.absoluteString, "https://proxy.example/web/mfa/browser/" + requestID)
        XCTAssertEqual(snapshot.callbackStatuses, [400, 200])
        let begin = try object(XCTUnwrap(snapshot.begin))
        XCTAssertEqual(Set(begin.keys), ["user", "pass", "browser_mfa_tsh_redirect_url"])
        XCTAssertEqual(begin["user"] as? String, "alice")
        XCTAssertEqual(begin["pass"] as? String, "test-password")
        let finish = try object(XCTUnwrap(snapshot.finish))
        XCTAssertEqual(finish["user"] as? String, "alice")
        XCTAssertEqual(finish["password"] as? String, "test-password")
        XCTAssertEqual(finish["ttl"] as? Int64, 3_600_000_000_000)
        XCTAssertNotNil(finish["ssh_pub_key"] as? String)
        XCTAssertNotNil(finish["tls_pub_key"] as? String)
        XCTAssertEqual(finish["totp_code"] as? String, "")
        let response = try XCTUnwrap(finish["browser_response"] as? [String: Any])
        XCTAssertEqual(response["requestId"] as? String, requestID)
        let assertion = try XCTUnwrap(response["webauthnResponse"] as? [String: Any])
        XCTAssertEqual(assertion["id"] as? String, "AQID")
        XCTAssertEqual(assertion["type"] as? String, "public-key")
        XCTAssertEqual(snapshot.paths.filter { $0.contains("mfa/login/begin") }.count, 1)
        XCTAssertEqual(snapshot.paths.filter { $0.contains("mfa/login/finish") }.count, 1)
        XCTAssertEqual(snapshot.paths.filter { $0.contains("auth/export") }.count, 2)
    }

    func testWrongCertificateAccountClusterAndKeysNeverReachIdentityStore() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        for fault in [BrowserMFACertificateIssuer.Fault.account, .cluster, .sshKey, .tlsKey] {
            let fixture = BrowserMFAHTTPFixture(exports: try issuer.authorityExports(), finish: { try issuer.response(to: $0, fault: fault) })
            let store = BrowserMFARecordingStore()
            do {
                _ = try await login(fixture, store: store)
                XCTFail("certificate with wrong binding was stored")
            } catch is TeleportError {}
            let writes = await store.writeCount
            let stored = await store.load()
            XCTAssertEqual(writes, 0)
            XCTAssertNil(stored)
        }
    }

    func testFailedStoreWritePreservesPriorIdentityAndLoginCanRetry() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let fixture = BrowserMFAHTTPFixture(exports: try issuer.authorityExports(), finish: { try issuer.response(to: $0) })
        let store = BrowserMFARecordingStore()
        let client = TeleportClient(proxy: try proxy(), identityStore: store)
        let first = try await login(fixture, client: client)
        await store.setFailWrites(true)
        do { _ = try await login(fixture, client: client); XCTFail("failed store write succeeded") }
        catch BrowserMFATestError.storeWrite {}
        let preserved = try await client.identity()
        XCTAssertEqual(preserved.tlsCertificateDER, first.tlsCertificateDER)
        await store.setFailWrites(false)
        _ = try await login(fixture, client: client)
        let writes = await store.writeCount
        XCTAssertEqual(writes, 2)
    }
    #endif

    func testDifferentAuthenticationMethodsDoNotSharePendingBrowserMFALogin() async throws {
        let fixture = BrowserMFAHTTPFixture(approval: .wait)
        let client = TeleportClient(proxy: try proxy())
        let task = Task { try await self.login(fixture, client: client) }
        await fixture.waitForBrowser()
        for method in [TeleportClient.LoginMethod.password("alice"), .sso(.github, "alice"), .browserMFA("other")] {
            do {
                _ = try await client.sharedLogin(method: method) { throw BrowserMFATestError.unexpectedOperation }
                XCTFail("different authentication method joined pending login")
            } catch let error as TeleportError {
                guard case .invalidConfiguration = error else { XCTFail("wrong error for pending authentication method"); continue }
            }
        }
        task.cancel()
        do { _ = try await task.value; XCTFail("canceled login succeeded") }
        catch is CancellationError {}
    }

    func testCancelingOneSharedTaskWaiterLeavesOtherWaiterActive() async throws {
        let gate = BrowserMFATestGate()
        let shared = Task { await gate.wait(); try Task.checkCancellation(); return 42 }
        let canceled = Task { try await SharedTaskWaiter<Int>.wait(for: shared) }
        let active = Task { try await SharedTaskWaiter<Int>.wait(for: shared) }
        canceled.cancel()
        do { _ = try await canceled.value; XCTFail("canceled waiter returned a result") }
        catch is CancellationError {}
        await gate.release()
        let value = try await active.value
        XCTAssertEqual(value, 42)
    }

    private func login(_ fixture: BrowserMFAHTTPFixture, store: BrowserMFARecordingStore) async throws -> TeleportIdentity {
        try await login(fixture, client: TeleportClient(proxy: proxy(), identityStore: store))
    }
    private func login(_ fixture: BrowserMFAHTTPFixture, client: TeleportClient) async throws -> TeleportIdentity {
        let proxy = try proxy()
        return try await client.sharedLogin(method: .browserMFA("alice")) {
            try await BrowserMFALogin.perform(proxy: proxy, username: "alice", password: "test-password", ttl: 3600,
                                             presenter: BrowserMFATestPresenter(fixture: fixture), request: { path, query, body in
                try await fixture.request(path: path, query: query, body: body)
            })
        }
    }
    private func proxy() throws -> TeleportProxy { try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example"))) }
    private func object(_ data: Data) throws -> [String: Any] { try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any]) }
}

private enum BrowserMFATestError: Error { case unexpectedRequest, unexpectedOperation, storeWrite }

private actor BrowserMFATestGate {
    private var released = false
    private var waiter: CheckedContinuation<Void, Never>?
    func wait() async {
        if released { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func release() { released = true; waiter?.resume(); waiter = nil }
}

private actor BrowserMFARecordingStore: TeleportIdentityStore {
    private var identity: TeleportIdentity?
    private var failWrites = false
    private(set) var writeCount = 0
    func load() -> TeleportIdentity? { identity }
    func replace(with identity: TeleportIdentity?) throws {
        if failWrites { throw BrowserMFATestError.storeWrite }
        self.identity = identity; writeCount += 1
    }
    func setFailWrites(_ value: Bool) { failWrites = value }
}

private struct BrowserMFATestPresenter: TeleportBrowserPresenter {
    let fixture: BrowserMFAHTTPFixture
    @MainActor func open(_ url: URL) async throws { try await fixture.open(url) }
}

private actor BrowserMFAHTTPFixture {
    enum Approval: Sendable, Equatable { case approve, tamperedThenValid, wait }
    struct Snapshot: Sendable {
        var paths = [String]()
        var begin: Data?
        var finish: Data?
        var browserURL: URL?
        var callbackStatuses = [Int]()
    }
    static var assertion: [String: Any] {
        ["id": "AQID", "type": "public-key", "rawId": "AQID", "extensions": ["appid": false],
         "response": ["clientDataJSON": "e30", "authenticatorData": "AQID", "signature": "BAUG", "userHandle": "BwgJ"]]
    }
    private let challenge: Data
    private let payload: Data
    private let approval: Approval
    private let exports: [String: Data]
    private let finish: @Sendable (Data) throws -> Data
    private var state = Snapshot()
    private var browserObserver: CheckedContinuation<Void, Never>?

    init(challenge: Data = Data("{\"browser_challenge\":{\"requestId\":\"86a9e814-26f3-41d1-b7ed-934a2e07f790\"}}".utf8),
         payload: Data? = nil, approval: Approval = .approve, exports: [String: Data] = [:],
         finish: @escaping @Sendable (Data) throws -> Data = { _ in throw BrowserMFATestError.unexpectedRequest }) {
        self.challenge = challenge
        self.payload = payload ?? Data("{\"browser_mfa_webauthn_response\":{\"id\":\"AQID\",\"type\":\"public-key\",\"rawId\":\"AQID\",\"extensions\":{\"appid\":false},\"response\":{\"clientDataJSON\":\"e30\",\"authenticatorData\":\"AQID\",\"signature\":\"BAUG\",\"userHandle\":\"BwgJ\"}}}".utf8)
        self.approval = approval; self.exports = exports; self.finish = finish
    }
    func snapshot() -> Snapshot { state }
    func waitForBrowser() async {
        if state.browserURL != nil { return }
        await withCheckedContinuation { browserObserver = $0 }
    }
    func request(path: String, query: [URLQueryItem], body: Data?) throws -> Data {
        state.paths.append(path)
        if path == "v1/webapi/ping" {
            return Data("{\"cluster_name\":\"cluster\",\"server_version\":\"18.11.4\",\"auth\":{\"type\":\"local\",\"second_factor\":\"on\",\"webauthn\":{\"rp_id\":\"proxy.example\"}},\"proxy\":{\"tls_routing_enabled\":true}}".utf8)
        }
        if path == "v1/webapi/mfa/login/begin" { state.begin = try XCTUnwrap(body); return challenge }
        if path == "v1/webapi/mfa/login/finish" { state.finish = try XCTUnwrap(body); return try finish(XCTUnwrap(body)) }
        if path.contains("auth/export") {
            let type = try XCTUnwrap(query.first(where: { $0.name == "type" })?.value)
            return try XCTUnwrap(exports[type])
        }
        throw BrowserMFATestError.unexpectedRequest
    }
    func open(_ url: URL) async throws {
        state.browserURL = url; browserObserver?.resume(); browserObserver = nil
        guard approval != .wait else { return }
        let begin = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(state.begin)) as? [String: Any])
        let redirect = try XCTUnwrap(begin["browser_mfa_tsh_redirect_url"] as? String)
        var callback = try XCTUnwrap(URLComponents(string: redirect))
        let secret = try XCTUnwrap(callback.queryItems?.first(where: { $0.name == "secret_key" })?.value)
        var keyBytes = Data()
        var index = secret.startIndex
        while index < secret.endIndex {
            let end = secret.index(index, offsetBy: 2)
            keyBytes.append(try XCTUnwrap(UInt8(secret[index..<end], radix: 16))); index = end
        }
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        for tampered in approval == .tamperedThenValid ? [true, false] : [false] {
            let key = tampered ? SymmetricKey(size: .bits256) : SymmetricKey(data: keyBytes)
            let box = try AES.GCM.seal(payload, using: key)
            let encrypted = try JSONSerialization.data(withJSONObject: ["ciphertext": (box.ciphertext + box.tag).base64EncodedString(),
                                                                      "nonce": box.nonce.withUnsafeBytes { Data($0) }.base64EncodedString()])
            callback.queryItems = [URLQueryItem(name: "response", value: String(decoding: encrypted, as: UTF8.self))]
            let request: URLRequest
            if encrypted.count > 4096 {
                let form = callback.percentEncodedQuery
                callback.query = nil
                var post = URLRequest(url: try XCTUnwrap(callback.url))
                post.httpMethod = "POST"
                post.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                post.httpBody = Data(try XCTUnwrap(form).replacingOccurrences(of: "+", with: "%2B").utf8)
                request = post
            } else { request = URLRequest(url: try XCTUnwrap(callback.url)) }
            let (_, response) = try await session.data(for: request)
            state.callbackStatuses.append(try XCTUnwrap(response as? HTTPURLResponse).statusCode)
        }
    }
}
