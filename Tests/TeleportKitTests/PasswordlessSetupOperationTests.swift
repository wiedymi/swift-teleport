import Foundation
import XCTest
@testable import TeleportKit

final class PasswordlessSetupOperationTests: XCTestCase, @unchecked Sendable {
    func testSetupExcludesOtherAuthenticationAndSignOutCancelsIt() async throws {
        let client = try client()
        let pause = SetupPause()
        let setup = Task { try await client.setupDeviceCredential { try await pause.wait() } }
        await pause.waitForEntry()
        do {
            _ = try await client.loginWithSecureEnclave(username: "alice", prompt: "Approve login")
            XCTFail("login started during setup")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("device credential setup or deletion is active")) }
        do {
            try await client.deleteSecureEnclaveCredential(username: "alice")
            XCTFail("deletion started during setup")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("another authentication operation is active")) }
        do {
            _ = try await client.setupDeviceCredential { throw SetupFailure.unexpected }
            XCTFail("second setup started")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("another authentication operation is active")) }
        try await client.signOut()
        do { _ = try await setup.value; XCTFail("setup survived sign-out") }
        catch is CancellationError {}
        do { _ = try await client.identity(); XCTFail("sign-out kept an identity") }
        catch let error as TeleportError { XCTAssertEqual(error, .authenticationRequired) }
    }

    func testCanceledSetupAllowsRetryAndNeverStoresPartialWork() async throws {
        let store = SetupIdentityStore()
        let client = try client(identityStore: store)
        let pause = SetupPause()
        let setup = Task { try await client.setupDeviceCredential { try await pause.wait() } }
        await pause.waitForEntry()
        setup.cancel()
        do { _ = try await setup.value; XCTFail("canceled setup succeeded") }
        catch is CancellationError {}
        do {
            _ = try await client.setupDeviceCredential { throw SetupFailure.retry }
            XCTFail("failed setup succeeded")
        } catch SetupFailure.retry {}
        let writes = await store.writes
        XCTAssertEqual(writes, 0)
    }

    func testUnavailableBiometricsStopsSetupBeforeBrowserOrStorage() async throws {
        let store = SetupIdentityStore()
        let client = try client(identityStore: store)
        do {
            _ = try await client.registerSecureEnclaveCredential(username: "alice", name: "This device",
                                                                  browser: UnusedSetupBrowser(), prompt: "Approve setup")
            XCTFail("unavailable biometrics started setup")
        } catch let error as TeleportError { XCTAssertEqual(error, .biometricsUnavailable) }
        let writes = await store.writes
        XCTAssertEqual(writes, 0)
    }

    #if os(macOS)
    func testOnlyCompleteSetupResultIsStoredAndWriteFailurePreservesOldIdentity() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try proxy()
        let key = try CredentialKey()
        let body = try JSONSerialization.data(withJSONObject: ["ssh_pub_key": Data(key.sshPublicKey.utf8).base64EncodedString(),
                                                               "tls_pub_key": Data(key.tlsPublicKeyPEM.utf8).base64EncodedString()])
        let response = try JSONDecoder().decode(LoginResponse.self, from: issuer.response(to: body))
        let exports = try issuer.authorityExports()
        let trust = try await UserAuthorityTrust.load(proxy: proxy) { _, query, _ in
            try XCTUnwrap(exports[XCTUnwrap(query.first(where: { $0.name == "type" })?.value)])
        }
        let identity = try response.identity(proxy: proxy, username: "alice", cluster: "cluster", key: key, userTrust: trust, ttl: 3600)
        let store = SetupIdentityStore(identity: identity)
        let client = try client(identityStore: store)
        let result = try await client.setupDeviceCredential { identity }
        XCTAssertTrue(result.tlsCertificateDER == identity.tlsCertificateDER)
        await store.failWrites()
        do {
            _ = try await client.setupDeviceCredential { identity }
            XCTFail("failed storage succeeded")
        } catch SetupFailure.storage {}
        let stored = try await client.identity()
        XCTAssertTrue(stored.tlsCertificateDER == identity.tlsCertificateDER)
        let writes = await store.writes
        XCTAssertEqual(writes, 1)
    }
    #endif

    private func proxy() throws -> TeleportProxy { try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example"))) }
    private func client(identityStore: any TeleportIdentityStore = MemoryIdentityStore()) throws -> TeleportClient {
        TeleportClient(proxy: try proxy(), identityStore: identityStore, deviceCredentialStorage: EmptySetupCredentials(),
                       deviceKeyOperations: UnavailableSetupKeys())
    }
}

private enum SetupFailure: Error { case unexpected, retry, storage }
private actor SetupPause {
    private var entered = false
    private var observer: CheckedContinuation<Void, Never>?
    func wait() async throws -> TeleportIdentity {
        entered = true; observer?.resume(); observer = nil
        try await Task.sleep(for: .seconds(10))
        throw SetupFailure.unexpected
    }
    func waitForEntry() async {
        if entered { return }
        await withCheckedContinuation { observer = $0 }
    }
}
private actor SetupIdentityStore: TeleportIdentityStore {
    private var identity: TeleportIdentity?
    private var fails = false
    private(set) var writes = 0
    init(identity: TeleportIdentity? = nil) { self.identity = identity }
    func load() -> TeleportIdentity? { identity }
    func replace(with identity: TeleportIdentity?) throws {
        if fails { throw SetupFailure.storage }
        self.identity = identity; writes += 1
    }
    func failWrites() { fails = true }
}
private struct EmptySetupCredentials: DeviceCredentialStorage {
    func load(username: String) -> DeviceCredential? { nil }
    func add(_ credential: DeviceCredential, username: String) throws { throw SetupFailure.unexpected }
    func delete(username: String) {}
}
private struct UnavailableSetupKeys: DeviceKeyOperations {
    func checkAvailability() throws { throw TeleportError.biometricsUnavailable }
    func create(prompt: String) throws -> DeviceKeyMaterial { throw SetupFailure.unexpected }
    func sign(_ data: Data, protectedKey: Data, prompt: String) throws -> Data { throw SetupFailure.unexpected }
}
private struct UnusedSetupBrowser: TeleportBrowserPresenter {
    @MainActor func open(_ url: URL) throws { throw SetupFailure.unexpected }
}
