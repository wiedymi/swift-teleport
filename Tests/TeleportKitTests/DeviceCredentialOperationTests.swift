import Foundation
import XCTest
@testable import TeleportKit

final class DeviceCredentialOperationTests: XCTestCase, @unchecked Sendable {
    func testSetupOwnsTheOperationBeforeLoadingTheCurrentIdentity() async throws {
        let identityStore = PausedDeviceIdentityLoad()
        let client = TeleportClient(proxy: try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example"))),
                                    identityStore: identityStore, deviceCredentialStorage: PausedDeviceDeletion(),
                                    deviceKeyOperations: SecureEnclaveDeviceKeyOperations())
        let setup = Task { try await client.registerSecureEnclaveCredential(name: "This device", prompt: "Approve setup") }
        await identityStore.waitForLoad()
        do {
            _ = try await client.login(username: "alice", password: "test-password", otp: "123456")
            XCTFail("Login started while setup loaded its identity")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("device credential setup or deletion is active")) }
        try await client.signOut()
        do { try await setup.value; XCTFail("Canceled setup succeeded") }
        catch is CancellationError {}
    }

    func testSignOutCancelsLocalDeletionAndBlocksCompetingAuthentication() async throws {
        let store = PausedDeviceDeletion()
        let client = try client(store: store)
        let deletion = Task { try await client.deleteSecureEnclaveCredential(username: "alice") }
        await store.waitForDelete()
        do {
            _ = try await client.login(username: "alice", password: "test-password", otp: "123456")
            XCTFail("Password login started during credential deletion")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("device credential setup or deletion is active")) }
        do {
            _ = try await client.loginWithSecureEnclave(username: "alice", password: "test-password", prompt: "Approve login")
            XCTFail("Biometric login started during credential deletion")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("device credential setup or deletion is active")) }
        do {
            try await client.deleteSecureEnclaveCredential(username: "alice")
            XCTFail("A second credential operation started")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("another authentication operation is active")) }
        try await client.signOut()
        do { try await deletion.value; XCTFail("Canceled deletion succeeded") }
        catch is CancellationError {}
        await store.stopPausing()
        try await client.deleteSecureEnclaveCredential(username: "alice")
        let count = await store.completed
        XCTAssertEqual(count, 1)
    }

    func testCancelingCredentialOperationReleasesTheClientForRetry() async throws {
        let store = PausedDeviceDeletion()
        let client = try client(store: store)
        let deletion = Task { try await client.deleteSecureEnclaveCredential(username: "alice") }
        await store.waitForDelete()
        deletion.cancel()
        do { try await deletion.value; XCTFail("Canceled deletion succeeded") }
        catch is CancellationError {}
        await store.stopPausing()
        try await client.deleteSecureEnclaveCredential(username: "alice")
        let count = await store.completed
        XCTAssertEqual(count, 1)
    }

    private func client(store: PausedDeviceDeletion) throws -> TeleportClient {
        TeleportClient(proxy: try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example"))), identityStore: MemoryIdentityStore(),
                       deviceCredentialStorage: store, deviceKeyOperations: SecureEnclaveDeviceKeyOperations())
    }
}

private actor PausedDeviceIdentityLoad: TeleportIdentityStore {
    private var entered = false
    private var observer: CheckedContinuation<Void, Never>?
    func load() async throws -> TeleportIdentity? {
        entered = true; observer?.resume(); observer = nil
        try await Task.sleep(for: .seconds(10))
        return nil
    }
    func replace(with identity: TeleportIdentity?) {}
    func waitForLoad() async {
        if entered { return }
        await withCheckedContinuation { observer = $0 }
    }
}

private actor PausedDeviceDeletion: DeviceCredentialStorage {
    private var pausing = true
    private var entered = false
    private var observer: CheckedContinuation<Void, Never>?
    private(set) var completed = 0
    func load(username: String) -> DeviceCredential? { nil }
    func add(_ credential: DeviceCredential, username: String) { XCTFail("Unexpected credential write") }
    func delete(username: String) async throws {
        entered = true; observer?.resume(); observer = nil
        if pausing { try await Task.sleep(for: .seconds(10)) }
        try Task.checkCancellation()
        completed += 1
    }
    func waitForDelete() async {
        if entered { return }
        await withCheckedContinuation { observer = $0 }
    }
    func stopPausing() { pausing = false }
}
