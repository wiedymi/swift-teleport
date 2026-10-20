import Foundation
import XCTest
@testable import TeleportKit

final class DeviceCredentialStorageTests: XCTestCase, @unchecked Sendable {
    func testStorageScopeUsesCanonicalProxyAndExactAccount() throws {
        let canonical = try proxy("https://proxy.example")
        let equivalent = try proxy("https://PROXY.example:443/")
        let expected = try KeychainDeviceCredentialStore.account(proxy: canonical, username: "alice")
        XCTAssertEqual(expected, try KeychainDeviceCredentialStore.account(proxy: equivalent, username: "alice"))
        XCTAssertEqual(expected.utf8.count, 64)
        XCTAssertTrue(expected.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) })
        for (origin, username) in [
            ("https://other.example", "alice"),
            ("https://proxy.example:3080", "alice"),
            ("https://proxy.example", "Alice"),
            ("https://proxy.example", "alice "),
            ("https://proxy.example", "bob"),
        ] {
            XCTAssertNotEqual(expected, try KeychainDeviceCredentialStore.account(proxy: proxy(origin), username: username))
        }
    }

    func testStorageScopeRejectsEmptyLongAndControlCharacterAccounts() throws {
        let origin = try proxy("https://proxy.example")
        _ = try KeychainDeviceCredentialStore.account(proxy: origin, username: String(repeating: "a", count: 1024))
        for username in ["", "alice\u{0}other", "alice\n", String(repeating: "a", count: 1025), String(repeating: "é", count: 513)] {
            XCTAssertThrowsError(try KeychainDeviceCredentialStore.account(proxy: origin, username: username)) { error in
                XCTAssertEqual(error as? TeleportError, .invalidConfiguration("device credential storage"))
            }
        }
    }

    func testStorageConfigurationValidatesEachAppSuppliedName() throws {
        let longest = String(repeating: "a", count: 255)
        let configuration = try TeleportSecureEnclaveConfiguration(keychainService: longest, accessGroup: longest)
        XCTAssertEqual(configuration.keychainService, longest)
        XCTAssertEqual(configuration.accessGroup, longest)
        XCTAssertNil(try TeleportSecureEnclaveConfiguration(keychainService: "test.service").accessGroup)
        for invalid in ["", "test\u{0}service", "test\nservice", String(repeating: "a", count: 256), String(repeating: "é", count: 128)] {
            XCTAssertThrowsError(try TeleportSecureEnclaveConfiguration(keychainService: invalid)) { error in
                XCTAssertEqual(error as? TeleportError, .invalidConfiguration("device credential storage"))
            }
            XCTAssertThrowsError(try TeleportSecureEnclaveConfiguration(keychainService: "test.service", accessGroup: invalid)) { error in
                XCTAssertEqual(error as? TeleportError, .invalidConfiguration("device credential storage"))
            }
        }
    }

    func testStoredCredentialRejectsMissingOversizedAndInvalidFields() throws {
        try credential().validate()
        try credential(cluster: String(repeating: "a", count: 1024), id: Data(repeating: 1, count: 1024),
                       key: Data(repeating: 2, count: 16_384)).validate()
        for invalid in [
            credential(cluster: ""),
            credential(cluster: "cluster\n"),
            credential(cluster: String(repeating: "a", count: 1025)),
            credential(cluster: String(repeating: "é", count: 513)),
            credential(id: Data()),
            credential(id: Data(repeating: 1, count: 1025)),
            credential(key: Data()),
            credential(key: Data(repeating: 2, count: 16_385)),
        ] {
            XCTAssertThrowsError(try invalid.validate()) { error in
                XCTAssertEqual(error as? TeleportError, .deviceCredentialStorage)
            }
        }
    }

    func testCredentialRoundTripPreservesFieldsAndRedactsDebugOutput() throws {
        let original = credential()
        let restored = try JSONDecoder().decode(DeviceCredential.self, from: JSONEncoder().encode(original))
        XCTAssertEqual(restored.clusterName, original.clusterName)
        XCTAssertEqual(restored.credentialID, original.credentialID)
        XCTAssertEqual(restored.protectedKey, original.protectedKey)
        XCTAssertEqual(String(describing: restored), "DeviceCredential(<redacted>)")
        XCTAssertEqual(String(reflecting: restored), "DeviceCredential(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: restored).children.isEmpty)
    }

    func testInvalidPromptFailsBeforeAnyHardwareOperation() async throws {
        let driver = SecureEnclaveDeviceKeyOperations()
        for prompt in ["", "   ", "\t", "Approve\nlogin", String(repeating: "a", count: 1025), String(repeating: "é", count: 513)] {
            do {
                _ = try await driver.create(prompt: prompt)
                XCTFail("invalid prompt was accepted")
            } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("biometric prompt")) }
            do {
                _ = try await driver.sign(Data([1]), protectedKey: Data([2]), prompt: prompt)
                XCTFail("invalid prompt was accepted")
            } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("biometric prompt")) }
        }
    }

    func testCancelledKeyAttemptsStopBeforeAnyHardwareOperation() async throws {
        let driver = SecureEnclaveDeviceKeyOperations()
        let create = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await driver.create(prompt: "Approve login")
        }
        do { _ = try await create.value; XCTFail("canceled key setup was accepted") }
        catch is CancellationError {}
        let sign = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await driver.sign(Data([1]), protectedKey: Data([2]), prompt: "Approve login")
        }
        do { _ = try await sign.value; XCTFail("canceled signing was accepted") }
        catch is CancellationError {}
    }

    private func credential(cluster: String = "cluster", id: Data = Data([1]), key: Data = Data([2])) -> DeviceCredential {
        DeviceCredential(clusterName: cluster, credentialID: id, protectedKey: key)
    }

    private func proxy(_ value: String) throws -> TeleportProxy {
        try TeleportProxy(url: XCTUnwrap(URL(string: value)))
    }
}
