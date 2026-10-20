import CryptoKit
import Foundation
import Security
import TeleportCore

struct DeviceCredential: Codable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let clusterName: String
    let credentialID: Data
    /// An opaque encrypted representation. The private key stays in the Secure Enclave.
    let protectedKey: Data

    func validate() throws {
        guard !clusterName.isEmpty, clusterName.utf8.count <= 1024,
              !clusterName.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              !credentialID.isEmpty, credentialID.count <= 1024,
              !protectedKey.isEmpty, protectedKey.count <= 16_384 else {
            throw TeleportError.deviceCredentialStorage
        }
    }

    var description: String { "DeviceCredential(<redacted>)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: [:]) }
}

protocol DeviceCredentialStorage: Sendable {
    func load(username: String) async throws -> DeviceCredential?
    func add(_ credential: DeviceCredential, username: String) async throws
    func delete(username: String) async throws
}

actor KeychainDeviceCredentialStore: DeviceCredentialStorage {
    private let proxy: TeleportProxy
    private let configuration: TeleportSecureEnclaveConfiguration

    init(proxy: TeleportProxy, configuration: TeleportSecureEnclaveConfiguration) {
        self.proxy = proxy
        self.configuration = configuration
    }

    func load(username: String) throws -> DeviceCredential? {
        try Task.checkCancellation()
        var query = try query(username: username)
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecReturnData] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 65_536 else {
            throw TeleportError.deviceCredentialStorage
        }
        do {
            let credential = try JSONDecoder().decode(DeviceCredential.self, from: data)
            try credential.validate()
            return credential
        } catch {
            throw TeleportError.deviceCredentialStorage
        }
    }

    func add(_ credential: DeviceCredential, username: String) throws {
        try Task.checkCancellation()
        try credential.validate()
        var query = try query(username: username)
        let data = try JSONEncoder().encode(credential)
        guard data.count <= 65_536 else { throw TeleportError.deviceCredentialStorage }
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        query[kSecValueData] = data
        try Task.checkCancellation()
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status != errSecDuplicateItem else { throw TeleportError.deviceCredentialExists }
        guard status == errSecSuccess else { throw TeleportError.deviceCredentialStorage }
    }

    func delete(username: String) throws {
        try Task.checkCancellation()
        let status = SecItemDelete(try query(username: username) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw TeleportError.deviceCredentialStorage }
    }

    nonisolated static func account(proxy: TeleportProxy, username: String) throws -> String {
        guard !username.isEmpty, username.utf8.count <= 1024,
              !username.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw TeleportError.invalidConfiguration("device credential storage")
        }
        // HTTPS origin cannot contain a NUL; the separator makes the two fields unambiguous.
        var scope = Data(proxy.url.absoluteString.utf8)
        scope.append(0)
        scope.append(contentsOf: username.utf8)
        return SHA256.hash(data: scope).map { String(format: "%02x", $0) }.joined()
    }

    private func query(username: String) throws -> [CFString: Any] {
        var query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                     kSecAttrService: configuration.keychainService,
                                     kSecAttrAccount: try Self.account(proxy: proxy, username: username),
                                     kSecUseDataProtectionKeychain: true,
                                     kSecAttrSynchronizable: false]
        if let group = configuration.accessGroup { query[kSecAttrAccessGroup] = group }
        return query
    }
}
