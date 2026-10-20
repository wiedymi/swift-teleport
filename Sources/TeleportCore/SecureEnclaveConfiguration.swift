import Foundation

/// Device-only Keychain storage selected by the consuming app. No credential is created at initialization.
public struct TeleportSecureEnclaveConfiguration: Sendable {
    public let keychainService: String
    public let accessGroup: String?

    public init(keychainService: String, accessGroup: String? = nil) throws {
        for value in [keychainService, accessGroup].compactMap({ $0 }) {
            guard !value.isEmpty, value.utf8.count <= 255,
                  !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
                throw TeleportError.invalidConfiguration("device credential storage")
            }
        }
        self.keychainService = keychainService; self.accessGroup = accessGroup
    }
}
