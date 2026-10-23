import CryptoKit
import Foundation
import LocalAuthentication
import Security
import TeleportCore

struct DeviceKeyMaterial: Sendable {
    let protectedKey: Data
    let publicKeyX963: Data
}

protocol DeviceKeyOperations: Sendable {
    func checkAvailability() async throws
    func create(prompt: String) async throws -> DeviceKeyMaterial
    /// Returns the ASN.1 DER ECDSA signature required by WebAuthn ES256.
    func sign(_ data: Data, protectedKey: Data, prompt: String) async throws -> Data
    func withAuthentication<Result: Sendable>(
        prompt: String, operation: @Sendable (any DeviceKeyOperations) async throws -> Result
    ) async throws -> Result
}

extension DeviceKeyOperations {
    func checkAvailability() async throws {}
    func withAuthentication<Result: Sendable>(
        prompt: String, operation: @Sendable (any DeviceKeyOperations) async throws -> Result
    ) async throws -> Result {
        try await operation(self)
    }
}

struct SecureEnclaveDeviceKeyOperations: DeviceKeyOperations {
    private let scopedAuthentication: AuthenticationPrompt?

    init() { scopedAuthentication = nil }
    private init(authentication: AuthenticationPrompt) { scopedAuthentication = authentication }

    func withAuthentication<Result: Sendable>(
        prompt: String, operation: @Sendable (any DeviceKeyOperations) async throws -> Result
    ) async throws -> Result {
        try Self.validatePrompt(prompt)
        return try await withAuthentication(AuthenticationPrompt(reason: prompt), operation: operation)
    }

    func withAuthentication<Result: Sendable>(
        _ authentication: AuthenticationPrompt, operation: @Sendable (any DeviceKeyOperations) async throws -> Result
    ) async throws -> Result {
        defer { authentication.context.invalidate() }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let result = try await operation(Self(authentication: authentication))
            try Task.checkCancellation()
            return result
        } onCancel: {
            authentication.context.invalidate()
        }
    }

    func authenticationPrompt(reason: String) -> AuthenticationPrompt {
        scopedAuthentication ?? AuthenticationPrompt(reason: reason)
    }

    func checkAvailability() async throws {
        try Task.checkCancellation()
        try await Task.detached {
            let context = LAContext()
            defer { context.invalidate() }
            try Self.requireBiometrics(context)
        }.value
        try Task.checkCancellation()
    }

    func create(prompt: String) async throws -> DeviceKeyMaterial {
        try Self.validatePrompt(prompt)
        let authentication = authenticationPrompt(reason: prompt)
        defer { if scopedAuthentication == nil { authentication.context.invalidate() } }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            do {
                let material = try await Task.detached {
                    try Self.requireBiometrics(authentication.context)
                    var error: Unmanaged<CFError>?
                    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                       [.privateKeyUsage, .biometryCurrentSet], &error) else {
                        throw TeleportError.secureEnclaveUnavailable
                    }
                    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access,
                                                                       authenticationContext: authentication.context)
                    return DeviceKeyMaterial(protectedKey: key.dataRepresentation, publicKeyX963: key.publicKey.x963Representation)
                }.value
                try Task.checkCancellation()
                return material
            } catch {
                throw mapped(error)
            }
        } onCancel: {
            authentication.context.invalidate()
        }
    }

    func sign(_ data: Data, protectedKey: Data, prompt: String) async throws -> Data {
        try Self.validatePrompt(prompt)
        guard !protectedKey.isEmpty, protectedKey.count <= 16_384 else { throw TeleportError.deviceCredentialMissing }
        let authentication = authenticationPrompt(reason: prompt)
        defer { if scopedAuthentication == nil { authentication.context.invalidate() } }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            do {
                let signature = try await Task.detached {
                    try Self.requireBiometrics(authentication.context)
                    let key: SecureEnclave.P256.Signing.PrivateKey
                    do {
                        key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: protectedKey,
                                                                       authenticationContext: authentication.context)
                    } catch {
                        if error is LAError { throw error }
                        let systemError = error as NSError
                        if systemError.domain == NSOSStatusErrorDomain,
                           systemError.code == Int(errSecUserCanceled) { throw error }
                        throw TeleportError.deviceCredentialMissing
                    }
                    return try key.signature(for: data).derRepresentation
                }.value
                try Task.checkCancellation()
                return signature
            } catch {
                throw mapped(error)
            }
        } onCancel: {
            authentication.context.invalidate()
        }
    }

    static func validatePrompt(_ prompt: String) throws {
        guard !prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, prompt.utf8.count <= 1024,
              !prompt.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw TeleportError.invalidConfiguration("biometric prompt")
        }
    }

    private static func requireBiometrics(_ context: LAContext) throws {
        guard SecureEnclave.isAvailable else { throw TeleportError.secureEnclaveUnavailable }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw TeleportError.biometricsUnavailable
        }
    }

    private func mapped(_ error: any Error) -> any Error {
        if Task.isCancelled || error is CancellationError { return CancellationError() }
        if let error = error as? TeleportError { return error }
        if let error = error as? LAError {
            switch error.code {
            case .appCancel, .systemCancel, .userCancel: return CancellationError()
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout: return TeleportError.biometricsUnavailable
            default: return TeleportError.accessDenied
            }
        }
        let status = error as NSError
        if status.domain == NSOSStatusErrorDomain {
            switch status.code {
            case Int(errSecUserCanceled): return CancellationError()
            case Int(errSecItemNotFound): return TeleportError.deviceCredentialMissing
            default: break
            }
        }
        // System error descriptions can include private key or authentication details.
        return TeleportError.accessDenied
    }
}

/// The context is configured before use. Only invalidation crosses the blocking key operation.
final class AuthenticationPrompt: @unchecked Sendable {
    let context: LAContext

    init(reason: String, context: LAContext = LAContext()) {
        context.localizedReason = reason
        context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        self.context = context
    }
}
