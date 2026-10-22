import CryptoKit
import Foundation
import TeleportCore

/// ES256 device credentials for MFA or passwordless login.
enum DeviceWebAuthn {
    struct Descriptor: Decodable {
        let type: String
        let id: Data
    }
    struct Selection {
        let authenticatorAttachment: String
        let requireResidentKey: Bool
        let userVerification: String
    }
    struct Creation {
        struct Options {
            struct RP { let id: String }
            struct User {
                let id: Data
                let name: String
            }
            struct Parameter {
                let type: String
                let alg: Int
            }
            let rp: RP
            let user: User
            let challenge: Data
            let pubKeyCredParams: [Parameter]
            let excludeCredentials: [Descriptor]
            let authenticatorSelection: Selection
            let attestation: String
        }
        let publicKey: Options

        func validate(proxy: TeleportProxy, username: String, usage: DeviceCredentialUsage = .mfa) throws {
            try DeviceWebAuthn.validate(rpID: publicKey.rp.id, challenge: publicKey.challenge, proxy: proxy)
            guard publicKey.user.name == username, !publicKey.user.id.isEmpty, publicKey.user.id.count <= 64,
                  publicKey.pubKeyCredParams.count <= 32,
                  publicKey.excludeCredentials.count <= 128 else { throw TeleportError.invalidResponse("WebAuthn registration binding") }
            guard publicKey.pubKeyCredParams.contains(where: { $0.type == "public-key" && $0.alg == -7 }),
                  publicKey.attestation.isEmpty || publicKey.attestation == "none" else {
                throw TeleportError.unsupportedPolicy(.authenticatorRequirements)
            }
            let selection = publicKey.authenticatorSelection
            guard selection.requireResidentKey == (usage == .passwordless),
                  ["", "platform"].contains(selection.authenticatorAttachment),
                  ["", "discouraged", "preferred", "required"].contains(selection.userVerification),
                  usage == .mfa || selection.userVerification == "required" else {
                throw TeleportError.unsupportedPolicy(.authenticatorRequirements)
            }
            try DeviceWebAuthn.validate(descriptors: publicKey.excludeCredentials)
        }
    }
    struct AssertionChallenge: Decodable {
        struct Options: Decodable {
            let challenge: Data
            let rpId: String
            let allowCredentials: [Descriptor]?
            let userVerification: String?
        }
        let publicKey: Options

        func validate(proxy: TeleportProxy, credentialID: Data, usage: DeviceCredentialUsage = .mfa) throws {
            try DeviceWebAuthn.validate(rpID: publicKey.rpId, challenge: publicKey.challenge, proxy: proxy)
            let allowed = publicKey.allowCredentials ?? []
            guard allowed.count <= 128 else { throw TeleportError.limitExceeded("WebAuthn credential descriptors") }
            guard usage == .passwordless || !allowed.isEmpty else { throw TeleportError.unsupportedPolicy(.passwordless) }
            try DeviceWebAuthn.validate(descriptors: allowed)
            guard allowed.isEmpty || allowed.contains(where: { $0.id == credentialID }) else { throw TeleportError.deviceCredentialMissing }
            guard ["", "discouraged", "preferred", "required"].contains(publicKey.userVerification ?? "") else {
                throw TeleportError.unsupportedPolicy(.authenticatorRequirements)
            }
            guard usage == .mfa || publicKey.userVerification == "required" else {
                throw TeleportError.unsupportedPolicy(.authenticatorRequirements)
            }
        }
    }
    struct Registration: Sendable {
        let credentialID: Data
        let clientDataJSON: Data
        let attestationObject: Data
        let publicKeyCOSE: Data
    }

    static func registration(challenge: Creation, proxy: TeleportProxy, username: String,
                             key: DeviceKeyMaterial, keys: any DeviceKeyOperations, prompt: String,
                             usage: DeviceCredentialUsage = .mfa) async throws -> Registration {
        try challenge.validate(proxy: proxy, username: username, usage: usage)
        guard key.publicKeyX963.count == 65, key.publicKeyX963.first == 4,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: key.publicKeyX963) else {
            throw TeleportError.invalidResponse("device public key")
        }
        let credentialID = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        guard !challenge.publicKey.excludeCredentials.contains(where: { $0.id == credentialID }) else {
            throw TeleportError.deviceCredentialExists
        }
        let clientData = try clientData(type: "webauthn.create", challenge: challenge.publicKey.challenge, proxy: proxy)
        // Fixed COSE map: EC2 key, ES256 algorithm, P-256 curve, then X and Y coordinates.
        var publicKeyCOSE = Data([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        publicKeyCOSE.append(key.publicKeyX963.dropFirst().prefix(32))
        publicKeyCOSE.append(contentsOf: [0x22, 0x58, 0x20])
        publicKeyCOSE.append(key.publicKeyX963.suffix(32))

        var authData = authenticatorData(rpID: challenge.publicKey.rp.id, flags: 0x45)
        authData.append(Data(repeating: 0, count: 16)) // No vendor attestation identifier.
        authData.append(contentsOf: [0, 32]) // Two-byte length for the 32-byte credential ID.
        authData.append(credentialID)
        authData.append(publicKeyCOSE)

        // fmt:none carries no signature. A local signature check still requires biometrics and binds this key.
        let signedData = authData + Data(SHA256.hash(data: clientData))
        let signatureBytes = try await keys.sign(signedData, protectedKey: key.protectedKey, prompt: prompt)
        try Task.checkCancellation()
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureBytes),
              publicKey.isValidSignature(signature, for: signedData) else {
            throw TeleportError.invalidResponse("device authentication key")
        }

        guard authData.count <= 255 else { throw TeleportError.limitExceeded("WebAuthn attestation") }
        // CBOR map with fmt:"none", attStmt:{}, and the authenticator data.
        var attestationObject = Data([0xa3, 0x63])
        attestationObject.append(contentsOf: "fmt".utf8)
        attestationObject.append(0x64)
        attestationObject.append(contentsOf: "none".utf8)
        attestationObject.append(0x67)
        attestationObject.append(contentsOf: "attStmt".utf8)
        attestationObject.append(0xa0)
        attestationObject.append(0x68)
        attestationObject.append(contentsOf: "authData".utf8)
        attestationObject.append(contentsOf: [0x58, UInt8(authData.count)])
        attestationObject.append(authData)
        return Registration(credentialID: credentialID, clientDataJSON: clientData,
                            attestationObject: attestationObject, publicKeyCOSE: publicKeyCOSE)
    }

    static func assertion(challenge: AssertionChallenge, credential: DeviceCredential, proxy: TeleportProxy,
                          keys: any DeviceKeyOperations, prompt: String,
                          usage: DeviceCredentialUsage = .mfa) async throws -> BrowserMFAAssertion {
        try credential.validate()
        guard usage == .mfa || credential.userHandle != nil else { throw TeleportError.deviceCredentialMissing }
        try challenge.validate(proxy: proxy, credentialID: credential.credentialID, usage: usage)
        let clientData = try clientData(type: "webauthn.get", challenge: challenge.publicKey.challenge, proxy: proxy)
        let auth = authenticatorData(rpID: challenge.publicKey.rpId, flags: 0x05)
        let signature = try await keys.sign(auth + Data(SHA256.hash(data: clientData)), protectedKey: credential.protectedKey, prompt: prompt)
        try Task.checkCancellation()
        let assertion = BrowserMFAAssertion(id: urlBytes(credential.credentialID), type: "public-key", rawId: urlBytes(credential.credentialID),
                                            extensions: .init(appid: false, credProps: nil),
                                            response: .init(clientDataJSON: urlBytes(clientData), authenticatorData: urlBytes(auth),
                                                            signature: urlBytes(signature),
                                                            userHandle: usage == .passwordless ? credential.userHandle.map(urlBytes) : nil))
        try assertion.validate()
        return assertion
    }

    static func decode<T: Decodable>(_ data: Data, field: String) throws -> T {
        guard data.count <= 1_048_576 else { throw TeleportError.limitExceeded("authentication response") }
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw TeleportError.invalidResponse(field) }
    }

    private static func validate(rpID: String, challenge: Data, proxy: TeleportProxy) throws {
        // Exact match avoids a public-suffix dependency and keeps each credential on one configured proxy.
        guard !rpID.isEmpty, rpID.utf8.count <= 253, rpID == proxy.url.host,
              !challenge.isEmpty, challenge.count <= 1024 else { throw TeleportError.invalidResponse("WebAuthn relying party or challenge") }
    }
    private static func validate(descriptors: [Descriptor]) throws {
        guard descriptors.allSatisfy({ $0.type == "public-key" && !$0.id.isEmpty && $0.id.count <= 1024 }) else {
            throw TeleportError.invalidResponse("WebAuthn credential descriptor")
        }
    }
    private static func clientData(type: String, challenge: Data, proxy: TeleportProxy) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["type": type, "challenge": urlBytes(challenge), "origin": proxy.url.absoluteString, "crossOrigin": false])
    }
    private static func authenticatorData(rpID: String, flags: UInt8) -> Data {
        Data(SHA256.hash(data: Data(rpID.utf8))) + Data([flags, 0, 0, 0, 0])
    }
    private static func urlBytes(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").filter { $0 != "=" }
    }
}
