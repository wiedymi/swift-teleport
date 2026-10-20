import CryptoKit
import Foundation
import TeleportCore

/// Only the non-resident ES256 MFA credential used by this library is supported.
enum DeviceWebAuthn {
    struct Descriptor: Decodable { let type: String; let id: Data }
    struct Selection: Decodable {
        let authenticatorAttachment: String?
        let requireResidentKey: Bool?
        let residentKey: String?
        let userVerification: String?
    }
    struct Creation: Decodable {
        struct Options: Decodable {
            struct RP: Decodable { let id: String }
            struct User: Decodable { let id: Data; let name: String }
            struct Parameter: Decodable { let type: String; let alg: Int }
            let rp: RP
            let user: User
            let challenge: Data
            let pubKeyCredParams: [Parameter]
            let excludeCredentials: [Descriptor]?
            let authenticatorSelection: Selection?
            let attestation: String?
        }
        let publicKey: Options

        func validate(proxy: TeleportProxy, username: String) throws {
            try DeviceWebAuthn.validate(rpID: publicKey.rp.id, challenge: publicKey.challenge, proxy: proxy)
            guard publicKey.user.name == username, !publicKey.user.id.isEmpty, publicKey.user.id.count <= 64,
                  publicKey.pubKeyCredParams.count <= 32,
                  (publicKey.excludeCredentials?.count ?? 0) <= 128 else { throw TeleportError.invalidResponse("WebAuthn registration binding") }
            guard publicKey.pubKeyCredParams.contains(where: { $0.type == "public-key" && $0.alg == -7 }),
                  publicKey.attestation == nil || publicKey.attestation == "" || publicKey.attestation == "none" else {
                throw TeleportError.unsupportedPolicy(.authenticatorRequirements)
            }
            let selection = publicKey.authenticatorSelection
            guard selection?.requireResidentKey != true,
                  ["", "discouraged", "preferred"].contains(selection?.residentKey ?? ""),
                  ["", "platform"].contains(selection?.authenticatorAttachment ?? ""),
                  ["", "discouraged", "preferred", "required"].contains(selection?.userVerification ?? "") else {
                throw TeleportError.unsupportedPolicy(.authenticatorRequirements)
            }
            try DeviceWebAuthn.validate(descriptors: publicKey.excludeCredentials ?? [])
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

        func validate(proxy: TeleportProxy, credentialID: Data) throws {
            try DeviceWebAuthn.validate(rpID: publicKey.rpId, challenge: publicKey.challenge, proxy: proxy)
            let allowed = publicKey.allowCredentials ?? []
            guard !allowed.isEmpty, allowed.count <= 128 else { throw TeleportError.unsupportedPolicy(.passwordless) }
            try DeviceWebAuthn.validate(descriptors: allowed)
            guard allowed.contains(where: { $0.id == credentialID }) else { throw TeleportError.deviceCredentialMissing }
            guard ["", "discouraged", "preferred", "required"].contains(publicKey.userVerification ?? "") else {
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
                             key: DeviceKeyMaterial, keys: any DeviceKeyOperations, prompt: String) async throws -> Registration {
        try challenge.validate(proxy: proxy, username: username)
        guard key.publicKeyX963.count == 65, key.publicKeyX963.first == 4,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: key.publicKeyX963) else {
            throw TeleportError.invalidResponse("device public key")
        }
        let id = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        guard !(challenge.publicKey.excludeCredentials ?? []).contains(where: { $0.id == id }) else {
            throw TeleportError.deviceCredentialExists
        }
        let clientData = try clientData(type: "webauthn.create", challenge: challenge.publicKey.challenge, proxy: proxy)
        // Fixed COSE EC2/P-256/ES256 map. No general CBOR parser or authenticator framework is needed.
        var cose = Data([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        cose.append(key.publicKeyX963.dropFirst().prefix(32)); cose.append(contentsOf: [0x22, 0x58, 0x20]); cose.append(key.publicKeyX963.suffix(32))
        var auth = authenticatorData(rpID: challenge.publicKey.rp.id, flags: 0x45)
        auth.append(Data(repeating: 0, count: 16)) // No vendor attestation identifier.
        auth.append(contentsOf: [0, 32]); auth.append(id); auth.append(cose)
        // fmt:none has no attestation signature. Still use the protected key so UP/UV reflect a biometric check.
        let signed = auth + Data(SHA256.hash(data: clientData))
        let signatureBytes = try await keys.sign(signed, protectedKey: key.protectedKey, prompt: prompt)
        try Task.checkCancellation()
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureBytes),
              publicKey.isValidSignature(signature, for: signed) else { throw TeleportError.invalidResponse("device authentication key") }
        guard auth.count <= 255 else { throw TeleportError.limitExceeded("WebAuthn attestation") }
        var attestation = Data([0xa3, 0x63])
        attestation.append(Data("fmt".utf8)); attestation.append(0x64); attestation.append(Data("none".utf8))
        attestation.append(0x67); attestation.append(Data("attStmt".utf8)); attestation.append(0xa0)
        attestation.append(0x68); attestation.append(Data("authData".utf8)); attestation.append(contentsOf: [0x58, UInt8(auth.count)]); attestation.append(auth)
        return Registration(credentialID: id, clientDataJSON: clientData, attestationObject: attestation, publicKeyCOSE: cose)
    }

    static func assertion(challenge: AssertionChallenge, credential: DeviceCredential, proxy: TeleportProxy,
                          keys: any DeviceKeyOperations, prompt: String) async throws -> BrowserMFAAssertion {
        try challenge.validate(proxy: proxy, credentialID: credential.credentialID)
        let clientData = try clientData(type: "webauthn.get", challenge: challenge.publicKey.challenge, proxy: proxy)
        let auth = authenticatorData(rpID: challenge.publicKey.rpId, flags: 0x05)
        let signature = try await keys.sign(auth + Data(SHA256.hash(data: clientData)), protectedKey: credential.protectedKey, prompt: prompt)
        try Task.checkCancellation()
        let assertion = BrowserMFAAssertion(id: urlBytes(credential.credentialID), type: "public-key", rawId: urlBytes(credential.credentialID),
                                            extensions: .init(appid: false, credProps: nil),
                                            response: .init(clientDataJSON: urlBytes(clientData), authenticatorData: urlBytes(auth),
                                                            signature: urlBytes(signature), userHandle: nil))
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
