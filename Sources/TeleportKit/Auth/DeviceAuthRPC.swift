import Foundation
import SwiftProtobuf
import TeleportCore

/// The native registration calls use the same verified Auth mTLS route as node lookup.
enum DeviceAuthRPC {
    static let authenticatePath = "/proto.AuthService/CreateAuthenticateChallenge"
    static let registrationPath = "/proto.AuthService/CreateRegisterChallenge"
    static let addPath = "/proto.AuthService/AddMFADeviceSync"

    enum ManagementChallenge: Equatable, Sendable {
        case none
        case totp
        case browser(String)
    }

    static func authenticationRequest(proxy: TeleportProxy, callbackURL: URL?) throws -> Data {
        var request = Teleportkit_Deviceauth_CreateAuthenticateChallengeRequest()
        request.contextUser = Teleportkit_Deviceauth_ContextUser()
        request.challengeExtensions.scope = 4 // MANAGE_DEVICES
        request.challengeExtensions.allowReuse = 2 // NO
        guard let host = proxy.url.host else { throw TeleportError.invalidConfiguration("proxy host") }
        let address = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        request.proxyAddress = address + (proxy.url.port.map { ":\($0)" } ?? "")
        if let callbackURL { request.browserMfaTshRedirectURL = callbackURL.absoluteString }
        return try request.serializedData()
    }

    static func managementChallenge(_ bytes: Data) throws -> ManagementChallenge {
        let response: Teleportkit_Deviceauth_MFAAuthenticateChallenge = try decode(bytes)
        guard (0...2).contains(response.mfaRequired) else { throw TeleportError.invalidResponse("device approval requirement") }
        if response.hasSsoChallenge { throw TeleportError.unsupportedPolicy(.sessionMFA) }
        if response.hasBrowserMfaChallenge {
            let id = response.browserMfaChallenge.requestID
            guard id.utf8.count == 36, let uuid = UUID(uuidString: id), uuid.uuidString.lowercased() == id.lowercased() else {
                throw TeleportError.invalidResponse("device approval request ID")
            }
            return .browser(id)
        }
        if response.hasTotp { return .totp }
        if response.hasWebauthnChallenge { throw TeleportError.unsupportedPolicy(.browserMFA) }
        guard response.mfaRequired != 1 else { throw TeleportError.invalidResponse("device approval challenge") }
        return .none
    }

    static func registrationRequest(approval: BrowserMFAResponse? = nil, otp: String? = nil) throws -> Data {
        guard approval == nil || otp == nil else { throw TeleportError.invalidConfiguration("one device approval method is required") }
        var request = Teleportkit_Deviceauth_CreateRegisterChallengeRequest()
        request.deviceType = 3 // WEBAUTHN
        request.deviceUsage = 1 // MFA
        if let approval {
            try approval.webauthnResponse.validate()
            var browser = Teleportkit_Deviceauth_BrowserMFAResponse()
            browser.requestID = approval.requestId
            browser.webauthnResponse = try assertion(approval.webauthnResponse)
            request.existingMfaResponse.browser = browser
        } else if let otp {
            guard (6...8).contains(otp.utf8.count), otp.utf8.allSatisfy({ (48...57).contains($0) }) else {
                throw TeleportError.invalidConfiguration("device approval TOTP code")
            }
            request.existingMfaResponse.totp.code = otp
        }
        return try request.serializedData()
    }

    /// Match Teleport's public WebAuthn creation JSON, so native creation has one validator.
    static func registrationChallenge(_ bytes: Data) throws -> Data {
        let response: Teleportkit_Deviceauth_MFARegisterChallenge = try decode(bytes)
        guard case .webauthn(let creation)? = response.request, creation.hasPublicKey else {
            throw TeleportError.invalidResponse("device registration challenge")
        }
        let options = creation.publicKey
        guard options.credentialParameters.count <= 128, options.excludeCredentials.count <= 128 else {
            throw TeleportError.limitExceeded("device registration options")
        }
        let credentials: [[String: Any]] = options.excludeCredentials.map { ["type": $0.type, "id": $0.id.base64EncodedString()] }
        let parameters: [[String: Any]] = options.credentialParameters.map { ["type": $0.type, "alg": $0.alg] }
        let publicKey: [String: Any] = [
            "challenge": options.challenge.base64EncodedString(),
            "rp": ["id": options.rp.id, "name": options.rp.name],
            "user": ["id": options.user.id.base64EncodedString(), "name": options.user.name, "displayName": options.user.displayName],
            "pubKeyCredParams": parameters,
            "timeout": options.timeoutMs,
            "excludeCredentials": credentials,
            "attestation": options.attestation,
            "extensions": ["appid": options.extensions.appID, "credProps": options.extensions.credProps],
            "authenticatorSelection": [
                "authenticatorAttachment": options.authenticatorSelection.authenticatorAttachment,
                "requireResidentKey": options.authenticatorSelection.requireResidentKey,
                "userVerification": options.authenticatorSelection.userVerification,
            ],
        ]
        return try JSONSerialization.data(withJSONObject: ["publicKey": publicKey])
    }

    static func addRequest(deviceName: String, credentialID: Data, clientDataJSON: Data, attestationObject: Data) throws -> Data {
        guard !deviceName.isEmpty, deviceName.utf8.count <= 30, !credentialID.isEmpty, credentialID.count <= 1024,
              !clientDataJSON.isEmpty, clientDataJSON.count <= 16_384,
              !attestationObject.isEmpty, attestationObject.count <= 65_536 else {
            throw TeleportError.invalidConfiguration("device registration bounds")
        }
        var creation = Teleportkit_Deviceauth_CredentialCreationResponse()
        creation.type = "public-key"
        creation.rawID = credentialID
        creation.response.clientDataJson = clientDataJSON
        creation.response.attestationObject = attestationObject
        creation.extensions.credProps = Teleportkit_Deviceauth_CredentialPropertiesOutput()
        var request = Teleportkit_Deviceauth_AddMFADeviceSyncRequest()
        request.newDeviceName = deviceName
        request.newMfaResponse.webauthn = creation
        request.deviceUsage = 1 // MFA
        request.contextUser = Teleportkit_Deviceauth_ContextUser()
        return try request.serializedData()
    }

    static func validateAddedDevice(_ bytes: Data, credentialID: Data, rpID: String, publicKeyCOSE: Data) throws {
        let response: Teleportkit_Deviceauth_AddMFADeviceSyncResponse = try decode(bytes)
        guard response.hasDevice, case .webauthn(let device)? = response.device.device,
              device.credentialID == credentialID,
              device.credentialRpID == rpID,
              device.publicKeyCbor == publicKeyCOSE else {
            throw TeleportError.invalidResponse("registered device binding")
        }
    }

    private static func assertion(_ value: BrowserMFAAssertion) throws -> Teleportkit_Deviceauth_CredentialAssertionResponse {
        var response = Teleportkit_Deviceauth_CredentialAssertionResponse()
        response.type = value.type
        response.rawID = try urlBytes(value.rawId)
        response.response.clientDataJson = try urlBytes(value.response.clientDataJSON)
        response.response.authenticatorData = try urlBytes(value.response.authenticatorData)
        response.response.signature = try urlBytes(value.response.signature)
        if let handle = value.response.userHandle, !handle.isEmpty { response.response.userHandle = try urlBytes(handle) }
        if let extensions = value.extensions {
            var outputs = Teleportkit_Deviceauth_AuthenticationExtensionsClientOutputs()
            outputs.appID = extensions.appid ?? false
            if let properties = extensions.credProps {
                var props = Teleportkit_Deviceauth_CredentialPropertiesOutput()
                props.rk = properties.rk ?? false
                outputs.credProps = props
            }
            response.extensions = outputs
        }
        return response
    }

    private static func urlBytes(_ string: String) throws -> Data {
        let unpadded = string.prefix(while: { $0 != "=" })
        var standard = unpadded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let data = Data(base64Encoded: standard) else { throw TeleportError.invalidResponse("device approval byte field") }
        return data
    }

    private static func decode<T: SwiftProtobuf.Message>(_ bytes: Data) throws -> T {
        guard bytes.count <= 1_048_576 else { throw TeleportError.limitExceeded("device authentication response") }
        var options = BinaryDecodingOptions()
        options.messageDepthLimit = 8
        options.discardUnknownFields = true
        do { return try T(serializedBytes: bytes, options: options) }
        catch { throw TeleportError.invalidResponse("device authentication protobuf") }
    }
}
