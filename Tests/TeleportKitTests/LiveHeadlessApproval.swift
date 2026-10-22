#if os(macOS)
import Foundation
import SwiftProtobuf
@testable import TeleportKit

/// Replaces browser UI with real Auth mTLS approval using the lab's registered software authenticator.
struct LiveHeadlessApproval: TeleportBrowserPresenter {
    let identity: TeleportIdentity
    let credential: DeviceCredential
    let keys: any DeviceKeyOperations

    @MainActor
    func open(_ url: URL) async throws {
        let id = url.lastPathComponent
        guard UUID(uuidString: id)?.uuidString.lowercased() == id,
              url == identity.proxy.url.appendingPathComponent("web/headless").appendingPathComponent(id) else {
            throw ApprovalFailure.invalidPage
        }
        // Pinned Auth schema: GetHeadlessAuthenticationRequest.id is string field 1.
        let idBytes = Data(id.utf8)
        guard idBytes.count == 36 else { throw ApprovalFailure.invalidPage }
        let getRequest = Data([0x0a, 36]) + idBytes
        let transport = ProxyTransport()
        _ = try await transport.unary(path: "/proto.AuthService/GetHeadlessAuthentication", message: getRequest, identity: identity)

        var request = try Teleportkit_Deviceauth_CreateAuthenticateChallengeRequest(
            serializedBytes: DeviceAuthRPC.authenticationRequest(proxy: identity.proxy, callbackURL: nil)
        )
        request.challengeExtensions.scope = 3 // HEADLESS_LOGIN; allow_reuse remains NO.
        let bytes = try await transport.unary(path: DeviceAuthRPC.authenticatePath, message: request.serializedData(), identity: identity)
        let response = try Teleportkit_Deviceauth_MFAAuthenticateChallenge(serializedBytes: bytes)
        guard response.hasWebauthnChallenge else { throw ApprovalFailure.missingChallenge }
        let options = response.webauthnChallenge.publicKey
        let challenge = DeviceWebAuthn.AssertionChallenge(publicKey: .init(
            challenge: options.challenge, rpId: options.rpID,
            allowCredentials: options.allowCredentials.map { .init(type: $0.type, id: $0.id) },
            userVerification: options.userVerification
        ))
        let assertion = try await DeviceWebAuthn.assertion(challenge: challenge, credential: credential, proxy: identity.proxy,
                                                          keys: keys, prompt: "Approve test headless login")
        var approval = Teleportkit_Deviceauth_MFAAuthenticateResponse()
        approval.webauthn.type = assertion.type
        approval.webauthn.rawID = credential.credentialID
        approval.webauthn.response.clientDataJson = try Self.urlBytes(assertion.response.clientDataJSON)
        approval.webauthn.response.authenticatorData = try Self.urlBytes(assertion.response.authenticatorData)
        approval.webauthn.response.signature = try Self.urlBytes(assertion.response.signature)
        let approvalBytes = try approval.serializedData()
        guard approvalBytes.count < 16_384 else { throw ApprovalFailure.invalidResponseField }
        // Pinned Auth schema: id=1, state=2 (APPROVED=3), mfa_response=3.
        var update = getRequest + Data([0x10, 3, 0x1a])
        if approvalBytes.count >= 128 {
            update.append(UInt8(approvalBytes.count & 0x7f) | 0x80)
            update.append(UInt8(approvalBytes.count >> 7))
        } else {
            update.append(UInt8(approvalBytes.count))
        }
        update.append(approvalBytes)
        _ = try await transport.unary(path: "/proto.AuthService/UpdateHeadlessAuthenticationState", message: update, identity: identity)
    }

    private static func urlBytes(_ value: String) throws -> Data {
        guard value.utf8.count <= 16_384 else { throw ApprovalFailure.invalidResponseField }
        var standard = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let bytes = Data(base64Encoded: standard) else { throw ApprovalFailure.invalidResponseField }
        return bytes
    }

    private enum ApprovalFailure: Error { case invalidPage, missingChallenge, invalidResponseField }
}
#endif
