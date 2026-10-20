import Foundation
import TeleportCore

typealias AuthRPC = @Sendable (_ path: String, _ message: Data) async throws -> Data

enum DeviceCredentialAuthentication {
    private struct LoginChallenge: Decodable {
        let webauthn_challenge: DeviceWebAuthn.AssertionChallenge?
        let sso_challenge: JSONValue?
    }

    static func register(proxy: TeleportProxy, identity: TeleportIdentity, name: String, otp: String,
                         presenter: (any TeleportBrowserPresenter)?, prompt: String,
                         store: any DeviceCredentialStorage, keys: any DeviceKeyOperations,
                         request: AuthRequest? = nil, rpc: AuthRPC) async throws {
        let request = http(proxy: proxy, request: request)
        guard identity.proxy == proxy, identity.isUsable() else { throw TeleportError.authenticationRequired }
        guard try await store.load(username: identity.username) == nil else { throw TeleportError.deviceCredentialExists }
        let discovery: ProxyPing = try DeviceWebAuthn.decode(await request("v1/webapi/ping", [], nil), field: "proxy discovery")
        try discovery.validate()
        guard discovery.cluster_name == identity.clusterName else { throw TeleportError.invalidResponse("registration cluster") }
        let callback = try presenter.map { _ in try BrowserCallback() }
        defer { callback?.close() }
        let callbackURL = try await callback?.start()
        let authenticationRequest = try DeviceAuthRPC.authenticationRequest(proxy: proxy, callbackURL: callbackURL)
        let challenge = try await rpc(DeviceAuthRPC.authenticatePath, authenticationRequest)
        let registrationRequest: Data
        switch try DeviceAuthRPC.managementChallenge(challenge) {
        case .none:
            registrationRequest = try DeviceAuthRPC.registrationRequest()
        case .totp:
            guard presenter == nil else { throw TeleportError.unsupportedPolicy(.browserMFA) }
            guard !otp.isEmpty else { throw TeleportError.invalidConfiguration("a fresh TOTP code is required for setup") }
            registrationRequest = try DeviceAuthRPC.registrationRequest(otp: otp)
        case .browser(let id):
            guard let callback, let presenter else {
                throw TeleportError.unsupportedPolicy(.browserMFA)
            }
            let approval = try await BrowserMFAApproval.receive(
                proxy: proxy, requestID: id, callback: callback, presenter: presenter
            )
            registrationRequest = try DeviceAuthRPC.registrationRequest(approval: approval)
        }
        try Task.checkCancellation()
        let bytes = try await rpc(DeviceAuthRPC.registrationPath, registrationRequest)
        let creation = try DeviceAuthRPC.registrationChallenge(bytes)
        try creation.validate(proxy: proxy, username: identity.username)
        let key = try await keys.create(prompt: prompt)
        try Task.checkCancellation()
        let registration = try await DeviceWebAuthn.registration(challenge: creation, proxy: proxy, username: identity.username,
                                                                key: key, keys: keys, prompt: prompt)
        try Task.checkCancellation()
        let addRequest = try DeviceAuthRPC.addRequest(
            deviceName: name, credentialID: registration.credentialID,
            clientDataJSON: registration.clientDataJSON, attestationObject: registration.attestationObject
        )
        let added = try await rpc(DeviceAuthRPC.addPath, addRequest)
        try DeviceAuthRPC.validateAddedDevice(added, credentialID: registration.credentialID,
                                             rpID: creation.publicKey.rp.id, publicKeyCOSE: registration.publicKeyCOSE)
        try Task.checkCancellation()
        // The server and Keychain cannot commit together. A failed add preserves any prior local credential.
        try await store.add(DeviceCredential(clusterName: identity.clusterName, credentialID: registration.credentialID,
                                             protectedKey: key.protectedKey), username: identity.username)
    }

    static func login(proxy: TeleportProxy, username: String, password: String, ttl: TimeInterval, prompt: String,
                      store: any DeviceCredentialStorage, keys: any DeviceKeyOperations,
                      request: AuthRequest? = nil) async throws -> TeleportIdentity {
        guard let credential = try await store.load(username: username) else { throw TeleportError.deviceCredentialMissing }
        try credential.validate()
        let request = http(proxy: proxy, request: request)
        let discovery: ProxyPing = try DeviceWebAuthn.decode(await request("v1/webapi/ping", [], nil), field: "proxy discovery")
        try discovery.validate()
        guard discovery.cluster_name == credential.clusterName else { throw TeleportError.invalidResponse("device credential cluster") }
        let begin = try JSONEncoder().encode(LoginBegin(user: username, pass: password))
        let challenge: LoginChallenge = try DeviceWebAuthn.decode(await request("v1/webapi/mfa/login/begin", [], begin), field: "device login challenge")
        guard challenge.sso_challenge == nil else { throw TeleportError.unsupportedPolicy(.sessionMFA) }
        guard let options = challenge.webauthn_challenge else { throw TeleportError.deviceCredentialMissing }
        let assertion = try await DeviceWebAuthn.assertion(challenge: options, credential: credential, proxy: proxy, keys: keys, prompt: prompt)
        try Task.checkCancellation()
        let key = try await Task.detached { try CredentialKey() }.value
        try Task.checkCancellation()
        let finish = LoginFinish(user: username, password: password, totp_code: "", ssh_pub_key: Data(key.sshPublicKey.utf8),
                                 tls_pub_key: Data(key.tlsPublicKeyPEM.utf8), ttl: Int64(ttl * 1_000_000_000), webauthn_challenge_response: assertion)
        let response: LoginResponse = try DeviceWebAuthn.decode(await request("v1/webapi/mfa/login/finish", [], JSONEncoder().encode(finish)), field: "device login certificates")
        let userTrust = try await UserAuthorityTrust.load(proxy: proxy, request: request)
        try Task.checkCancellation()
        return try response.identity(proxy: proxy, username: username, cluster: discovery.cluster_name, key: key, userTrust: userTrust, ttl: ttl)
    }

    private static func http(proxy: TeleportProxy, request: AuthRequest?) -> AuthRequest {
        request ?? { path, query, body in try await BoundedHTTP(proxy: proxy).run(path: path, query: query, body: body) }
    }
}
