import Foundation
import TeleportCore

/// The browser returns an assertion, not the certificate response used by SSO.
struct BrowserMFAAssertion: Codable {
    struct Extensions: Codable {
        struct CredentialProperties: Codable { let rk: Bool? }
        let appid: Bool?
        let credProps: CredentialProperties?
    }
    struct Response: Codable {
        let clientDataJSON: String
        let authenticatorData: String
        let signature: String
        let userHandle: String?
    }
    let id: String
    let type: String
    let rawId: String
    let extensions: Extensions?
    let response: Response

    func validate() throws {
        guard type == "public-key",
              try Self.bytes(id, limit: 1024) == Self.bytes(rawId, limit: 1024) else {
            throw TeleportError.invalidResponse("browser MFA credential")
        }
        _ = try Self.bytes(response.clientDataJSON, limit: 16_384)
        _ = try Self.bytes(response.authenticatorData, limit: 65_536)
        _ = try Self.bytes(response.signature, limit: 16_384)
        if let handle = response.userHandle, !handle.isEmpty { _ = try Self.bytes(handle, limit: 64) }
    }

    /// Teleport's WebAuthn byte fields use URL-safe base64, with optional trailing padding.
    private static func bytes(_ value: String, limit: Int) throws -> Data {
        guard !value.isEmpty, value.utf8.count <= ((limit + 2) / 3) * 4 else {
            throw TeleportError.invalidResponse("browser MFA byte field")
        }
        let unpadded = value.prefix(while: { $0 != "=" })
        let padding = value.utf8.count - unpadded.utf8.count
        guard padding <= 2, value.dropFirst(unpadded.count).allSatisfy({ $0 == "=" }),
              unpadded.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }),
              padding == 0 || value.utf8.count % 4 == 0 else {
            throw TeleportError.invalidResponse("browser MFA byte field")
        }
        var standard = unpadded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let data = Data(base64Encoded: standard), !data.isEmpty, data.count <= limit,
              data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").filter({ $0 != "=" }) == unpadded else {
            throw TeleportError.invalidResponse("browser MFA byte field")
        }
        return data
    }
}

struct BrowserMFAResponse: Encodable {
    let requestId: String
    let webauthnResponse: BrowserMFAAssertion
}

/// Local login and device management use the same encrypted browser assertion callback.
/// Their challenge creation, MFA scopes, and final requests remain separate.
struct BrowserMFAApproval: Decodable {
    let browser_mfa_webauthn_response: BrowserMFAAssertion

    static func receive(proxy: TeleportProxy, requestID: String, callback: BrowserCallback,
                        presenter: any TeleportBrowserPresenter) async throws -> BrowserMFAResponse {
        guard requestID.utf8.count == 36, let uuid = UUID(uuidString: requestID), uuid.uuidString.lowercased() == requestID.lowercased() else {
            throw TeleportError.invalidResponse("browser MFA request ID")
        }
        try Task.checkCancellation()
        try await presenter.open(proxy.url.appendingPathComponent("web/mfa/browser").appendingPathComponent(requestID))
        let bytes = try await callback.wait()
        let approval: BrowserMFAApproval
        do { approval = try JSONDecoder().decode(Self.self, from: bytes) }
        catch { throw TeleportError.invalidResponse("browser MFA approval") }
        try approval.browser_mfa_webauthn_response.validate()
        return BrowserMFAResponse(requestId: requestID, webauthnResponse: approval.browser_mfa_webauthn_response)
    }
}

enum BrowserMFALogin {
    static func perform(proxy: TeleportProxy, username: String, password: String, ttl: TimeInterval,
                        presenter: any TeleportBrowserPresenter, request: AuthRequest? = nil) async throws -> TeleportIdentity {
        let request: AuthRequest = request ?? { path, query, body in
            try await BoundedHTTP(proxy: proxy).run(path: path, query: query, body: body)
        }
        let ping: ProxyPing = try decode(await request("v1/webapi/ping", [], nil), field: "proxy discovery")
        try ping.validate()
        let callback = try BrowserCallback()
        defer { callback.close() }
        let callbackURL = try await callback.start()
        let begin = LoginBegin(user: username, pass: password, browser_mfa_tsh_redirect_url: callbackURL.absoluteString)
        let challenge: LoginChallenge = try decode(await request("v1/webapi/mfa/login/begin", [], JSONEncoder().encode(begin)), field: "browser MFA challenge")
        guard let id = challenge.browser_challenge?.requestId else { throw TeleportError.unsupportedPolicy(.browserMFA) }
        let approval = try await BrowserMFAApproval.receive(proxy: proxy, requestID: id, callback: callback, presenter: presenter)
        try Task.checkCancellation()
        // The server binds the approved request to this account. Certificate checks below bind both new keys.
        let key = try await Task.detached { try CredentialKey() }.value
        try Task.checkCancellation()
        let finish = LoginFinish(user: username, password: password, totp_code: "",
                                 ssh_pub_key: Data(key.sshPublicKey.utf8), tls_pub_key: Data(key.tlsPublicKeyPEM.utf8),
                                 ttl: Int64(ttl * 1_000_000_000),
                                 browser_response: approval)
        let response: LoginResponse = try decode(await request("v1/webapi/mfa/login/finish", [], JSONEncoder().encode(finish)), field: "browser MFA certificates")
        let userTrust = try await UserAuthorityTrust.load(proxy: proxy, request: request)
        try Task.checkCancellation()
        return try response.identity(proxy: proxy, username: username, cluster: ping.cluster_name, key: key, userTrust: userTrust, ttl: ttl)
    }

    private static func decode<T: Decodable>(_ data: Data, field: String) throws -> T {
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw TeleportError.invalidResponse(field) }
    }
}
