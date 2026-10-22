import CryptoKit
import Foundation
import TeleportCore

/// A short-lived identity authorizes device setup. It is never stored by this operation.
enum HeadlessBootstrap {
    private struct Request: Encodable {
        let user: String
        let headless_id: String
        let ssh_pub_key: Data
        let tls_pub_key: Data
        let ttl: Int64 = 60_000_000_000
    }

    static func perform(proxy: TeleportProxy, username: String, presenter: any TeleportBrowserPresenter,
                        request: AuthRequest? = nil) async throws -> TeleportIdentity {
        let request: AuthRequest = request ?? { path, query, body in
            try await BoundedHTTP(proxy: proxy).run(path: path, query: query, body: body,
                                                  timeout: path == "v1/webapi/headless/login" ? 180 : 60)
        }
        let ping: ProxyPing = try DeviceWebAuthn.decode(await request("v1/webapi/ping", [], nil), field: "proxy discovery")
        try ping.validate()
        guard ping.auth.type == "local", ping.auth.allow_headless == true else { throw TeleportError.unsupportedPolicy(.headless) }
        guard ping.auth.allow_passwordless == true else { throw TeleportError.unsupportedPolicy(.passwordless) }
        try Task.checkCancellation()
        let key = try await Task.detached { try CredentialKey() }.value
        try Task.checkCancellation()
        let sshPublicKey = Data(key.sshPublicKey.utf8)
        let id = requestID(sshPublicKey: sshPublicKey)
        let body = try JSONEncoder().encode(Request(user: username, headless_id: id, ssh_pub_key: sshPublicKey,
                                                   tls_pub_key: Data(key.tlsPublicKeyPEM.utf8)))
        let url = proxy.url.appendingPathComponent("web/headless").appendingPathComponent(id)
        let bytes = try await withThrowingTaskGroup(of: Data?.self) { group in
            // Teleport allows five seconds for this POST to reach Auth after the browser opens.
            group.addTask { try await request("v1/webapi/headless/login", [], body) }
            group.addTask { try await presenter.open(url); return nil }
            defer { group.cancelAll() }
            while let result = try await group.next() {
                if let result { return result }
            }
            throw CancellationError()
        }
        try Task.checkCancellation()
        let response: LoginResponse = try DeviceWebAuthn.decode(bytes, field: "device setup certificates")
        let trust = try await UserAuthorityTrust.load(proxy: proxy, request: request)
        return try response.identity(proxy: proxy, username: username, cluster: ping.cluster_name, key: key, userTrust: trust, ttl: 60)
    }

    /// Teleport hashes the exact SSH authorized_keys bytes with a zero UUID namespace.
    static func requestID(sshPublicKey: Data) -> String {
        var hash = SHA256()
        hash.update(data: Data(repeating: 0, count: 16))
        hash.update(data: sshPublicKey)
        var bytes = Array(hash.finalize().prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x50
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
            .uuidString.lowercased()
    }
}
