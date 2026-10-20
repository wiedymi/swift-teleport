import Foundation
import TeleportCore

/// One client represents one proxy and one account profile. Share it between terminal tabs.
public actor TeleportClient {
    public let proxy: TeleportProxy
    private let identityStore: any TeleportIdentityStore
    private let transport = ProxyTransport()
    enum LoginMethod: Equatable, Sendable {
        case password(String)
        case browserMFA(String)
        case sso(TeleportConnector.Kind, String)
    }
    private enum Operation {
        case idle(UUID)
        case login(method: LoginMethod, id: UUID, task: Task<TeleportIdentity, any Error>)
        case signOut(id: UUID, task: Task<Void, any Error>)

        var id: UUID {
            switch self {
            case .idle(let id), .login(_, let id, _), .signOut(let id, _): id
            }
        }
    }
    private var operation = Operation.idle(UUID())
    private var loginWaiters = 0

    public init(proxy: TeleportProxy, identityStore: any TeleportIdentityStore = MemoryIdentityStore()) {
        self.proxy = proxy; self.identityStore = identityStore
    }

    public func discover() async throws -> TeleportDiscovery { try await ping().discovery }

    private func ping() async throws -> ProxyPing {
        let bytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/ping")
        let ping: ProxyPing
        do { ping = try JSONDecoder().decode(ProxyPing.self, from: bytes) }
        catch { throw TeleportError.invalidResponse("proxy discovery") }
        try ping.validate(); return ping
    }

    /// The password and one-time code are used only by the pending request.
    public func login(username: String, password: String, otp: String, ttl: TimeInterval = 3600) async throws -> TeleportIdentity {
        guard !username.isEmpty, username.utf8.count <= 1024, !password.isEmpty, password.utf8.count <= 65_536,
              otp.isEmpty || ((6...8).contains(otp.utf8.count) && otp.utf8.allSatisfy({ (48...57).contains($0) })),
              ttl.isFinite, ttl >= 60, ttl <= 43_200 else { throw TeleportError.invalidConfiguration("login input") }
        return try await sharedLogin(method: .password(username)) { [proxy] in
            try await Self.localLogin(proxy: proxy, username: username, password: password, otp: otp, ttl: ttl)
        }
    }

    /// Approve local password login with an existing passkey or security key in the browser.
    public func login(username: String, password: String, browser: any TeleportBrowserPresenter, ttl: TimeInterval = 3600) async throws -> TeleportIdentity {
        guard !username.isEmpty, username.utf8.count <= 1024, !password.isEmpty, password.utf8.count <= 65_536,
              ttl.isFinite, ttl >= 60, ttl <= 43_200 else { throw TeleportError.invalidConfiguration("login input") }
        return try await sharedLogin(method: .browserMFA(username)) { [proxy] in
            try await BrowserMFALogin.perform(proxy: proxy, username: username, password: password, ttl: ttl, presenter: browser)
        }
    }

    /// Start browser SSO with the server's loopback callback contract.
    /// The app must permit incoming loopback connections and keep the login alive while the browser is open.
    public func login(browser: any TeleportBrowserPresenter, connector: TeleportConnector, ttl: TimeInterval = 3600) async throws -> TeleportIdentity {
        guard !connector.id.isEmpty, connector.id.utf8.count <= 256,
              connector.id.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 || $0 == 46 }),
              ttl.isFinite, ttl >= 60, ttl <= 43_200 else { throw TeleportError.invalidConfiguration("browser login input") }
        return try await sharedLogin(method: .sso(connector.kind, connector.id)) { [proxy] in
            try await BrowserLogin.perform(proxy: proxy, connector: connector, ttl: ttl, presenter: browser)
        }
    }

    func sharedLogin(method: LoginMethod, operation: @escaping @Sendable () async throws -> TeleportIdentity) async throws -> TeleportIdentity {
        guard loginWaiters < 64 else { throw TeleportError.limitExceeded("login waiters") }
        let task: Task<TeleportIdentity, any Error>
        switch self.operation {
        case .signOut: throw TeleportError.invalidConfiguration("sign-out is active")
        case .login(let pendingMethod, _, let pendingTask):
            guard pendingMethod == method else { throw TeleportError.invalidConfiguration("a different login is active") }
            task = pendingTask
        case .idle:
            let id = UUID(), store = identityStore
            task = Task {
                do {
                    let result = try await operation()
                    try Task.checkCancellation()
                    try await store.replace(with: result)
                    clearLogin(id)
                    return result
                } catch {
                    clearLogin(id)
                    throw error
                }
            }
            self.operation = .login(method: method, id: id, task: task)
        }
        loginWaiters += 1
        defer {
            loginWaiters -= 1
            if loginWaiters == 0, case .login(_, _, let pendingTask) = self.operation { pendingTask.cancel() }
        }
        return try await SharedTaskWaiter<TeleportIdentity>.wait(for: task)
    }

    private func clearLogin(_ id: UUID) { if case .login(_, let pendingID, _) = operation, pendingID == id { operation = .idle(UUID()) } }

    private nonisolated static func localLogin(proxy: TeleportProxy, username: String, password: String, otp: String, ttl: TimeInterval) async throws -> TeleportIdentity {
        let discoveryBytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/ping")
        let ping = try JSONDecoder().decode(ProxyPing.self, from: discoveryBytes)
        try ping.validate()
        let beginBytes = try JSONEncoder().encode(LoginBegin(user: username, pass: password))
        let challengeBytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/mfa/login/begin", body: beginBytes)
        let challenge = try JSONDecoder().decode(LoginChallenge.self, from: challengeBytes)
        if challenge.sso_challenge != nil { throw TeleportError.unsupportedPolicy(.sessionMFA) }
        if challenge.totp_challenge == true {
            guard !otp.isEmpty else { throw TeleportError.invalidConfiguration("a TOTP code is required") }
        } else if challenge.webauthn_challenge != nil { throw TeleportError.unsupportedPolicy(.hardwareKey) }
        else if !otp.isEmpty { throw TeleportError.invalidResponse("TOTP was not offered") }
        let key = try await Task.detached { try CredentialKey() }.value
        try Task.checkCancellation()
        let request = LoginFinish(user: username, password: password, totp_code: otp,
                                  ssh_pub_key: Data(key.sshPublicKey.utf8), tls_pub_key: Data(key.tlsPublicKeyPEM.utf8), ttl: Int64(ttl * 1_000_000_000))
        let bytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/mfa/login/finish", body: JSONEncoder().encode(request))
        let response = try JSONDecoder().decode(LoginResponse.self, from: bytes)
        let userTrust = try await UserAuthorityTrust.load(proxy: proxy)
        return try response.identity(proxy: proxy, username: username, cluster: ping.cluster_name, key: key, userTrust: userTrust, ttl: ttl)
    }

    public func identity() async throws -> TeleportIdentity {
        if case .signOut = operation { throw TeleportError.authenticationRequired }
        let operationID = operation.id
        guard let identity = try await identityStore.load(), identity.proxy == proxy, identity.isUsable() else { throw TeleportError.authenticationRequired }
        guard operation.id == operationID else { throw TeleportError.authenticationRequired }
        return identity
    }

    /// Clear local credentials. This does not revoke credentials held by other clients.
    public func signOut() async throws {
        if case .signOut(_, let task) = operation { try await task.value; return }
        let loginTask: Task<TeleportIdentity, any Error>?
        if case .login(_, _, let task) = operation { loginTask = task; task.cancel() } else { loginTask = nil }
        let id = UUID(), store = identityStore
        let task = Task {
            do {
                if let loginTask { _ = try? await loginTask.value }
                await transport.reset()
                try await store.replace(with: nil)
                clearSignOut(id)
            } catch { clearSignOut(id); throw error }
        }
        operation = .signOut(id: id, task: task)
        try await task.value
    }

    private func clearSignOut(_ id: UUID) { if case .signOut(let pendingID, _) = operation, pendingID == id { operation = .idle(UUID()) } }

    public func connect(to node: TeleportNode, login: String) async throws -> TeleportConnection {
        let identity = try await identity()
        guard node.clusterName == identity.clusterName else { throw TeleportError.unsupportedPolicy(.leafCluster) }
        guard identity.allowedLogins.contains(login), !login.isEmpty, login.utf8.count <= 255 else { throw TeleportError.invalidConfiguration("OS login is not an issued principal") }
        let operationID = operation.id
        let connection = try await transport.connect(identity: identity, node: node, login: login)
        guard operation.id == operationID else { await connection.close(); throw TeleportError.authenticationRequired }
        return connection
    }

    func resourceRequest(message: Data, identity: TeleportIdentity) async throws -> Data {
        let operationID = operation.id
        let result = try await transport.unary(path: "/proto.AuthService/ListResources", message: message, identity: identity)
        guard operation.id == operationID else { throw TeleportError.authenticationRequired }
        return result
    }
}
