import Foundation
import CryptoKit
import Network
import TeleportCore

struct BrowserRequest: Encodable {
    let redirect_url: String
    let ssh_pub_key: Data
    let tls_pub_key: Data
    let cert_ttl: Int64
    let connector_id: String
}
struct BrowserRedirect: Decodable { let redirect_url: String?; let post_form: String? }

enum BrowserLogin {
    static func perform(proxy: TeleportProxy, connector: TeleportConnector, ttl: TimeInterval, presenter: any TeleportBrowserPresenter) async throws -> TeleportIdentity {
        let pingBytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/ping/" + connector.id)
        let ping = try JSONDecoder().decode(ProxyPing.self, from: pingBytes)
        try ping.validate()
        guard ping.discovery.connectors.contains(where: { $0.kind == connector.kind && $0.id == connector.id }) else { throw TeleportError.invalidConfiguration("connector is not advertised by this proxy") }
        let credentialKey = try await Task.detached { try CredentialKey() }.value
        let callback = try BrowserCallback()
        defer { callback.close() }
        let callbackURL = try await callback.start()
        let request = BrowserRequest(redirect_url: callbackURL.absoluteString, ssh_pub_key: Data(credentialKey.sshPublicKey.utf8),
                                     tls_pub_key: Data(credentialKey.tlsPublicKeyPEM.utf8), cert_ttl: Int64(ttl * 1_000_000_000), connector_id: connector.id)
        let redirectBytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/" + connector.kind.rawValue + "/login/console", body: JSONEncoder().encode(request))
        let redirect = try JSONDecoder().decode(BrowserRedirect.self, from: redirectBytes)
        guard redirect.post_form == nil || redirect.post_form == "" else { throw TeleportError.unsupportedPolicy(.browserCallback) }
        guard let value = redirect.redirect_url, value.utf8.count <= 32_768, let url = URL(string: value),
              url.scheme == "https", url.host != nil, url.user == nil, url.password == nil else { throw TeleportError.invalidResponse("browser redirect") }
        try Task.checkCancellation()
        try await presenter.open(url)
        let bytes = try await callback.wait()
        let response = try JSONDecoder().decode(LoginResponse.self, from: bytes)
        let userTrust = try await UserAuthorityTrust.load(proxy: proxy)
        return try response.identity(proxy: proxy, username: nil, cluster: ping.cluster_name, key: credentialKey, userTrust: userTrust, ttl: ttl)
    }
}

/// A small one-attempt HTTP listener. Only authenticated AES-GCM data completes it.
final class BrowserCallback: @unchecked Sendable {
    private let queue = DispatchQueue(label: "TeleportKit.browser-callback")
    private let listener: NWListener
    private let key = SymmetricKey(size: .bits256)
    private let timeout: TimeInterval
    private var ready: CheckedContinuation<URL, any Error>?
    private var waiter: CheckedContinuation<Data, any Error>?
    private var result: Result<Data, any Error>?
    private var connections = [UUID: NWConnection]()

    init(timeout: TimeInterval = 180) throws {
        guard timeout.isFinite, timeout > 0, timeout <= 180 else { throw TeleportError.invalidConfiguration("browser timeout") }
        self.timeout = timeout
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() async throws -> URL {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    guard result == nil else { continuation.resume(throwing: CancellationError()); return }
                    ready = continuation
                    listener.stateUpdateHandler = { [weak self] state in self?.state(state) }
                    listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
                    listener.start(queue: queue)
                    queue.asyncAfter(deadline: .now() + timeout) { [weak self] in self?.complete(.failure(TeleportError.transport("browser login timeout"))) }
                }
            }
        } onCancel: { self.close() }
    }
    func wait() async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                queue.async { [self] in
                    if let result { continuation.resume(with: result) }
                    else { waiter = continuation }
                }
            }
        } onCancel: { self.close() }
    }
    func close() { queue.async { [self] in complete(.failure(CancellationError())) } }

    private func state(_ state: NWListener.State) {
        switch state {
        case .ready:
            guard let port = listener.port?.rawValue, let continuation = ready else { return }
            ready = nil
            let secret = key.withUnsafeBytes { Data($0).map { String(format: "%02x", $0) }.joined() }
            continuation.resume(returning: URL(string: "http://127.0.0.1:\(port)/callback?secret_key=\(secret)")!)
        case .failed: complete(.failure(TeleportError.transport("browser callback listener")))
        default: break
        }
    }
    private func complete(_ result: Result<Data, any Error>) {
        guard self.result == nil else { return }
        self.result = result
        let waiting = waiter; waiter = nil; waiting?.resume(with: result)
        if let ready { self.ready = nil; ready.resume(throwing: TeleportError.transport("browser callback listener stopped")) }
        listener.cancel()
        for connection in connections.values { connection.cancel() }
        connections.removeAll()
    }
    private func accept(_ connection: NWConnection) {
        guard result == nil, connections.count < 4 else { connection.cancel(); return }
        let id = UUID(); connections[id] = connection
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 15) { [weak self, weak connection] in
            connection?.cancel(); self?.connections.removeValue(forKey: id)
        }
        receive(connection, id: id, bytes: Data())
    }
    private func receive(_ connection: NWConnection, id: UUID, bytes: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { [weak self] chunk, _, done, error in
            guard let self, self.result == nil else { connection.cancel(); return }
            var bytes = bytes
            if let chunk {
                guard chunk.count <= 1_048_576 - bytes.count else { self.reply(connection, id: id, status: 413); return }
                bytes.append(chunk)
            }
            do {
                switch try self.parse(bytes) {
                case .authenticated(let data):
                    self.reply(connection, id: id, status: 200)
                    self.complete(.success(data)); return
                case .preflight: self.reply(connection, id: id, status: 200); return
                case .incomplete: break
                }
            } catch { self.reply(connection, id: id, status: 400); return }
            if done || error != nil { self.reply(connection, id: id, status: 400) }
            else { self.receive(connection, id: id, bytes: bytes) }
        }
    }
    private func reply(_ connection: NWConnection, id: UUID, status: Int) {
        connections.removeValue(forKey: id)
        let message = "HTTP/1.1 \(status) \(status == 200 ? "OK" : "Error")\r\nConnection: close\r\nContent-Length: 0\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n"
        connection.send(content: Data(message.utf8), completion: .contentProcessed { _ in connection.cancel() })
    }
    private enum Request { case incomplete, preflight, authenticated(Data) }
    private func parse(_ bytes: Data) throws -> Request {
        guard let boundary = bytes.range(of: Data("\r\n\r\n".utf8)) else {
            guard bytes.count <= 16_384 else { throw TeleportError.limitExceeded("callback headers") }; return .incomplete
        }
        guard boundary.lowerBound <= 16_384, let header = String(data: bytes[..<boundary.lowerBound], encoding: .ascii) else { throw TeleportError.invalidResponse("callback header") }
        let lines = header.components(separatedBy: "\r\n")
        let first = lines[0].split(separator: " ")
        guard first.count == 3, first[2] == "HTTP/1.1", ["GET", "POST", "OPTIONS"].contains(String(first[0])), let port = listener.port?.rawValue,
              let url = URLComponents(string: "http://127.0.0.1:" + String(port) + first[1]), url.path == "/callback", url.fragment == nil else { throw TeleportError.invalidResponse("callback target") }
        var fields = [String: String]()
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { throw TeleportError.invalidResponse("callback header") }
            let name = line[..<colon].lowercased(), value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard fields.updateValue(value, forKey: name) == nil else { throw TeleportError.invalidResponse("duplicate callback header") }
        }
        guard fields["host"] == "127.0.0.1:" + String(port), fields["transfer-encoding"] == nil else { throw TeleportError.invalidResponse("callback authority") }
        let length: Int
        if let text = fields["content-length"] {
            guard let count = Int(text), (0...1_000_000).contains(count) else { throw TeleportError.invalidResponse("callback body length") }; length = count
        } else { length = 0 }
        let available = bytes.count - boundary.upperBound
        guard available <= length else { throw TeleportError.invalidResponse("callback trailing data") }
        guard available == length else { return .incomplete }
        if first[0] == "OPTIONS" { return .preflight }
        let parameters: [URLQueryItem]
        if first[0] == "POST" {
            guard fields["content-type"]?.lowercased().hasPrefix("application/x-www-form-urlencoded") == true,
                  let body = String(data: bytes[boundary.upperBound...], encoding: .utf8), let query = URLComponents(string: "?" + body.replacingOccurrences(of: "+", with: "%20")) else { throw TeleportError.invalidResponse("callback form") }
            parameters = query.queryItems ?? []
        } else { parameters = url.queryItems ?? [] }
        let responses = parameters.filter { $0.name == "response" }
        guard responses.count == 1, let response = responses[0].value, response.utf8.count <= 1_000_000 else { throw TeleportError.invalidResponse("callback response") }
        return .authenticated(try Self.decrypt(Data(response.utf8), key: key))
    }

    static func decrypt(_ bytes: Data, key: SymmetricKey) throws -> Data {
        struct Sealed: Decodable { let ciphertext: Data; let nonce: Data }
        guard bytes.count <= 1_000_000 else { throw TeleportError.limitExceeded("encrypted callback") }
        let sealed = try JSONDecoder().decode(Sealed.self, from: bytes)
        guard sealed.nonce.count == 12, sealed.ciphertext.count >= 16 else { throw TeleportError.invalidResponse("callback cipher data") }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: sealed.nonce), ciphertext: sealed.ciphertext.dropLast(16), tag: sealed.ciphertext.suffix(16))
        return try AES.GCM.open(box, using: key)
    }
}
