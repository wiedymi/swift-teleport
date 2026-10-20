import Foundation

public enum TeleportUnsupportedPolicy: String, Sendable, Codable {
    case legacyProxy, leafCluster, deviceTrust, hardwareKey, passwordless, headless
    case sessionMFA, accessRequest, fips, agentForwarding, browserCallback, messageOfTheDay
}

public enum TeleportError: Error, Sendable, Equatable, CustomStringConvertible {
    case invalidConfiguration(String)
    case invalidResponse(String)
    case invalidCertificate(String)
    case unsupportedPolicy(TeleportUnsupportedPolicy)
    case unsupportedVersion
    case httpStatus(Int)
    case authenticationRequired
    case accessDenied
    case ambiguousNode
    case nodeNotFound
    case limitExceeded(String)
    case transport(String)

    public var description: String {
        switch self {
        case .invalidConfiguration(let reason): "Invalid Teleport configuration: \(reason)."
        case .invalidResponse(let reason): "Invalid Teleport response: \(reason)."
        case .invalidCertificate(let reason): "Invalid Teleport certificate: \(reason)."
        case .unsupportedPolicy(let policy): "Unsupported Teleport policy: \(policy.rawValue)."
        case .unsupportedVersion: "This Teleport server version is not supported."
        case .httpStatus(let status): "Teleport returned HTTP \(status)."
        case .authenticationRequired: "Teleport login is required."
        case .accessDenied: "Teleport access was denied."
        case .ambiguousNode: "More than one Teleport node has this name."
        case .nodeNotFound: "The Teleport node was not found."
        case .limitExceeded(let name): "Teleport exceeded the \(name) limit."
        case .transport(let reason): "Teleport transport failed: \(reason)."
        }
    }
}

public struct TeleportProxy: Sendable, Hashable, Codable {
    public let url: URL
    /// Optional HTTPS roots. System HTTPS trust is used if this is empty.
    public let httpsCACertificatesDER: [Data]

    public init(url: URL, httpsCACertificatesDER: [Data] = []) throws {
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              parts.scheme?.lowercased() == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/", (parts.port.map { (1...65535).contains($0) } ?? true)
        else { throw TeleportError.invalidConfiguration("an HTTPS origin is required") }
        guard httpsCACertificatesDER.count <= 32, httpsCACertificatesDER.allSatisfy({ $0.count <= 65_536 }) else {
            throw TeleportError.limitExceeded("HTTPS roots")
        }
        parts.host = host.lowercased()
        parts.scheme = "https"
        parts.path = ""
        if parts.port == 443 { parts.port = nil }
        guard let normalized = parts.url else { throw TeleportError.invalidConfiguration("proxy URL") }
        self.url = normalized
        self.httpsCACertificatesDER = httpsCACertificatesDER
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(url: c.decode(URL.self, forKey: .url), httpsCACertificatesDER: c.decode([Data].self, forKey: .httpsCACertificatesDER))
    }
}

public struct TeleportDiscovery: Sendable, Equatable {
    public let clusterName: String
    public let serverVersion: String
    public let authenticationType: String
    public let secondFactor: String
    public let connectors: [TeleportConnector]

    public init(clusterName: String, serverVersion: String, authenticationType: String, secondFactor: String, connectors: [TeleportConnector]) {
        self.clusterName = clusterName; self.serverVersion = serverVersion
        self.authenticationType = authenticationType; self.secondFactor = secondFactor; self.connectors = connectors
    }
}

public struct TeleportConnector: Sendable, Equatable, Codable {
    public enum Kind: String, Sendable, Codable { case github, oidc, saml }
    public let kind: Kind
    public let id: String
    public let displayName: String
    public init(kind: Kind, id: String, displayName: String) { self.kind = kind; self.id = id; self.displayName = displayName }
}

public struct TeleportNode: Sendable, Equatable, Hashable {
    public let id: String
    public let name: String
    public let clusterName: String
    public let labels: [String: String]
    public init(id: String, name: String, clusterName: String, labels: [String: String] = [:]) throws {
        for value in [id, name, clusterName] {
            guard !value.isEmpty, value.utf8.count <= 1024, !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw TeleportError.invalidResponse("node identity")
            }
        }
        guard id.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 || $0 == 46 }) else {
            throw TeleportError.invalidResponse("node identifier")
        }
        guard labels.count <= 128, labels.allSatisfy({ $0.key.utf8.count <= 1024 && $0.value.utf8.count <= 4096 }) else {
            throw TeleportError.limitExceeded("node labels")
        }
        self.id = id; self.name = name; self.clusterName = clusterName; self.labels = labels
    }
}

public protocol TeleportIdentityStore: Sendable {
    func load() async throws -> TeleportIdentity?
    /// Replace the entire record in one durable operation. A failed write must preserve the previous record.
    func replace(with identity: TeleportIdentity?) async throws
}

public actor MemoryIdentityStore: TeleportIdentityStore {
    private var identity: TeleportIdentity?
    public init() {}
    public func load() -> TeleportIdentity? { identity }
    public func replace(with identity: TeleportIdentity?) { self.identity = identity }
}
