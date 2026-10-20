import Foundation
import TeleportCore

struct ProxyPing: Decodable, Sendable {
    struct Auth: Decodable, Sendable {
        struct Connector: Decodable, Sendable { let name: String; let display: String? }
        struct DeviceTrust: Decodable, Sendable { let auto_enroll: Bool? }
        let type: String
        let second_factor: String?
        let private_key_policy: String?
        let github: Connector?
        let oidc: Connector?
        let saml: Connector?
        let device_trust: DeviceTrust?
        let has_motd: Bool?
    }
    struct Proxy: Decodable, Sendable { let tls_routing_enabled: Bool }
    let auth: Auth
    let proxy: Proxy
    let cluster_name: String
    let server_version: String
    let fips: Bool?

    func validate() throws {
        let parts = server_version.split(separator: ".", omittingEmptySubsequences: false)
        guard !cluster_name.isEmpty, cluster_name.utf8.count <= 1024, parts.count == 3,
              parts.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 6 && $0.utf8.allSatisfy({ (48...57).contains($0) }) }),
              parts.allSatisfy({ UInt32($0) != nil }) else { throw TeleportError.invalidResponse("cluster or server version") }
        guard parts[0] == "18" else { throw TeleportError.unsupportedVersion }
        guard proxy.tls_routing_enabled else { throw TeleportError.unsupportedPolicy(.legacyProxy) }
        guard fips != true else { throw TeleportError.unsupportedPolicy(.fips) }
        guard auth.device_trust?.auto_enroll != true else { throw TeleportError.unsupportedPolicy(.deviceTrust) }
        guard auth.has_motd != true else { throw TeleportError.unsupportedPolicy(.messageOfTheDay) }
        guard auth.private_key_policy == nil || auth.private_key_policy == "none" || auth.private_key_policy == "" else { throw TeleportError.unsupportedPolicy(.hardwareKey) }
    }
    var discovery: TeleportDiscovery {
        var connectors = [TeleportConnector]()
        for (kind, value) in [(TeleportConnector.Kind.github, auth.github), (.oidc, auth.oidc), (.saml, auth.saml)] {
            if let value { connectors.append(TeleportConnector(kind: kind, id: value.name, displayName: value.display ?? value.name)) }
        }
        return TeleportDiscovery(clusterName: cluster_name, serverVersion: server_version, authenticationType: auth.type,
                                 secondFactor: auth.second_factor ?? "", connectors: connectors)
    }
}

struct LoginBegin: Encodable { let user: String; let pass: String }
struct LoginChallenge: Decodable {
    let totp_challenge: Bool?
    let webauthn_challenge: JSONValue?
    let sso_challenge: JSONValue?
}
enum JSONValue: Decodable {
    case object
    init(from decoder: any Decoder) throws { self = .object }
}
struct LoginFinish: Encodable {
    let user: String
    let password: String
    let totp_code: String
    let ssh_pub_key: Data
    let tls_pub_key: Data
    let ttl: Int64
}

struct LoginResponse: Decodable, Sendable {
    struct Authority: Decodable, Sendable {
        let domain_name: String
        let checking_keys: [Data]
        let tls_certs: [Data]
    }
    let username: String
    let cert: Data
    let tls_cert: Data
    let host_signers: [Authority]
    let mfa_token: String?

    func identity(proxy: TeleportProxy, username expectedUser: String?, cluster: String, key: CredentialKey, userTrust: UserAuthorityTrust, ttl: TimeInterval) throws -> TeleportIdentity {
        guard expectedUser == nil || expectedUser == username, host_signers.count <= 32,
              let signer = host_signers.first(where: { $0.domain_name == cluster }),
              host_signers.filter({ $0.domain_name == cluster }).count == 1,
              signer.checking_keys.count <= 32, signer.tls_certs.count <= 32,
              let ssh = String(data: cert, encoding: .utf8), cert.count <= 262_144 else { throw TeleportError.invalidResponse("login binding") }
        guard mfa_token == nil || mfa_token == "" else { throw TeleportError.unsupportedPolicy(.sessionMFA) }
        let roots = try signer.tls_certs.map { try DER.decodePEM($0, label: "CERTIFICATE") }
        let hostKeys = try signer.checking_keys.map { data -> String in
            guard data.count <= 65_536, let string = String(data: data, encoding: .utf8) else { throw TeleportError.invalidResponse("SSH authority encoding") }; return string
        }
        let identity = try TeleportIdentity(proxy: proxy, username: username, clusterName: cluster,
                                            tlsCertificateDER: DER.decodePEM(tls_cert, label: "CERTIFICATE"), tlsPrivateKeyDER: key.privateDER,
                                            sshCertificateOpenSSH: ssh, tlsCACertificatesDER: roots, sshHostCAKeys: hostKeys,
                                            tlsUserCACertificatesDER: userTrust.tlsRoots, sshUserCAKeys: userTrust.sshKeys)
        guard identity.isUsable(), identity.validBefore <= Date().addingTimeInterval(ttl + 60) else { throw TeleportError.invalidCertificate("new identity validity") }
        return identity
    }
}

struct UserAuthorityTrust: Sendable {
    let tlsRoots: [Data]
    let sshKeys: [String]
    private struct Export: Decodable { let data: Data }

    static func load(proxy: TeleportProxy) async throws -> Self {
        func fetch(_ type: String) async throws -> [Data] {
            let bytes = try await BoundedHTTP(proxy: proxy).run(path: "v1/webapi/auth/export", query: [URLQueryItem(name: "type", value: type), URLQueryItem(name: "format", value: "json")])
            let entries = try JSONDecoder().decode([Export].self, from: bytes)
            guard !entries.isEmpty, entries.count <= 32, entries.allSatisfy({ $0.data.count <= 262_144 }) else { throw TeleportError.invalidResponse("user authority export") }
            return entries.map(\.data)
        }
        async let tls = fetch("tls-user")
        async let ssh = fetch("user")
        let roots = try await tls.map { try DER.decodePEM($0, label: "CERTIFICATE") }
        var keys = [String]()
        for bytes in try await ssh {
            guard let text = String(data: bytes, encoding: .utf8) else { throw TeleportError.invalidResponse("SSH user authority encoding") }
            for line in text.split(whereSeparator: \.isNewline) {
                let parts = line.split(whereSeparator: \.isWhitespace)
                guard let index = parts.firstIndex(where: { $0 == "ssh-rsa" || $0 == "ssh-ed25519" || $0.hasPrefix("ecdsa-sha2-nistp") }), index + 1 < parts.count,
                      keys.count < 32 else { throw TeleportError.invalidResponse("SSH user authority") }
                keys.append(String(parts[index]) + " " + String(parts[index + 1]))
            }
        }
        guard !keys.isEmpty else { throw TeleportError.invalidResponse("empty SSH user authority") }
        return Self(tlsRoots: roots, sshKeys: keys)
    }
}
