import Foundation
import Security

/// A complete identity record. Treat its encoded form as a secret.
public struct TeleportIdentity: Sendable, Codable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let proxy: TeleportProxy
    public let username: String
    public let clusterName: String
    public let tlsCertificateDER: Data
    public let tlsPrivateKeyDER: Data
    public let sshCertificateOpenSSH: String
    public let tlsCACertificatesDER: [Data]
    public let sshHostCAKeys: [String]
    public let tlsUserCACertificatesDER: [Data]
    public let sshUserCAKeys: [String]
    private let sshCertificate: TeleportSSHCertificate
    private let tlsValidity: (after: Date, before: Date)

    public var sshPrivateKeyPEM: String { DER.pem(tlsPrivateKeyDER, label: "RSA PRIVATE KEY") }
    public var allowedLogins: [String] { sshCertificate.principals.filter { !$0.hasPrefix("-teleport-") } }
    public var validAfter: Date { max(sshCertificate.validAfter, tlsValidity.after) }
    public var validBefore: Date { sshCertificate.validBefore.map { min($0, tlsValidity.before) } ?? tlsValidity.before }
    public func isUsable(at date: Date = Date()) -> Bool { date >= validAfter && date < validBefore }

    /// Validate an imported record, including the private key and both issued certificates.
    public init(proxy: TeleportProxy, username: String, clusterName: String, tlsCertificateDER: Data, tlsPrivateKeyDER: Data,
                sshCertificateOpenSSH: String, tlsCACertificatesDER: [Data], sshHostCAKeys: [String],
                tlsUserCACertificatesDER: [Data], sshUserCAKeys: [String]) throws {
        for value in [username, clusterName] {
            guard !value.isEmpty, value.utf8.count <= 1024, !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw TeleportError.invalidCertificate("identity binding") }
        }
        guard !tlsCACertificatesDER.isEmpty, tlsCACertificatesDER.count <= 32, !sshHostCAKeys.isEmpty, sshHostCAKeys.count <= 32,
              !tlsUserCACertificatesDER.isEmpty, tlsUserCACertificatesDER.count <= 32, !sshUserCAKeys.isEmpty, sshUserCAKeys.count <= 32,
              (tlsCACertificatesDER + tlsUserCACertificatesDER).allSatisfy({ $0.count <= 65_536 }),
              (sshHostCAKeys + sshUserCAKeys).allSatisfy({ $0.utf8.count <= 65_536 }),
              tlsCertificateDER.count <= 65_536, tlsPrivateKeyDER.count <= 16_384 else { throw TeleportError.invalidCertificate("identity trust limits") }
        let ssh = try TeleportSSHCertificate(openSSH: sshCertificateOpenSSH)
        guard ssh.kind == .user, ssh.keyID == username, !ssh.principals.filter({ !$0.hasPrefix("-teleport-") }).isEmpty else { throw TeleportError.invalidCertificate("SSH account or login principals") }
        try ssh.verify(authorities: sshUserCAKeys, principal: ssh.principals[0], kind: .user,
                       at: ssh.validAfter.addingTimeInterval(ssh.validBefore.map { min(1, $0.timeIntervalSince(ssh.validAfter) / 2) } ?? 1))
        let key = try CredentialKey(privateDER: tlsPrivateKeyDER)
        guard ssh.publicKeyBlob == key.sshPublicKeyBlob else { throw TeleportError.invalidCertificate("SSH certificate key binding") }
        let facts = try X509Facts(der: tlsCertificateDER)
        guard facts.commonName == username, facts.issuerCommonName == clusterName, facts.issuerOrganizations == [clusterName],
              !facts.isCertificateAuthority, let certificate = SecCertificateCreateWithData(nil, tlsCertificateDER as CFData),
              let certKey = SecCertificateCopyKey(certificate), let certPublicDER = SecKeyCopyExternalRepresentation(certKey, nil) as Data?,
              certPublicDER == key.publicDER else { throw TeleportError.invalidCertificate("TLS certificate key or account binding") }
        for data in tlsCACertificatesDER {
            let root = try X509Facts(der: data)
            guard root.isCertificateAuthority, root.commonName == clusterName else { throw TeleportError.invalidCertificate("host TLS authority cluster") }
        }
        let roots = try tlsUserCACertificatesDER.map { data -> SecCertificate in
            let root = try X509Facts(der: data)
            guard root.isCertificateAuthority, root.commonName == clusterName, let cert = SecCertificateCreateWithData(nil, data as CFData) else { throw TeleportError.invalidCertificate("user TLS authority") }
            return cert
        }
        for authority in sshHostCAKeys { _ = try SSHEncoding.authorizedKey(authority) }
        let start = max(ssh.validAfter, facts.notBefore), end = ssh.validBefore.map { min($0, facts.notAfter) } ?? facts.notAfter
        guard start < end else { throw TeleportError.invalidCertificate("credential validity mismatch") }
        let verificationDate = min(max(Date(), start), end.addingTimeInterval(-min(1, end.timeIntervalSince(start) / 2)))
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust,
              SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, verificationDate as CFDate) == errSecSuccess else { throw TeleportError.invalidCertificate("TLS certificate trust setup") }
        var trustError: CFError?
        guard SecTrustEvaluateWithError(trust, &trustError) else {
            let code = trustError.map { CFErrorGetCode($0) } ?? 0
            throw TeleportError.invalidCertificate("TLS certificate chain (\(code))")
        }
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], !chain.isEmpty, chain.count <= 33 else {
            throw TeleportError.invalidCertificate("TLS certificate chain bounds")
        }
        let chainFacts = try chain.map { try X509Facts(der: SecCertificateCopyData($0) as Data) }
        let after = chainFacts.reduce(facts.notBefore) { max($0, $1.notBefore) }
        let before = chainFacts.reduce(facts.notAfter) { min($0, $1.notAfter) }
        self.proxy = proxy; self.username = username; self.clusterName = clusterName
        self.tlsCertificateDER = tlsCertificateDER; self.tlsPrivateKeyDER = tlsPrivateKeyDER; self.sshCertificateOpenSSH = sshCertificateOpenSSH
        self.tlsCACertificatesDER = tlsCACertificatesDER; self.sshHostCAKeys = sshHostCAKeys
        self.tlsUserCACertificatesDER = tlsUserCACertificatesDER; self.sshUserCAKeys = sshUserCAKeys
        sshCertificate = ssh; tlsValidity = (after, before)
    }

    private enum CodingKeys: String, CodingKey {
        case proxy, username, clusterName, tlsCertificateDER, tlsPrivateKeyDER, sshCertificateOpenSSH, tlsCACertificatesDER, sshHostCAKeys, tlsUserCACertificatesDER, sshUserCAKeys
    }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(proxy: c.decode(TeleportProxy.self, forKey: .proxy), username: c.decode(String.self, forKey: .username),
                      clusterName: c.decode(String.self, forKey: .clusterName), tlsCertificateDER: c.decode(Data.self, forKey: .tlsCertificateDER),
                      tlsPrivateKeyDER: c.decode(Data.self, forKey: .tlsPrivateKeyDER), sshCertificateOpenSSH: c.decode(String.self, forKey: .sshCertificateOpenSSH),
                      tlsCACertificatesDER: c.decode([Data].self, forKey: .tlsCACertificatesDER), sshHostCAKeys: c.decode([String].self, forKey: .sshHostCAKeys),
                      tlsUserCACertificatesDER: c.decode([Data].self, forKey: .tlsUserCACertificatesDER), sshUserCAKeys: c.decode([String].self, forKey: .sshUserCAKeys))
    }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(proxy, forKey: .proxy); try c.encode(username, forKey: .username); try c.encode(clusterName, forKey: .clusterName)
        try c.encode(tlsCertificateDER, forKey: .tlsCertificateDER); try c.encode(tlsPrivateKeyDER, forKey: .tlsPrivateKeyDER)
        try c.encode(sshCertificateOpenSSH, forKey: .sshCertificateOpenSSH); try c.encode(tlsCACertificatesDER, forKey: .tlsCACertificatesDER)
        try c.encode(sshHostCAKeys, forKey: .sshHostCAKeys)
        try c.encode(tlsUserCACertificatesDER, forKey: .tlsUserCACertificatesDER); try c.encode(sshUserCAKeys, forKey: .sshUserCAKeys)
    }
    public var description: String { "TeleportIdentity(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

package struct CredentialKey: Sendable {
    package let privateDER: Data
    package let publicDER: Data
    package let sshPublicKeyBlob: Data
    package var sshPublicKey: String { "ssh-rsa " + sshPublicKeyBlob.base64EncodedString() + "\n" }
    package var tlsPublicKeyPEM: String {
        let rsaAlgorithm = Data([0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00])
        return DER.pem(DER.sequence(rsaAlgorithm, DER.value(0x03, Data([0]) + publicDER)), label: "PUBLIC KEY")
    }
    package init() throws {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 3072]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, nil), let data = SecKeyCopyExternalRepresentation(key, nil) as Data? else { throw TeleportError.transport("create credential key") }
        try self.init(privateDER: data)
    }
    package init(privateDER: Data) throws {
        guard privateDER.count <= 16_384 else { throw TeleportError.limitExceeded("private key") }
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        guard let key = SecKeyCreateWithData(privateDER as CFData, attributes as CFDictionary, nil), let publicKey = SecKeyCopyPublicKey(key),
              let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else { throw TeleportError.invalidCertificate("RSA private key") }
        var all = try DERReader(data); var sequence = try all.child(0x30)
        let n = try sequence.value(0x02).data, e = try sequence.value(0x02).data
        guard all.isAtEnd, sequence.isAtEnd, n.count >= 257 else { throw TeleportError.invalidCertificate("RSA key size") }
        self.privateDER = privateDER; publicDER = data
        sshPublicKeyBlob = SSHEncoding.string("ssh-rsa") + SSHEncoding.data(e) + SSHEncoding.data(n)
    }
}
