import Foundation
import Security
import TeleportCore

/// Teleport's private PKI issues long-lived server certificates. Web PKI lifetime
/// limits do not apply to this route. Security still validates the full chain.
func verifyInternalServerTrust(_ trust: SecTrust, authorities: [SecCertificate],
                               serverName: String, at date: Date = Date()) throws {
    guard !authorities.isEmpty, authorities.count <= 32,
          SecTrustSetPolicies(trust, SecPolicyCreateBasicX509()) == errSecSuccess,
          SecTrustSetAnchorCertificates(trust, authorities as CFArray) == errSecSuccess,
          SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
          SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
          SecTrustSetVerifyDate(trust, date as CFDate) == errSecSuccess,
          SecTrustEvaluateWithError(trust, nil),
          let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
          !chain.isEmpty, chain.count <= 33 else {
        throw TeleportError.invalidCertificate("internal TLS chain")
    }
    let serverAuth = Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
    let anyUsage = Data([0x55, 0x1d, 0x25, 0x00])
    for (index, certificate) in chain.enumerated() {
        let data = SecCertificateCopyData(certificate) as Data
        guard data.count <= 65_536 else { throw TeleportError.limitExceeded("internal TLS certificate") }
        let facts = try X509Facts(der: data)
        guard date >= facts.notBefore, date < facts.notAfter else {
            throw TeleportError.invalidCertificate("internal TLS validity")
        }
        if index == 0 {
            guard !facts.isCertificateAuthority,
                  facts.dnsNames.contains(where: { $0.lowercased() == serverName.lowercased() }),
                  facts.extendedKeyUsage?.contains(serverAuth) == true,
                  facts.permitsDigitalSignature != false else {
                throw TeleportError.invalidCertificate("internal TLS name or usage")
            }
        } else if let usage = facts.extendedKeyUsage,
                  !usage.contains(serverAuth), !usage.contains(anyUsage) {
            throw TeleportError.invalidCertificate("internal TLS authority usage")
        }
    }
}
