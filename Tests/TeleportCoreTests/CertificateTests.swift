import XCTest
@testable import TeleportCore

final class CertificateTests: XCTestCase {
    func testProxyRejectsInvalidOriginsAndChecksPorts() throws {
        for input in ["http://proxy.example", "https://user:password@proxy.example", "https://proxy.example/path", "https://proxy.example:0", "https://proxy.example:65536", "https://proxy.example?x=1"] {
            XCTAssertThrowsError(try TeleportProxy(url: XCTUnwrap(URL(string: input))), input)
        }
        XCTAssertEqual(try TeleportProxy(url: XCTUnwrap(URL(string: "https://PROXY.example:443/"))).url.absoluteString, "https://proxy.example")
    }

    func testMalformedSSHLengthAndTimeDoNotTrap() throws {
        let malformed = [Data(), Data([0xff,0xff,0xff,0xff]), Data([0,0,0,11]) + Data("ssh-ed25519".utf8)]
        for data in malformed { XCTAssertThrowsError(try TeleportSSHCertificate(openSSH: "ssh-ed25519-cert-v01@openssh.com " + data.base64EncodedString())) }
        XCTAssertThrowsError(try DERReader(Data(repeating: 0, count: 262_145)))
    }

    #if os(macOS)
    func testRealUserIdentityBindsKeysAccountTrustAndStorage() throws {
        let fixture = try CertificateFixture()
        defer { fixture.remove() }
        let key = try CredentialKey()
        let identity = try fixture.identity(key: key)
        XCTAssertEqual(identity.allowedLogins, ["alice"])
        XCTAssertTrue(identity.isUsable())
        XCTAssertFalse(identity.isUsable(at: identity.validBefore))
        XCTAssertFalse(identity.isUsable(at: identity.validAfter.addingTimeInterval(-1)))
        XCTAssertEqual(String(describing: identity), "TeleportIdentity(<redacted>)")
        XCTAssertEqual(Mirror(reflecting: identity).children.count, 0)
        let restored = try JSONDecoder().decode(TeleportIdentity.self, from: JSONEncoder().encode(identity))
        XCTAssertEqual(restored.tlsPrivateKeyDER, key.privateDER)
        let wrongKey = try CredentialKey()
        XCTAssertThrowsError(try TeleportIdentity(proxy: identity.proxy, username: identity.username, clusterName: identity.clusterName,
                                                tlsCertificateDER: identity.tlsCertificateDER, tlsPrivateKeyDER: wrongKey.privateDER,
                                                sshCertificateOpenSSH: identity.sshCertificateOpenSSH, tlsCACertificatesDER: identity.tlsCACertificatesDER, sshHostCAKeys: identity.sshHostCAKeys, tlsUserCACertificatesDER: identity.tlsUserCACertificatesDER, sshUserCAKeys: identity.sshUserCAKeys))
        XCTAssertThrowsError(try TeleportIdentity(proxy: identity.proxy, username: "other", clusterName: identity.clusterName,
                                                tlsCertificateDER: identity.tlsCertificateDER, tlsPrivateKeyDER: key.privateDER,
                                                sshCertificateOpenSSH: identity.sshCertificateOpenSSH, tlsCACertificatesDER: identity.tlsCACertificatesDER, sshHostCAKeys: identity.sshHostCAKeys, tlsUserCACertificatesDER: identity.tlsUserCACertificatesDER, sshUserCAKeys: identity.sshUserCAKeys))
        XCTAssertThrowsError(try TeleportIdentity(proxy: identity.proxy, username: identity.username, clusterName: identity.clusterName,
                                                tlsCertificateDER: identity.tlsCertificateDER, tlsPrivateKeyDER: key.privateDER,
                                                sshCertificateOpenSSH: identity.sshCertificateOpenSSH, tlsCACertificatesDER: [identity.tlsCertificateDER], sshHostCAKeys: identity.sshHostCAKeys, tlsUserCACertificatesDER: identity.tlsUserCACertificatesDER, sshUserCAKeys: identity.sshUserCAKeys))
    }

    func testRealHostCertificatesVerifySignaturesPrincipalTimeAndAuthority() throws {
        let fixture = try CertificateFixture()
        defer { fixture.remove() }
        for algorithm in ["ed25519", "ecdsa", "rsa"] {
            let certificate = try fixture.hostCertificate(algorithm: algorithm)
            let parsed = try TeleportSSHCertificate(openSSH: certificate)
            let authority = try String(contentsOf: fixture.url("host-signing-" + algorithm + ".pub"), encoding: .utf8)
            try parsed.verify(authorities: [authority], principal: "node.cluster", kind: .host)
            XCTAssertThrowsError(try parsed.verify(authorities: [authority], principal: "wrong.cluster", kind: .host))
            XCTAssertThrowsError(try parsed.verify(authorities: [authority], principal: "node.cluster", kind: .user))
            XCTAssertThrowsError(try parsed.verify(authorities: [authority], principal: "node.cluster", kind: .host, at: XCTUnwrap(parsed.validBefore)))
            let wrongAuthority = try String(contentsOf: fixture.url("user-ca.pub"), encoding: .utf8)
            XCTAssertThrowsError(try parsed.verify(authorities: [wrongAuthority], principal: "node.cluster", kind: .host))
            var wire = try SSHEncoding.authorizedKey(certificate).blob
            wire[wire.count - 1] ^= 1
            let kind = try SSHEncoding.authorizedKey(certificate).kind
            let tampered = try TeleportSSHCertificate(openSSH: kind + " " + wire.base64EncodedString())
            XCTAssertThrowsError(try tampered.verify(authorities: [authority], principal: "node.cluster", kind: .host))
        }
    }

    func testRealHostCertificateWithoutExpiryStillChecksSignatureAndStartTime() throws {
        let fixture = try CertificateFixture()
        defer { fixture.remove() }
        let parsed = try TeleportSSHCertificate(openSSH: fixture.hostCertificate(algorithm: "ed25519", validity: "-1m:forever"))
        XCTAssertNil(parsed.validBefore)
        let authority = try String(contentsOf: fixture.url("host-signing-ed25519.pub"), encoding: .utf8)
        try parsed.verify(authorities: [authority], principal: "node.cluster", kind: .host)
        XCTAssertThrowsError(try parsed.verify(authorities: [authority], principal: "node.cluster", kind: .host, at: parsed.validAfter.addingTimeInterval(-1)))
        let wrongAuthority = try String(contentsOf: fixture.url("user-ca.pub"), encoding: .utf8)
        XCTAssertThrowsError(try parsed.verify(authorities: [wrongAuthority], principal: "node.cluster", kind: .host))
    }
    #endif
}

#if os(macOS)
private final class CertificateFixture {
    private let directory: URL
    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("teleport-cert-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            try write(Data("[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n".utf8), "ca.conf")
            for name in ["user-ca", "host-ca"] { _ = try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", url(name).path]) }
            _ = try run("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", url("tls-ca.key").path, "-out", url("tls-ca.pem").path, "-subj", "/CN=cluster/O=cluster", "-days", "1", "-config", url("ca.conf").path, "-extensions", "v3_ca"])
        } catch { remove(); throw error }
    }
    func url(_ name: String) -> URL { directory.appendingPathComponent(name) }
    func remove() { try? FileManager.default.removeItem(at: directory) }
    private func write(_ bytes: Data, _ name: String) throws {
        try bytes.write(to: url(name)); try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url(name).path)
    }
    func identity(key: CredentialKey) throws -> TeleportIdentity {
        try write(Data(DER.pem(key.privateDER, label: "RSA PRIVATE KEY").utf8), "client.key")
        try write(Data(key.sshPublicKey.utf8), "client.pub")
        _ = try run("/usr/bin/ssh-keygen", ["-q", "-s", url("user-ca").path, "-I", "alice", "-n", "alice,-teleport-internal-join", "-V", "-1m:+1h", url("client.pub").path])
        _ = try run("/usr/bin/openssl", ["req", "-new", "-key", url("client.key").path, "-out", url("client.csr").path, "-subj", "/CN=alice"])
        _ = try run("/usr/bin/openssl", ["x509", "-req", "-in", url("client.csr").path, "-CA", url("tls-ca.pem").path, "-CAkey", url("tls-ca.key").path, "-CAcreateserial", "-days", "1", "-out", url("client.pem").path])
        return try TeleportIdentity(proxy: TeleportProxy(url: URL(string: "https://proxy.example")!), username: "alice", clusterName: "cluster",
                                    tlsCertificateDER: DER.decodePEM(Data(contentsOf: url("client.pem")), label: "CERTIFICATE"), tlsPrivateKeyDER: key.privateDER,
                                    sshCertificateOpenSSH: String(contentsOf: url("client-cert.pub"), encoding: .utf8),
                                    tlsCACertificatesDER: [DER.decodePEM(Data(contentsOf: url("tls-ca.pem")), label: "CERTIFICATE")],
                                    sshHostCAKeys: [String(contentsOf: url("host-ca.pub"), encoding: .utf8)],
                                    tlsUserCACertificatesDER: [DER.decodePEM(Data(contentsOf: url("tls-ca.pem")), label: "CERTIFICATE")],
                                    sshUserCAKeys: [String(contentsOf: url("user-ca.pub"), encoding: .utf8)])
    }
    func hostCertificate(algorithm: String, validity: String = "-1m:+1h") throws -> String {
        let path = url("host-" + algorithm)
        let authority = url("host-signing-" + algorithm)
        _ = try run("/usr/bin/ssh-keygen", ["-q", "-t", algorithm, "-N", "", "-f", authority.path])
        _ = try run("/usr/bin/ssh-keygen", ["-q", "-t", algorithm, "-N", "", "-f", path.path])
        _ = try run("/usr/bin/ssh-keygen", ["-q", "-s", authority.path, "-I", "node", "-h", "-n", "node.cluster", "-V", validity, path.path + ".pub"])
        return try String(contentsOf: URL(fileURLWithPath: path.path + "-cert.pub"), encoding: .utf8)
    }
    @discardableResult private func run(_ executable: String, _ arguments: [String]) throws -> Data {
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw TeleportError.transport("certificate test tool failed") }; return data
    }
}
#endif
