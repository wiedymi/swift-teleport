#if os(macOS)
import Foundation
import XCTest
@testable import TeleportKit

/// Signs only the public keys received by the mock certificate endpoint.
struct BrowserMFACertificateIssuer: Sendable {
    enum Fault: Sendable, Equatable { case none, account, cluster, sshKey, tlsKey }
    private let directory: URL
    private let openssl: String

    init() throws {
        let candidates = ["/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl"]
        guard let openssl = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw XCTSkip("Mock certificate issuance needs an existing OpenSSL 3 installation with -force_pubkey.")
        }
        self.openssl = openssl
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("teleport-browser-mfa-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                              attributes: [.posixPermissions: 0o700])
        do {
            try write(Data("[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n".utf8), "ca.conf")
            try write(Data("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n".utf8), "client.conf")
            for name in ["user-ca", "host-ca"] {
                try run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", file(name)])
            }
            try run(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", file("tls-ca.key"),
                              "-out", file("tls-ca.pem"), "-subj", "/CN=cluster/O=cluster", "-days", "1",
                              "-config", file("ca.conf"), "-extensions", "ca"])
            try run(openssl, ["pkey", "-in", file("tls-ca.key"), "-pubout", "-out", file("other-tls.pub")])
        } catch { remove(); throw error }
    }

    func remove() { try? FileManager.default.removeItem(at: directory) }

    func response(to body: Data, fault: Fault = .none, sshValidity: String = "-1m:+59m") throws -> Data {
        let request = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let ssh = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request["ssh_pub_key"] as? String)))
        let tls = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(request["tls_pub_key"] as? String)))
        try write(fault == .sshKey ? Data(contentsOf: url("host-ca.pub")) : ssh, "client.pub")
        try write(tls, "client-tls.pub")
        try run("/usr/bin/ssh-keygen", ["-q", "-s", file("user-ca"), "-I", "alice", "-n", "alice,-teleport-internal-join",
                                       "-V", sshValidity, file("client.pub")])
        try run(openssl, ["x509", "-new", "-force_pubkey", file(fault == .tlsKey ? "other-tls.pub" : "client-tls.pub"),
                          "-CA", file("tls-ca.pem"), "-CAkey", file("tls-ca.key"), "-set_serial", "1", "-days", "1",
                          "-subj", "/CN=alice", "-extfile", file("client.conf"), "-out", file("client.pem")])
        return try JSONSerialization.data(withJSONObject: [
            "username": fault == .account ? "other" : "alice",
            "cert": Data(contentsOf: url("client-cert.pub")).base64EncodedString(),
            "tls_cert": Data(contentsOf: url("client.pem")).base64EncodedString(),
            "host_signers": [["domain_name": fault == .cluster ? "other" : "cluster",
                              "checking_keys": [Data(contentsOf: url("host-ca.pub")).base64EncodedString()],
                              "tls_certs": [Data(contentsOf: url("tls-ca.pem")).base64EncodedString()]]]
        ])
    }

    func authorityExports() throws -> [String: Data] {
        try ["tls-user": JSONSerialization.data(withJSONObject: [["data": Data(contentsOf: url("tls-ca.pem")).base64EncodedString()]]),
             "user": JSONSerialization.data(withJSONObject: [["data": Data(contentsOf: url("user-ca.pub")).base64EncodedString()]])]
    }

    private func file(_ name: String) -> String { url(name).path }
    private func url(_ name: String) -> URL { directory.appendingPathComponent(name) }
    private func write(_ bytes: Data, _ name: String) throws {
        try bytes.write(to: url(name))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file(name))
    }
    private func run(_ executable: String, _ arguments: [String]) throws {
        let process = Process(); process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw TeleportError.transport("mock certificate tool") }
    }
}
#endif
