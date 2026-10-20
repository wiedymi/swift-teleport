#if os(macOS)
import Foundation
import Security
import Testing
import TeleportCore
@testable import TeleportKit

@Test func internalTLSAcceptsPrivatePKILifetimeAndRejectsWrongTrustNameUsageAndTime() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("teleport-tls-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                          attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    func file(_ name: String) -> String { directory.appendingPathComponent(name).path }
    func run(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw TeleportError.transport("TLS test tool") }
    }
    try Data("[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n".utf8)
        .write(to: directory.appendingPathComponent("ca.conf"))
    for name in ["root", "other"] {
        try run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", file(name + ".key"),
                 "-out", file(name + ".pem"), "-subj", "/CN=" + name, "-days", "4000",
                 "-config", file("ca.conf"), "-extensions", "ca"])
    }
    try run(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", file("server.key"),
             "-out", file("server.csr"), "-subj", "/CN=server"])
    for (name, usage, keyUsage) in [("server", "serverAuth", "digitalSignature"),
                                   ("client", "clientAuth", "digitalSignature"),
                                   ("key-usage", "serverAuth", "keyEncipherment")] {
        try Data("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:teleport.cluster.local\nextendedKeyUsage=\(usage)\nkeyUsage=critical,\(keyUsage)\n".utf8)
            .write(to: directory.appendingPathComponent("leaf.conf"))
        try run(["x509", "-req", "-in", file("server.csr"), "-CA", file("root.pem"),
                 "-CAkey", file("root.key"), "-CAcreateserial", "-days", "3650", "-extfile", file("leaf.conf"),
                 "-out", file(name + ".pem")])
    }
    func der(_ name: String) throws -> Data {
        try DER.decodePEM(Data(contentsOf: directory.appendingPathComponent(name + ".pem")), label: "CERTIFICATE")
    }
    func certificate(_ name: String) throws -> SecCertificate {
        try #require(SecCertificateCreateWithData(nil, der(name) as CFData))
    }
    let root = try certificate("root"), other = try certificate("other")
    func trust(_ certificate: SecCertificate) throws -> SecTrust {
        var result: SecTrust?
        #expect(SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &result) == errSecSuccess)
        return try #require(result)
    }
    let server = try certificate("server")
    try verifyInternalServerTrust(trust(server), authorities: [root], serverName: "teleport.cluster.local")
    for (leaf, authority, name, date) in [
        (server, other, "teleport.cluster.local", Date()),
        (server, root, "wrong.cluster.local", Date()),
        (try certificate("client"), root, "teleport.cluster.local", Date()),
        (try certificate("key-usage"), root, "teleport.cluster.local", Date()),
        (server, root, "teleport.cluster.local", Date().addingTimeInterval(3651 * 86_400)),
        (server, root, "teleport.cluster.local", Date().addingTimeInterval(-86_400)),
    ] {
        #expect(throws: TeleportError.self) { try verifyInternalServerTrust(trust(leaf), authorities: [authority], serverName: name, at: date) }
    }
    var tampered = try der("server"); tampered[tampered.count - 1] ^= 1
    let changed = try #require(SecCertificateCreateWithData(nil, tampered as CFData))
    #expect(throws: TeleportError.self) { try verifyInternalServerTrust(trust(changed), authorities: [root], serverName: "teleport.cluster.local") }
}
#endif
