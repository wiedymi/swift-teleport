import Foundation
import Security
import CryptoKit

package struct SSHReader {
    package let bytes: Data
    package var offset = 0
    package init(_ bytes: Data) throws {
        guard bytes.count <= 262_144 else { throw TeleportError.limitExceeded("SSH certificate") }
        self.bytes = Data(bytes)
    }
    package mutating func integer<T: FixedWidthInteger>(_ type: T.Type) throws -> T {
        let count = MemoryLayout<T>.size
        guard count <= bytes.count - offset else { throw TeleportError.invalidCertificate("truncated SSH value") }
        var value: T = 0
        for _ in 0..<count { value = (value << 8) | T(bytes[offset]); offset += 1 }
        return value
    }
    package mutating func data() throws -> Data {
        let length = Int(try integer(UInt32.self))
        guard length <= 65_536, length <= bytes.count - offset else { throw TeleportError.invalidCertificate("SSH field length") }
        defer { offset += length }; return bytes.subdata(in: offset..<(offset + length))
    }
    package mutating func string() throws -> String {
        guard let string = String(data: try data(), encoding: .utf8), !string.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw TeleportError.invalidCertificate("SSH string") }
        return string
    }
    package var isAtEnd: Bool { offset == bytes.count }
}

package enum SSHEncoding {
    package static func data(_ data: Data) -> Data {
        precondition(data.count <= Int(UInt32.max))
        var length = UInt32(data.count).bigEndian
        var result = withUnsafeBytes(of: &length) { Data($0) }; result.append(data); return result
    }
    package static func string(_ value: String) -> Data { data(Data(value.utf8)) }
    package static func authorizedKey(_ string: String) throws -> (kind: String, blob: Data) {
        guard string.utf8.count <= 350_000 else { throw TeleportError.limitExceeded("SSH public key") }
        let fields = string.split(whereSeparator: { $0.isWhitespace })
        guard fields.count >= 2, let raw = Data(base64Encoded: String(fields[1])), raw.count <= 262_144 else { throw TeleportError.invalidCertificate("SSH public key") }
        var reader = try SSHReader(raw)
        let kind = try reader.string()
        guard kind == fields[0] else { throw TeleportError.invalidCertificate("SSH key type") }
        return (kind, raw)
    }
    package static func rsaPublicDER(_ blob: Data) throws -> Data {
        var reader = try SSHReader(blob)
        guard try reader.string() == "ssh-rsa" else { throw TeleportError.invalidCertificate("RSA key type") }
        let e = try reader.data(), n = try reader.data()
        guard reader.isAtEnd, (256...1025).contains(n.count), !e.isEmpty, e.count <= 8 else { throw TeleportError.invalidCertificate("RSA key size") }
        try positiveInteger(e); try positiveInteger(n)
        return DER.sequence(DER.integer(n), DER.integer(e))
    }
    package static func positiveInteger(_ data: Data) throws {
        guard !data.isEmpty, data[0] & 0x80 == 0,
              !(data.count > 1 && data[0] == 0 && data[1] & 0x80 == 0) else { throw TeleportError.invalidCertificate("SSH positive integer") }
    }
}

/// An OpenSSH certificate. The parser rejects unsupported critical options.
public struct TeleportSSHCertificate: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public enum Kind: UInt32, Sendable { case user = 1, host = 2 }
    public let kind: Kind
    public let principals: [String]
    public let validAfter: Date
    /// Nil is OpenSSH's exact UInt64.max value for no expiry.
    public let validBefore: Date?
    public let keyID: String
    public let publicKeyBlob: Data
    public let signingKeyBlob: Data
    public let extensions: [String: Data]
    private let signedBytes: Data
    private let signature: Data

    public init(openSSH: String) throws {
        let parsed = try SSHEncoding.authorizedKey(openSSH)
        var r = try SSHReader(parsed.blob)
        let type = try r.string()
        _ = try r.data() // nonce
        let keyType: String
        var keyData = Data()
        switch type {
        case "ssh-rsa-cert-v01@openssh.com":
            keyType = "ssh-rsa"
            let e = try r.data(), n = try r.data()
            try SSHEncoding.positiveInteger(e); try SSHEncoding.positiveInteger(n)
            keyData.append(SSHEncoding.data(e)); keyData.append(SSHEncoding.data(n))
        case "ssh-ed25519-cert-v01@openssh.com":
            keyType = "ssh-ed25519"; let key = try r.data()
            guard key.count == 32 else { throw TeleportError.invalidCertificate("Ed25519 key size") }; keyData.append(SSHEncoding.data(key))
        case "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com":
            keyType = String(type.dropLast("-cert-v01@openssh.com".count))
            let curve = try r.string(), point = try r.data()
            guard keyType == "ecdsa-sha2-" + curve, [("nistp256",65),("nistp384",97),("nistp521",133)].contains(where: { $0.0 == curve && $0.1 == point.count }), point.first == 4 else { throw TeleportError.invalidCertificate("ECDSA key") }
            keyData.append(SSHEncoding.string(curve)); keyData.append(SSHEncoding.data(point))
        default: throw TeleportError.invalidCertificate("unsupported SSH algorithm")
        }
        publicKeyBlob = SSHEncoding.string(keyType) + keyData
        _ = try r.integer(UInt64.self) // serial
        guard let kind = Kind(rawValue: try r.integer(UInt32.self)) else { throw TeleportError.invalidCertificate("SSH certificate type") }
        self.kind = kind
        keyID = try r.string()
        var list = try SSHReader(r.data()); var principals = [String]()
        while !list.isAtEnd {
            guard principals.count < 256 else { throw TeleportError.limitExceeded("SSH principals") }
            let principal = try list.string()
            guard !principal.isEmpty, principal.utf8.count <= 1024 else { throw TeleportError.invalidCertificate("SSH principal") }
            principals.append(principal)
        }
        self.principals = principals
        let after = try r.integer(UInt64.self), before = try r.integer(UInt64.self)
        guard after < before, after <= 253_402_300_799,
              before == UInt64.max || before <= 253_402_300_799 else { throw TeleportError.invalidCertificate("SSH validity") }
        validAfter = Date(timeIntervalSince1970: Double(after))
        validBefore = before == UInt64.max ? nil : Date(timeIntervalSince1970: Double(before))
        let critical = try Self.options(r.data())
        guard critical.isEmpty else { throw TeleportError.invalidCertificate("unsupported SSH critical option") }
        extensions = try Self.options(r.data())
        _ = try r.data() // reserved
        signingKeyBlob = try r.data()
        signedBytes = parsed.blob.subdata(in: 0..<r.offset)
        signature = try r.data()
        guard r.isAtEnd else { throw TeleportError.invalidCertificate("trailing SSH data") }
    }

    private static func options(_ data: Data) throws -> [String: Data] {
        var r = try SSHReader(data); var result = [String: Data](); var previous = ""
        while !r.isAtEnd {
            guard result.count < 128 else { throw TeleportError.limitExceeded("SSH options") }
            let name = try r.string()
            guard !name.isEmpty, name > previous else { throw TeleportError.invalidCertificate("SSH option order") }
            result[name] = try r.data(); previous = name
        }
        return result
    }

    /// Verify the certificate signature, time, type and an exact principal.
    public func verify(authorities: [String], principal: String, kind: Kind, at date: Date = Date()) throws {
        guard self.kind == kind, date >= validAfter,
              validBefore.map({ date < $0 }) ?? true,
              principals.contains(principal) else { throw TeleportError.invalidCertificate("SSH certificate identity or time") }
        let trusted = try authorities.map { try SSHEncoding.authorizedKey($0).blob }
        guard trusted.contains(signingKeyBlob) else { throw TeleportError.invalidCertificate("untrusted SSH authority") }
        try verifySignature()
    }

    package func verifySignature() throws {
        var key = try SSHReader(signingKeyBlob), sig = try SSHReader(signature)
        let keyType = try key.string(), algorithm = try sig.string(), bytes = try sig.data()
        guard sig.isAtEnd else { throw TeleportError.invalidCertificate("SSH signature data") }
        let valid: Bool
        switch keyType {
        case "ssh-ed25519":
            let pub = try key.data()
            guard key.isAtEnd, algorithm == "ssh-ed25519", pub.count == 32 else { throw TeleportError.invalidCertificate("SSH signature algorithm") }
            valid = try Curve25519.Signing.PublicKey(rawRepresentation: pub).isValidSignature(bytes, for: signedBytes)
        case "ssh-rsa":
            guard algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512" else { throw TeleportError.invalidCertificate("RSA signature algorithm") }
            let der = try SSHEncoding.rsaPublicDER(signingKeyBlob)
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
            guard let publicKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else { throw TeleportError.invalidCertificate("RSA authority") }
            valid = SecKeyVerifySignature(publicKey, algorithm == "rsa-sha2-256" ? .rsaSignatureMessagePKCS1v15SHA256 : .rsaSignatureMessagePKCS1v15SHA512, signedBytes as CFData, bytes as CFData, nil)
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            let curve = try key.string(), point = try key.data()
            guard key.isAtEnd, keyType == "ecdsa-sha2-" + curve, algorithm == keyType else { throw TeleportError.invalidCertificate("ECDSA signature algorithm") }
            var pair = try SSHReader(bytes); let r = try pair.data(), s = try pair.data()
            guard pair.isAtEnd, r.count <= 67, s.count <= 67 else { throw TeleportError.invalidCertificate("ECDSA signature size") }
            try SSHEncoding.positiveInteger(r); try SSHEncoding.positiveInteger(s)
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic]
            guard let publicKey = SecKeyCreateWithData(point as CFData, attributes as CFDictionary, nil) else { throw TeleportError.invalidCertificate("ECDSA authority") }
            let alg: SecKeyAlgorithm = curve == "nistp256" ? .ecdsaSignatureMessageX962SHA256 : curve == "nistp384" ? .ecdsaSignatureMessageX962SHA384 : .ecdsaSignatureMessageX962SHA512
            valid = SecKeyVerifySignature(publicKey, alg, signedBytes as CFData, DER.sequence(DER.integer(r), DER.integer(s)) as CFData, nil)
        default: throw TeleportError.invalidCertificate("unsupported SSH authority")
        }
        guard valid else { throw TeleportError.invalidCertificate("SSH signature") }
    }

    public var description: String { "TeleportSSHCertificate(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
