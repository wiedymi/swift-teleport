import Foundation

/// A bounded DER codec. Cryptographic operations use Security or CryptoKit.
package struct DERReader {
    package let bytes: Data
    package var offset = 0
    package init(_ bytes: Data) throws {
        guard bytes.count <= 262_144 else { throw TeleportError.limitExceeded("DER data") }
        self.bytes = Data(bytes)
    }
    package mutating func value(_ expected: UInt8? = nil) throws -> (tag: UInt8, data: Data) {
        guard offset <= bytes.count - 2 else { throw TeleportError.invalidCertificate("truncated DER") }
        let tag = bytes[offset]; offset += 1
        let first = bytes[offset]; offset += 1
        var length = Int(first)
        if first & 0x80 != 0 {
            let count = Int(first & 0x7f)
            guard (1...4).contains(count), count <= bytes.count - offset, bytes[offset] != 0 else { throw TeleportError.invalidCertificate("DER length") }
            length = 0
            for _ in 0..<count { length = (length << 8) | Int(bytes[offset]); offset += 1 }
            guard length >= 128 else { throw TeleportError.invalidCertificate("noncanonical DER") }
        }
        guard length <= bytes.count - offset, expected == nil || tag == expected else { throw TeleportError.invalidCertificate("DER field") }
        let body = bytes.subdata(in: offset..<(offset + length)); offset += length
        return (tag, body)
    }
    package mutating func child(_ tag: UInt8) throws -> DERReader { try DERReader(value(tag).data) }
    package var isAtEnd: Bool { offset == bytes.count }
}

package enum DER {
    package static func value(_ tag: UInt8, _ data: Data) -> Data {
        var result = Data([tag])
        if data.count < 128 { result.append(UInt8(data.count)) }
        else {
            var length = data.count; var bytes = [UInt8]()
            while length > 0 { bytes.insert(UInt8(length & 0xff), at: 0); length >>= 8 }
            result.append(0x80 | UInt8(bytes.count)); result.append(contentsOf: bytes)
        }
        result.append(data); return result
    }
    package static func integer(_ value: Data) -> Data {
        var data = Data(value.drop(while: { $0 == 0 }))
        if data.isEmpty { data = Data([0]) }
        if data[0] & 0x80 != 0 { data.insert(0, at: 0) }
        return self.value(0x02, data)
    }
    package static func sequence(_ values: Data...) -> Data { value(0x30, values.reduce(into: Data()) { $0.append($1) }) }
    package static func pem(_ data: Data, label: String) -> String {
        let b64 = Array(data.base64EncodedString())
        let lines = stride(from: 0, to: b64.count, by: 64).map { String(b64[$0..<min($0 + 64, b64.count)]) }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }
    package static func decodePEM(_ data: Data, label: String) throws -> Data {
        guard data.count <= 262_144, let text = String(data: data, encoding: .utf8) else { throw TeleportError.invalidCertificate("PEM encoding") }
        let begin = "-----BEGIN \(label)-----", end = "-----END \(label)-----"
        guard let a = text.range(of: begin), let b = text.range(of: end), a.upperBound <= b.lowerBound,
              text[..<a.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              text[b.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let der = Data(base64Encoded: String(text[a.upperBound..<b.lowerBound]).filter { !$0.isWhitespace }), !der.isEmpty
        else { throw TeleportError.invalidCertificate("PEM block") }
        return der
    }
}

package struct X509Facts {
    package let commonName: String
    package let issuerCommonName: String
    package let issuerOrganizations: [String]
    package let notBefore: Date
    package let notAfter: Date
    package let isCertificateAuthority: Bool
    package let dnsNames: [String]
    package let extendedKeyUsage: [Data]?
    package let permitsDigitalSignature: Bool?

    package init(der: Data) throws {
        var all = try DERReader(der); var cert = try all.child(0x30); var body = try cert.child(0x30)
        if body.bytes.first == 0xa0 { _ = try body.value(0xa0) }
        _ = try body.value(0x02); _ = try body.value(0x30)
        let issuer = try Self.name(body.value(0x30).data)
        issuerCommonName = issuer.commonName; issuerOrganizations = issuer.organizations
        var validity = try body.child(0x30)
        func date(_ item: (tag: UInt8, data: Data)) throws -> Date {
            guard let s = String(data: item.data, encoding: .ascii), (item.tag == 0x17 && s.count == 13) || (item.tag == 0x18 && s.count == 15), s.hasSuffix("Z") else { throw TeleportError.invalidCertificate("X509 time") }
            let format = DateFormatter(); format.locale = Locale(identifier: "en_US_POSIX"); format.timeZone = TimeZone(secondsFromGMT: 0)
            format.dateFormat = item.tag == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
            format.twoDigitStartDate = Date(timeIntervalSince1970: -631_152_000)
            guard let d = format.date(from: s) else { throw TeleportError.invalidCertificate("X509 time") }; return d
        }
        notBefore = try date(validity.value()); notAfter = try date(validity.value())
        guard validity.isAtEnd, notBefore < notAfter else { throw TeleportError.invalidCertificate("X509 validity") }
        let subject = try Self.name(body.value(0x30).data)
        commonName = subject.commonName
        _ = try body.value(0x30) // SubjectPublicKeyInfo
        var authority: Bool?, names: [String]?, usages: [Data]?, digitalSignature: Bool?
        while !body.isAtEnd {
            let field = try body.value()
            if field.tag != 0xa3 { continue }
            var wrapper = try DERReader(field.data); var extensions = try wrapper.child(0x30)
            guard wrapper.isAtEnd else { throw TeleportError.invalidCertificate("X509 extensions") }
            while !extensions.isAtEnd {
                var item = try extensions.child(0x30)
                let oid = try item.value(0x06).data
                guard !item.isAtEnd else { throw TeleportError.invalidCertificate("X509 extension") }
                if item.bytes[item.offset] == 0x01 {
                    let critical = try item.value(0x01).data
                    guard critical == Data([0xff]) else { throw TeleportError.invalidCertificate("X509 critical extension") }
                }
                let payload = try item.value(0x04).data
                guard item.isAtEnd else { throw TeleportError.invalidCertificate("X509 extension") }
                switch oid {
                case Data([0x55, 0x1d, 0x13]):
                    guard authority == nil else { throw TeleportError.invalidCertificate("duplicate X509 constraints") }
                    authority = false
                    var constraintsDER = try DERReader(payload); var constraints = try constraintsDER.child(0x30)
                    if !constraints.isAtEnd, constraints.bytes[constraints.offset] == 0x01 {
                        let value = try constraints.value(0x01).data
                        guard value.count == 1, value[0] == 0 || value[0] == 0xff else { throw TeleportError.invalidCertificate("X509 constraints") }
                        authority = value[0] == 0xff
                    }
                case Data([0x55, 0x1d, 0x11]):
                    guard names == nil else { throw TeleportError.invalidCertificate("duplicate X509 subject names") }
                    names = try Self.subjectNames(payload)
                case Data([0x55, 0x1d, 0x25]):
                    guard usages == nil else { throw TeleportError.invalidCertificate("duplicate X509 extended usage") }
                    usages = try Self.keyPurposes(payload)
                case Data([0x55, 0x1d, 0x0f]):
                    guard digitalSignature == nil else { throw TeleportError.invalidCertificate("duplicate X509 key usage") }
                    digitalSignature = try Self.digitalSignature(payload)
                default: break
                }
            }
        }
        isCertificateAuthority = authority ?? false
        dnsNames = names ?? []
        extendedKeyUsage = usages
        permitsDigitalSignature = digitalSignature
    }

    private static func subjectNames(_ payload: Data) throws -> [String] {
        var outer = try DERReader(payload); var names = try outer.child(0x30)
        guard outer.isAtEnd, !names.isAtEnd else { throw TeleportError.invalidCertificate("X509 subject names") }
        var result = [String](), count = 0
        while !names.isAtEnd {
            guard count < 256 else { throw TeleportError.limitExceeded("X509 subject names") }
            count += 1
            let name = try names.value()
            guard [0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88].contains(name.tag) else {
                throw TeleportError.invalidCertificate("X509 subject name")
            }
            if name.tag == 0x82 {
                guard !name.data.isEmpty, name.data.count <= 253,
                      name.data.allSatisfy({ (0x21...0x7e).contains($0) }),
                      let value = String(data: name.data, encoding: .ascii) else {
                    throw TeleportError.invalidCertificate("X509 DNS name")
                }
                result.append(value)
            }
        }
        return result
    }

    private static func keyPurposes(_ payload: Data) throws -> [Data] {
        var outer = try DERReader(payload); var purposes = try outer.child(0x30)
        guard outer.isAtEnd, !purposes.isAtEnd else { throw TeleportError.invalidCertificate("X509 extended usage") }
        var result = [Data]()
        while !purposes.isAtEnd {
            guard result.count < 32 else { throw TeleportError.limitExceeded("X509 extended usage") }
            let oid = try purposes.value(0x06).data
            guard !oid.isEmpty, oid.count <= 32, let last = oid.last, last & 0x80 == 0 else { throw TeleportError.invalidCertificate("X509 usage OID") }
            var first = true
            for byte in oid {
                guard !first || byte != 0x80 else { throw TeleportError.invalidCertificate("X509 usage OID") }
                first = byte & 0x80 == 0
            }
            result.append(oid)
        }
        return result
    }

    private static func digitalSignature(_ payload: Data) throws -> Bool {
        var outer = try DERReader(payload); let bits = try outer.value(0x03).data
        guard outer.isAtEnd, (2...3).contains(bits.count), bits[0] < 8,
              (bits.count - 1) * 8 - Int(bits[0]) <= 9,
              let last = bits.last, last != 0,
              last.trailingZeroBitCount == Int(bits[0]) else {
            throw TeleportError.invalidCertificate("X509 key usage")
        }
        return bits[1] & 0x80 != 0
    }

    private static func name(_ data: Data) throws -> (commonName: String, organizations: [String]) {
        var subject = try DERReader(data); var names = [String](), organizations = [String]()
        while !subject.isAtEnd {
            var set = try subject.child(0x31)
            while !set.isAtEnd {
                var attribute = try set.child(0x30); let oid = try attribute.value(0x06).data; let string = try attribute.value()
                if oid == Data([0x55, 0x04, 0x03]) || oid == Data([0x55, 0x04, 0x0a]) {
                    guard [0x0c, 0x13, 0x16].contains(string.tag), let value = String(data: string.data, encoding: .utf8) else { throw TeleportError.invalidCertificate("X509 common name") }
                    if oid.last == 3 { names.append(value) } else { organizations.append(value) }
                }
            }
        }
        guard names.count == 1, let name = names.first else { throw TeleportError.invalidCertificate("X509 common name") }
        return (name, organizations)
    }
}
