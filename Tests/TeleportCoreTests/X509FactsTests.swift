import XCTest
@testable import TeleportCore

final class X509FactsTests: XCTestCase {
    private let serverAuth = Data([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])

    func testNameAndUsageFactsKeepAbsenceAndExactNames() throws {
        let absent = try X509Facts(der: certificate([]))
        XCTAssertEqual(absent.dnsNames, [])
        XCTAssertNil(absent.extendedKeyUsage)
        XCTAssertNil(absent.permitsDigitalSignature)
        let facts = try X509Facts(der: certificate([
            ext(0x11, DER.sequence(DER.value(0x82, Data("teleport.cluster.local".utf8)),
                                  DER.value(0x82, Data("*.example".utf8)),
                                  DER.value(0x86, Data("https://ignored.example".utf8)))),
            ext(0x25, DER.sequence(DER.value(0x06, serverAuth))),
            ext(0x0f, DER.value(0x03, Data([7, 0x80]))),
        ]))
        XCTAssertEqual(facts.dnsNames, ["teleport.cluster.local", "*.example"])
        XCTAssertFalse(facts.dnsNames.contains("other.example"))
        XCTAssertEqual(facts.extendedKeyUsage, [serverAuth])
        XCTAssertEqual(facts.permitsDigitalSignature, true)
        let noSignature = try X509Facts(der: certificate([ext(0x0f, DER.value(0x03, Data([5, 0x20])))]))
        XCTAssertEqual(noSignature.permitsDigitalSignature, false)
    }

    func testDuplicateNameAndUsageExtensionsFail() throws {
        for value in [ext(0x11, DER.sequence(DER.value(0x82, Data("host".utf8)))),
                      ext(0x25, DER.sequence(DER.value(0x06, serverAuth))),
                      ext(0x0f, DER.value(0x03, Data([5, 0x20])))] {
            XCTAssertThrowsError(try X509Facts(der: certificate([value, value])))
        }
    }

    func testSubjectNameEncodingAndCountAreBounded() throws {
        for bytes in [Data(), Data([0]), Data([0x80]), Data("bad name".utf8), Data(repeating: 0x61, count: 254)] {
            XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x11, DER.sequence(DER.value(0x82, bytes)))])))
        }
        for payload in [DER.sequence(), DER.sequence(DER.value(0x02, Data([1]))),
                        DER.sequence(DER.value(0x82, Data("host".utf8))) + Data([0]),
                        DER.value(0x30, Data([0x82, 3, 0x61]))] {
            XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x11, payload)])))
        }
        let nonDNS = DER.value(0x87, Data([127, 0, 0, 1]))
        let allowed = DER.value(0x30, Data(repeating: nonDNS, count: 256))
        XCTAssertEqual(try X509Facts(der: certificate([ext(0x11, allowed)])).dnsNames, [])
        XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x11, DER.value(0x30, Data(repeating: nonDNS, count: 257)))])))
    }

    func testExtendedUsageRequiresCanonicalBoundedOIDs() throws {
        for oid in [Data(), Data([0x80, 0]), Data([0x2b, 0x80, 0]), Data([0x2b, 0x81]), Data(repeating: 1, count: 33)] {
            XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x25, DER.sequence(DER.value(0x06, oid)))])))
        }
        XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x25, DER.sequence())])))
        let purpose = DER.value(0x06, serverAuth)
        XCTAssertEqual(try X509Facts(der: certificate([ext(0x25, DER.value(0x30, Data(repeating: purpose, count: 32)))])).extendedKeyUsage?.count, 32)
        XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x25, DER.value(0x30, Data(repeating: purpose, count: 33)))])))
        XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x25, DER.sequence(purpose) + Data([0]))])))
    }

    func testKeyUsageRequiresCanonicalNamedBits() throws {
        for bits in [Data(), Data([0]), Data([8, 0x80]), Data([0, 0]), Data([7, 0x81]), Data([0, 0x80]),
                     Data([6, 0x80, 0x40]), Data([7, 0x80, 0x80, 0x80])] {
            XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x0f, DER.value(0x03, bits))])))
        }
        XCTAssertThrowsError(try X509Facts(der: certificate([ext(0x0f, DER.value(0x03, Data([7, 0x80])) + Data([0]))])))
        XCTAssertEqual(try X509Facts(der: certificate([ext(0x0f, DER.value(0x03, Data([7, 0x80, 0x80])))] )).permitsDigitalSignature, true)
    }

    private func ext(_ oid: UInt8, _ payload: Data) -> Data {
        DER.sequence(DER.value(0x06, Data([0x55, 0x1d, oid])), DER.value(0x04, payload))
    }

    /// These values test DER parsing only. Security tests use signed certificates.
    private func certificate(_ extensions: [Data]) -> Data {
        let name = DER.sequence(DER.value(0x31, DER.sequence(DER.value(0x06, Data([0x55, 0x04, 0x03])), DER.value(0x0c, Data("cluster".utf8)))))
        let validity = DER.sequence(DER.value(0x17, Data("260101000000Z".utf8)), DER.value(0x17, Data("270101000000Z".utf8)))
        let extensionField = extensions.isEmpty ? Data() : DER.value(0xa3, DER.value(0x30, extensions.reduce(into: Data()) { $0.append($1) }))
        return DER.sequence(DER.sequence(DER.integer(Data([1])), DER.sequence(), name, validity, name, DER.sequence(), extensionField),
                            DER.sequence(), DER.value(0x03, Data([0, 1])))
    }
}

private extension Data {
    init(repeating bytes: Data, count: Int) {
        self = (0..<count).reduce(into: Data()) { value, _ in value.append(bytes) }
    }
}
