import XCTest
import Foundation
import CryptoKit
import SwiftProtobuf
@testable import TeleportKit

final class AuthTests: XCTestCase, @unchecked Sendable {
    func testLocalLoginWireUsesIndependentSSHAndTLSFieldsAndNanoseconds() throws {
        let finish = LoginFinish(user: "alice", password: "test-password", totp_code: "123456", ssh_pub_key: Data("ssh key\n".utf8), tls_pub_key: Data("TLS key\n".utf8), ttl: 3_600_000_000_000)
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(finish)) as? [String: Any])
        XCTAssertEqual(body["ssh_pub_key"] as? String, Data("ssh key\n".utf8).base64EncodedString())
        XCTAssertEqual(body["tls_pub_key"] as? String, Data("TLS key\n".utf8).base64EncodedString())
        XCTAssertEqual(body["totp_code"] as? String, "123456")
        XCTAssertEqual(body["ttl"] as? Int64, 3_600_000_000_000)
        let begin = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(LoginBegin(user: "alice", pass: "test-password"))) as? [String: String])
        XCTAssertEqual(begin["pass"], "test-password")
        XCTAssertNil(begin["password"])
    }

    func testDiscoveryRejectsUnsupportedAndMalformedPolicies() throws {
        func ping(version: String = "18.11.4", routing: Bool = true, fips: Bool = false, keyPolicy: String = "none", deviceEnrollment: Bool = false, motd: Bool = false) throws -> ProxyPing {
            let body: [String: Any] = ["cluster_name": "cluster", "server_version": version, "fips": fips, "auth": ["type": "local", "second_factor": "otp", "private_key_policy": keyPolicy, "device_trust": ["auto_enroll": deviceEnrollment], "has_motd": motd], "proxy": ["tls_routing_enabled": routing]]
            return try JSONDecoder().decode(ProxyPing.self, from: JSONSerialization.data(withJSONObject: body))
        }
        try ping().validate()
        for version in ["18.bad", "18.1.2.3", "18..2", "18.1.-2", "18.999999999.0", "19.0.0"] { XCTAssertThrowsError(try ping(version: version).validate()) }
        XCTAssertThrowsError(try ping(routing: false).validate())
        XCTAssertThrowsError(try ping(fips: true).validate())
        XCTAssertThrowsError(try ping(keyPolicy: "hardware_key_touch").validate())
        XCTAssertThrowsError(try ping(deviceEnrollment: true).validate())
        XCTAssertThrowsError(try ping(motd: true).validate())
    }

    func testNodePagePreservesIDAndRejectsDuplicateOrMalformedPagination() throws {
        var response = Teleportkit_Resources_ListResourcesResponse()
        var resource = Teleportkit_Resources_Resource()
        resource.node.kind = "node"; resource.node.metadata.name = "stable-id"; resource.node.spec.hostname = "display-name"
        resource.node.metadata.labels = ["env": "test"]
        response.resources = [resource]; response.nextKey = "next"
        let page = try NodePageDecoder.decode(response.serializedData(), clusterName: "cluster", limit: 1, startKey: "")
        XCTAssertEqual(page.nodes.first?.id, "stable-id"); XCTAssertEqual(page.nodes.first?.name, "display-name"); XCTAssertTrue(page.hasMore)
        XCTAssertThrowsError(try NodePageDecoder.decode(response.serializedData(), clusterName: "cluster", limit: 1, startKey: "next"))
        response.resources.append(resource)
        XCTAssertThrowsError(try NodePageDecoder.decode(response.serializedData(), clusterName: "cluster", limit: 2, startKey: ""))
        XCTAssertThrowsError(try NodePageDecoder.decode(Data([0x0a,0xff,0xff,0xff,0xff,0x7f]), clusterName: "cluster", limit: 100, startKey: ""))
        XCTAssertThrowsError(try NodePageDecoder.decode(Data(repeating: 0, count: 1_048_577), clusterName: "cluster", limit: 100, startKey: ""))
    }

    func testNodePageRejectsRepeatedEmptyResourcesBeforeDecodingAllEntries() throws {
        var bytes = Data(repeating: 0, count: 200_000)
        for index in stride(from: 0, to: bytes.count, by: 2) { bytes[index] = 0x0a }
        XCTAssertThrowsError(try NodePageDecoder.decode(bytes, clusterName: "cluster", limit: 100, startKey: "")) { error in
            XCTAssertEqual(error as? TeleportError, .limitExceeded("node page resources"))
        }
        // The excessive entry has malformed nested data. The page limit must
        // reject it without attempting to decode another Resource.
        let excessiveMalformedEntry = Data([0x0a, 0x00, 0x0a, 0x03, 0x1a, 0x01, 0x80])
        XCTAssertThrowsError(try NodePageDecoder.decode(excessiveMalformedEntry, clusterName: "cluster", limit: 1, startKey: "")) { error in
            XCTAssertEqual(error as? TeleportError, .limitExceeded("node page resources"))
        }
    }

    func testNodePageRetainsProtobufUnknownFieldAndWrongWireBehavior() throws {
        var response = Teleportkit_Resources_ListResourcesResponse()
        var resource = Teleportkit_Resources_Resource()
        resource.node.kind = "node"; resource.node.metadata.name = "stable-id"; resource.node.spec.hostname = "node"
        response.resources = [resource]
        var bytes = try response.serializedData()
        // Unknown varint, fixed64, bytes, group, and fixed32 fields.
        bytes.append(contentsOf: [0xf8, 0x07, 0x01, 0xf1, 0x07, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0xea, 0x07, 0x02, 0xff, 0xff, 0xe3, 0x07, 0x08, 0x01, 0xe4, 0x07,
                                  0xdd, 0x07, 0, 0, 0, 0])
        // A known Resource field with varint wire type must also be skipped.
        bytes.append(contentsOf: [0x08, 0x01])
        let page = try NodePageDecoder.decode(bytes, clusterName: "cluster", limit: 1, startKey: "")
        XCTAssertEqual(page.nodes.map(\.id), ["stable-id"])
    }

    func testBrowserCipherRejectsWrongKeyTamperingAndNonceSize() throws {
        let key = SymmetricKey(size: .bits256), payload = Data("credential test data".utf8)
        let box = try AES.GCM.seal(payload, using: key)
        var cipher = box.ciphertext + box.tag
        func sealed(_ nonce: Data) throws -> Data { try JSONSerialization.data(withJSONObject: ["ciphertext": cipher.base64EncodedString(), "nonce": nonce.base64EncodedString()]) }
        let nonce = box.nonce.withUnsafeBytes { Data($0) }
        XCTAssertEqual(try BrowserCallback.decrypt(sealed(nonce), key: key), payload)
        XCTAssertThrowsError(try BrowserCallback.decrypt(sealed(nonce), key: SymmetricKey(size: .bits256)))
        XCTAssertThrowsError(try BrowserCallback.decrypt(sealed(Data([1,2])), key: key))
        cipher[cipher.count - 1] ^= 1
        XCTAssertThrowsError(try BrowserCallback.decrypt(sealed(nonce), key: key))
    }

    func testRealLoopbackCallbackAcceptsOnlyAuthenticatedPayload() async throws {
        let callback = try BrowserCallback()
        defer { callback.close() }
        let url = try await callback.start()
        let parts = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let secret = try XCTUnwrap(parts.queryItems?.first(where: { $0.name == "secret_key" })?.value)
        var keyData = Data()
        var index = secret.startIndex
        while index < secret.endIndex {
            let end = secret.index(index, offsetBy: 2)
            keyData.append(try XCTUnwrap(UInt8(secret[index..<end], radix: 16))); index = end
        }
        let payload = Data("only authenticated data completes the callback".utf8)
        let box = try AES.GCM.seal(payload, using: SymmetricKey(data: keyData))
        let encrypted = try JSONSerialization.data(withJSONObject: ["ciphertext": (box.ciphertext + box.tag).base64EncodedString(), "nonce": box.nonce.withUnsafeBytes { Data($0) }.base64EncodedString()])
        var responseURL = parts; responseURL.queryItems = [URLQueryItem(name: "response", value: String(decoding: encrypted, as: UTF8.self))]
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        var invalidURL = parts; invalidURL.queryItems = [URLQueryItem(name: "response", value: "unauthenticated")]
        let (_, invalidHTTP) = try await session.data(from: XCTUnwrap(invalidURL.url))
        XCTAssertEqual((invalidHTTP as? HTTPURLResponse)?.statusCode, 400)
        let (_, http) = try await session.data(from: XCTUnwrap(responseURL.url))
        XCTAssertEqual((http as? HTTPURLResponse)?.statusCode, 200)
        let actual = try await callback.wait()
        XCTAssertEqual(actual, payload)
    }

    func testCancelBrowserCallbackStopsPendingWait() async throws {
        let callback = try BrowserCallback()
        _ = try await callback.start()
        let task = Task { try await callback.wait() }
        task.cancel()
        do { _ = try await task.value; XCTFail("canceled callback returned") }
        catch is CancellationError {}
        catch { XCTFail("unexpected cancellation error") }
        callback.close()
    }

    func testSignOutBlocksNewLoginUntilAtomicStoreWriteEnds() async throws {
        let store = PausedIdentityStore()
        let client = TeleportClient(proxy: try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example"))), identityStore: store)
        let signOut = Task { try await client.signOut() }
        await store.waitForWrite()
        do {
            _ = try await client.login(username: "alice", password: "test-password", otp: "123456")
            XCTFail("login started during sign-out")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidConfiguration("sign-out is active")) }
        catch { XCTFail("unexpected error while sign-out is active") }
        await store.finishWrite()
        try await signOut.value
        do { _ = try await client.identity(); XCTFail("identity remained after sign-out") }
        catch let error as TeleportError { XCTAssertEqual(error, .authenticationRequired) }
    }
}

private actor PausedIdentityStore: TeleportIdentityStore {
    private var writeStarted = false
    private var observer: CheckedContinuation<Void, Never>?
    private var writer: CheckedContinuation<Void, Never>?
    func load() -> TeleportIdentity? { nil }
    func replace(with identity: TeleportIdentity?) async {
        writeStarted = true; observer?.resume(); observer = nil
        await withCheckedContinuation { writer = $0 }
    }
    func waitForWrite() async {
        if writeStarted { return }
        await withCheckedContinuation { observer = $0 }
    }
    func finishWrite() { writer?.resume(); writer = nil }
}
