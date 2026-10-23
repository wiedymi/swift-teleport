import CryptoKit
import Foundation
import SwiftProtobuf
import XCTest
@testable import TeleportKit

final class DeviceCredentialTests: XCTestCase, @unchecked Sendable {
    func testRegistrationRejectsWrongAccountRPAndUnsupportedAuthenticatorRequirements() throws {
        let proxy = try Self.proxy()
        let valid = try DeviceAuthRPC.registrationChallenge(DeviceTestServer.creation())
        try valid.validate(proxy: proxy, username: "alice")
        for fault in [DeviceTestServer.CreationFault.rp, .account, .algorithm, .attestation, .resident, .attachment] {
            let challenge = try DeviceAuthRPC.registrationChallenge(DeviceTestServer.creation(fault: fault))
            XCTAssertThrowsError(try challenge.validate(proxy: proxy, username: "alice"))
        }
    }

    func testPasswordlessRegistrationRequiresResidentKeyAndUserVerification() throws {
        let proxy = try Self.proxy()
        let valid = try DeviceAuthRPC.registrationChallenge(DeviceTestServer.creation(usage: .passwordless))
        try valid.validate(proxy: proxy, username: "alice", usage: .passwordless)
        for fault in [DeviceTestServer.CreationFault.rp, .account, .algorithm, .attestation, .resident, .attachment, .verification] {
            let challenge = try DeviceAuthRPC.registrationChallenge(DeviceTestServer.creation(fault: fault, usage: .passwordless))
            XCTAssertThrowsError(try challenge.validate(proxy: proxy, username: "alice", usage: .passwordless))
        }
    }

    func testRegistrationRequiresTheMatchingSigningKeyAndAcceptsSlicedPublicKeyData() async throws {
        let proxy = try Self.proxy(), keys = DeviceTestKeys()
        let material = try await keys.create(prompt: "Test approval")
        let challenge = try DeviceAuthRPC.registrationChallenge(DeviceTestServer.creation())
        let unrelatedPoint = P256.Signing.PrivateKey().publicKey.x963Representation
        let mismatched = DeviceKeyMaterial(protectedKey: material.protectedKey, publicKeyX963: unrelatedPoint)
        do {
            _ = try await DeviceWebAuthn.registration(challenge: challenge, proxy: proxy, username: "alice",
                                                       key: mismatched, keys: keys, prompt: "Test approval")
            XCTFail("registration accepted a public key that did not match the signing key")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidResponse("device authentication key")) }

        let expected = try await DeviceWebAuthn.registration(challenge: challenge, proxy: proxy, username: "alice",
                                                             key: material, keys: keys, prompt: "Test approval")
        let padded = Data([0, 0, 0]) + material.publicKeyX963
        let slicedPoint = padded.dropFirst(3)
        XCTAssertGreaterThan(slicedPoint.startIndex, 0)
        let sliced = DeviceKeyMaterial(protectedKey: material.protectedKey, publicKeyX963: slicedPoint)
        let registration = try await DeviceWebAuthn.registration(challenge: challenge, proxy: proxy, username: "alice",
                                                                 key: sliced, keys: keys, prompt: "Test approval")
        XCTAssertTrue(registration.publicKeyCOSE == expected.publicKeyCOSE)
    }

    func testNativeAssertionSignsTheRequestedChallengeWithUserVerification() async throws {
        let proxy = try Self.proxy(), keys = DeviceTestKeys()
        let material = try await keys.create(prompt: "Test approval")
        let credential = DeviceCredential(clusterName: "cluster", credentialID: Data([1, 2, 3]), protectedKey: material.protectedKey)
        let challenge = try Self.assertionChallenge(credentialID: credential.credentialID)
        let assertion = try await DeviceWebAuthn.assertion(challenge: challenge, credential: credential,
                                                          proxy: proxy, keys: keys, prompt: "Test approval")
        let clientData = try Self.urlData(assertion.response.clientDataJSON)
        let client = try XCTUnwrap(JSONSerialization.jsonObject(with: clientData) as? [String: Any])
        XCTAssertEqual(client["type"] as? String, "webauthn.get")
        XCTAssertEqual(client["origin"] as? String, proxy.url.absoluteString)
        XCTAssertTrue(try Self.urlData(XCTUnwrap(client["challenge"] as? String)) == DeviceTestServer.challenge)
        let authenticator = try Self.urlData(assertion.response.authenticatorData)
        XCTAssertTrue(authenticator.prefix(32) == Data(SHA256.hash(data: Data("proxy.example".utf8))))
        XCTAssertEqual(authenticator.count, 37)
        XCTAssertEqual(authenticator[32], 0x05)
        XCTAssertTrue(authenticator.suffix(4).allSatisfy { $0 == 0 })
        let signature = try P256.Signing.ECDSASignature(derRepresentation: Self.urlData(assertion.response.signature))
        let publicKey = try P256.Signing.PublicKey(x963Representation: material.publicKeyX963)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: authenticator + Data(SHA256.hash(data: clientData))))
        XCTAssertNil(assertion.response.userHandle)
    }

    func testRejectedAssertionCannotUseAnUnlistedCredentialOrAnotherRP() async throws {
        let proxy = try Self.proxy(), keys = DeviceTestKeys()
        let material = try await keys.create(prompt: "Test approval")
        let credential = DeviceCredential(clusterName: "cluster", credentialID: Data([1, 2, 3]), protectedKey: material.protectedKey)
        for challenge in [
            try Self.assertionChallenge(credentialID: credential.credentialID, rpID: "example"),
            try Self.assertionChallenge(credentialID: credential.credentialID, rpID: "other.example"),
            try Self.assertionChallenge(credentialID: Data([4, 5, 6])),
            try Self.assertionChallenge(credentialID: nil),
        ] {
            do {
                _ = try await DeviceWebAuthn.assertion(challenge: challenge, credential: credential, proxy: proxy,
                                                      keys: keys, prompt: "Test approval")
                XCTFail("invalid device challenge was signed")
            } catch is TeleportError {}
        }
        let count = await keys.signCount
        XCTAssertEqual(count, 0)
    }

    func testPasswordlessAssertionIncludesTheUserHandleForDiscoverableAndListedCredentials() async throws {
        let proxy = try Self.proxy(), keys = DeviceTestKeys()
        let material = try await keys.create(prompt: "Test approval")
        let credential = DeviceCredential(clusterName: "cluster", credentialID: Data([1, 2, 3]),
                                          protectedKey: material.protectedKey, userHandle: DeviceTestServer.userHandle)
        for allowed in [nil, credential.credentialID] {
            let challenge = try Self.assertionChallenge(credentialID: allowed, verification: "required")
            let assertion = try await DeviceWebAuthn.assertion(challenge: challenge, credential: credential, proxy: proxy,
                                                              keys: keys, prompt: "Test approval", usage: .passwordless)
            XCTAssertEqual(try Self.urlData(XCTUnwrap(assertion.response.userHandle)), DeviceTestServer.userHandle)
            XCTAssertEqual(try Self.urlData(assertion.rawId), credential.credentialID)
            XCTAssertEqual(try Self.urlData(assertion.response.authenticatorData)[32], 0x05)
        }
    }

    func testPasswordlessAssertionRejectsLegacyKeysWrongRPAndWeakVerificationBeforeSigning() async throws {
        let proxy = try Self.proxy(), keys = DeviceTestKeys()
        let material = try await keys.create(prompt: "Test approval")
        let credential = DeviceCredential(clusterName: "cluster", credentialID: Data([1, 2, 3]),
                                          protectedKey: material.protectedKey, userHandle: DeviceTestServer.userHandle)
        let legacy = DeviceCredential(clusterName: "cluster", credentialID: credential.credentialID, protectedKey: material.protectedKey)
        let valid = try Self.assertionChallenge(credentialID: nil, verification: "required")
        let cases = [
            (legacy, valid),
            (credential, try Self.assertionChallenge(credentialID: nil, rpID: "other.example", verification: "required")),
            (credential, try Self.assertionChallenge(credentialID: Data([9]), verification: "required")),
            (credential, try Self.assertionChallenge(credentialID: nil, verification: "preferred")),
            (credential, try Self.assertionChallenge(credentialID: nil, verification: "")),
        ]
        for (stored, challenge) in cases {
            do {
                _ = try await DeviceWebAuthn.assertion(challenge: challenge, credential: stored, proxy: proxy,
                                                      keys: keys, prompt: "Test approval", usage: .passwordless)
                XCTFail("invalid passwordless challenge was signed")
            } catch is TeleportError {}
        }
        let count = await keys.signCount
        XCTAssertEqual(count, 0)
    }

    func testManagementApprovalRejectsSSOAndRequiredButMissingChallenges() throws {
        var sso = Teleportkit_Deviceauth_MFAAuthenticateChallenge()
        sso.ssoChallenge = Teleportkit_Deviceauth_SSOChallenge()
        sso.totp = Teleportkit_Deviceauth_TOTPChallenge()
        sso.browserMfaChallenge.requestID = DeviceTestServer.browserRequestID
        XCTAssertThrowsError(try DeviceAuthRPC.managementChallenge(sso.serializedData())) { error in
            XCTAssertEqual(error as? TeleportError, .unsupportedPolicy(.sessionMFA))
        }
        for requirement in [Int32(1), -1, 3] {
            var challenge = Teleportkit_Deviceauth_MFAAuthenticateChallenge()
            challenge.mfaRequired = requirement
            XCTAssertThrowsError(try DeviceAuthRPC.managementChallenge(challenge.serializedData()))
        }
    }

    func testBiometricCredentialCannotBypassHardwareSSHKeyOrDeviceTrustPolicy() async throws {
        let proxy = try Self.proxy()
        for policy in [TeleportUnsupportedPolicy.hardwareKey, .deviceTrust] {
            let keys = DeviceTestKeys(), material = await keys.material()
            let store = DeviceTestStore(credential: .init(clusterName: "cluster", credentialID: Data([1, 2, 3]), protectedKey: material.protectedKey))
            var auth: [String: Any] = ["type": "local", "second_factor": "on", "webauthn": ["rp_id": "proxy.example"]]
            if policy == .hardwareKey { auth["private_key_policy"] = "hardware_key" }
            else { auth["device_trust"] = ["auto_enroll": true] }
            let ping = try JSONSerialization.data(withJSONObject: ["auth": auth, "proxy": ["tls_routing_enabled": true],
                                                                   "cluster_name": "cluster", "server_version": "18.11.4"])
            do {
                _ = try await DeviceCredentialAuthentication.login(proxy: proxy, username: "alice", password: "test-password", ttl: 3600,
                                                                   prompt: "Test login", store: store, keys: keys,
                                                                   request: { route, _, _ in
                    guard route == "v1/webapi/ping" else { throw DeviceTestFailure.request }
                    return ping
                })
                XCTFail("device authentication bypassed the server policy")
            } catch let error as TeleportError { XCTAssertEqual(error, .unsupportedPolicy(policy)) }
            let count = await keys.signCount
            XCTAssertEqual(count, 0)
        }
    }

    #if os(macOS)
    func testTOTPSetupRequestsCodeBeforeCreatingOrStoringAKey() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), keys = DeviceTestKeys(), store = DeviceTestStore()
        let identity = try await Self.identity(issuer: issuer, proxy: proxy)
        let server = try await DeviceTestServer(issuer: issuer, keys: keys)
        do {
            try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server, otp: "")
            XCTFail("TOTP setup accepted an empty code")
        } catch let error as TeleportError { XCTAssertEqual(error, .oneTimeCodeRequired) }
        let created = await keys.createCount, signed = await keys.signCount
        let saved = await store.load(username: "alice"), writes = await store.writeCount
        let snapshot = await server.snapshot()
        XCTAssertEqual(created, 0)
        XCTAssertEqual(signed, 0)
        XCTAssertNil(saved)
        XCTAssertEqual(writes, 0)
        XCTAssertEqual(snapshot.registrations, 0)
    }

    func testSetupWithoutRequiredApprovalAcceptsAnEmptyCode() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), keys = DeviceTestKeys(), store = DeviceTestStore()
        let identity = try await Self.identity(issuer: issuer, proxy: proxy)
        let server = try await DeviceTestServer(issuer: issuer, keys: keys, approval: .none)
        try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server, otp: "")
        let created = await keys.createCount
        let saved = await store.load(username: "alice"), writes = await store.writeCount
        let snapshot = await server.snapshot()
        XCTAssertEqual(created, 1)
        XCTAssertNotNil(saved)
        XCTAssertEqual(writes, 1)
        XCTAssertEqual(snapshot.registrations, 1)
    }

    func testRegistrationThenLoginStoresOnlyACompleteBoundIdentity() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), keys = DeviceTestKeys(), store = DeviceTestStore()
        let server = try await DeviceTestServer(issuer: issuer, keys: keys)
        let previous = try await Self.identity(issuer: issuer, proxy: proxy)
        try await Self.register(proxy: proxy, identity: previous, store: store, keys: keys, server: server)
        let saved = await store.load(username: "alice")
        let credential = try XCTUnwrap(saved)
        XCTAssertEqual(credential.clusterName, "cluster")
        let identityStore = DeviceTestIdentityStore()
        let client = TeleportClient(proxy: proxy, identityStore: identityStore)
        let identity = try await Self.login(client: client, proxy: proxy, store: store, keys: keys, server: server)
        XCTAssertEqual(identity.username, "alice")
        XCTAssertEqual(identity.clusterName, "cluster")
        XCTAssertEqual(identity.allowedLogins, ["alice"])
        XCTAssertTrue(identity.isUsable())
        XCTAssertTrue(identity.tlsPrivateKeyDER != credential.protectedKey)
        let stored = await identityStore.load()
        XCTAssertTrue(stored?.tlsCertificateDER == identity.tlsCertificateDER)
        let writes = await identityStore.writeCount
        XCTAssertEqual(writes, 1)
        let snapshot = await server.snapshot()
        XCTAssertEqual(snapshot.registrations, 1)
        XCTAssertEqual(snapshot.finishes, 1)
        XCTAssertTrue(snapshot.assertionSignatureVerified)
    }

    func testBrowserManagementApprovalUsesFreshScopeAndMapsTheAuthenticatedCallback() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), keys = DeviceTestKeys(), store = DeviceTestStore()
        let identity = try await Self.identity(issuer: issuer, proxy: proxy)
        let server = try await DeviceTestServer(issuer: issuer, keys: keys, approval: .browser)
        try await DeviceCredentialAuthentication.register(proxy: proxy, identity: identity, name: "Test browser device", otp: "",
                                                          presenter: DeviceTestBrowser(server: server), prompt: "Register test device", store: store, keys: keys,
                                                          request: { try await server.request(path: $0, query: $1, body: $2) },
                                                          rpc: { try await server.rpc(path: $0, body: $1) })
        let saved = await store.load(username: "alice")
        let snapshot = await server.snapshot()
        XCTAssertNotNil(saved)
        XCTAssertEqual(snapshot.registrations, 1)
        XCTAssertTrue(snapshot.browserApprovalMapped)
    }

    func testBrowserApprovedPasswordlessRegistrationThenLoginReturnsCompleteCertificates() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), setupKeys = DeviceTestKeys(), store = DeviceTestStore()
        let keys = DeviceTestKeys(setupKeys: setupKeys)
        let previous = try await Self.identity(issuer: issuer, proxy: proxy)
        let server = try await DeviceTestServer(issuer: issuer, keys: setupKeys, approval: .browser, usage: .passwordless)
        let identityStore = DeviceTestIdentityStore(identity: previous)
        let client = TeleportClient(proxy: proxy, identityStore: identityStore)
        let identity = try await client.setupDeviceCredential {
            try await DeviceCredentialAuthentication.registerAndLoginPasswordless(
                proxy: proxy, identity: previous, name: "Test device", presenter: DeviceTestBrowser(server: server),
                prompt: "Register test device", ttl: 3600, store: store, keys: keys,
                request: { try await server.request(path: $0, query: $1, body: $2) },
                rpc: { try await server.rpc(path: $0, body: $1) }
            )
        }
        let registered = await store.load(username: "alice")
        let credential = try XCTUnwrap(registered)
        XCTAssertEqual(credential.userHandle, DeviceTestServer.userHandle)
        XCTAssertEqual(identity.username, "alice")
        XCTAssertEqual(identity.clusterName, "cluster")
        XCTAssertEqual(identity.allowedLogins, ["alice"])
        XCTAssertTrue(identity.isUsable())
        XCTAssertTrue(identity.tlsPrivateKeyDER != credential.protectedKey)
        let stored = await identityStore.load(), writes = await identityStore.writeCount
        XCTAssertEqual(stored?.tlsCertificateDER, identity.tlsCertificateDER)
        XCTAssertEqual(writes, 1)
        let snapshot = await server.snapshot()
        XCTAssertEqual(snapshot.registrations, 1)
        XCTAssertEqual(snapshot.finishes, 1)
        XCTAssertTrue(snapshot.assertionSignatureVerified)
        XCTAssertTrue(snapshot.browserApprovalMapped)
        let setupCreates = await setupKeys.createCount, setupSigns = await setupKeys.signCount
        let initialCreates = await keys.createCount, initialSigns = await keys.signCount
        XCTAssertEqual(setupCreates, 1)
        XCTAssertEqual(setupSigns, 2)
        XCTAssertEqual(initialCreates, 0)
        XCTAssertEqual(initialSigns, 0)
        _ = try await Self.login(client: client, proxy: proxy, store: store, keys: keys, server: server, usage: .passwordless)
        let laterSigns = await keys.signCount, unchangedSetupSigns = await setupKeys.signCount
        XCTAssertEqual(laterSigns, 1)
        XCTAssertEqual(unchangedSetupSigns, 2)
    }

    func testPasswordlessRegistrationRejectsNonResidentAcknowledgmentAndExistingCredentials() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), keys = DeviceTestKeys(), identity = try await Self.identity(issuer: issuer, proxy: proxy)
        let store = DeviceTestStore()
        let server = try await DeviceTestServer(issuer: issuer, keys: keys, ackFault: .resident, usage: .passwordless)
        do {
            try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server, usage: .passwordless)
            XCTFail("a non-resident acknowledgment was accepted for passwordless login")
        } catch let error as TeleportError { XCTAssertEqual(error, .invalidResponse("registered device binding")) }
        let saved = await store.load(username: "alice")
        XCTAssertNil(saved)
        let material = await keys.material()
        let legacy = DeviceTestStore(credential: .init(clusterName: "cluster", credentialID: Data([1]), protectedKey: material.protectedKey))
        do {
            try await Self.register(proxy: proxy, identity: identity, store: legacy, keys: keys, server: server, usage: .passwordless)
            XCTFail("passwordless setup replaced an existing MFA credential")
        } catch let error as TeleportError { XCTAssertEqual(error, .deviceCredentialExists) }
        let preserved = await legacy.load(username: "alice")
        XCTAssertNil(preserved?.userHandle)
        XCTAssertEqual(preserved?.credentialID, Data([1]))
    }

    func testPasswordlessLoginRequiresAResidentCredentialAndMatchingCluster() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy()
        for failure in [DeviceTestMissing.credential, .legacy, .key, .cluster] {
            let keys = DeviceTestKeys(mode: failure == .key ? .missing : .ready)
            let material = await keys.material()
            let credential = DeviceCredential(clusterName: failure == .cluster ? "other" : "cluster",
                                              credentialID: DeviceTestServer.defaultCredentialID, protectedKey: material.protectedKey,
                                              userHandle: failure == .legacy ? nil : DeviceTestServer.userHandle)
            let store = DeviceTestStore(credential: failure == .credential ? nil : credential)
            let server = try await DeviceTestServer(issuer: issuer, keys: keys, usage: .passwordless)
            do {
                _ = try await DeviceCredentialAuthentication.loginPasswordless(proxy: proxy, username: "alice", ttl: 3600,
                                                                               prompt: "Test login", store: store, keys: keys,
                                                                               request: { try await server.request(path: $0, query: $1, body: $2) })
                XCTFail("passwordless login accepted an unusable credential")
            } catch let error as TeleportError {
                XCTAssertEqual(error, failure == .cluster ? .invalidResponse("device credential cluster") : .deviceCredentialMissing)
            }
            let snapshot = await server.snapshot()
            XCTAssertEqual(snapshot.finishes, 0)
        }
    }

    func testPasswordlessLoginRejectsDisabledPolicyBeforeSigning() async throws {
        let proxy = try Self.proxy(), keys = DeviceTestKeys(), material = await keys.material()
        let store = DeviceTestStore(credential: .init(clusterName: "cluster", credentialID: Data([1]),
                                                     protectedKey: material.protectedKey, userHandle: DeviceTestServer.userHandle))
        for policy in [TeleportUnsupportedPolicy.passwordless, .hardwareKey, .deviceTrust] {
            var auth: [String: Any] = ["type": "local", "second_factor": "on", "allow_passwordless": policy != .passwordless,
                                       "webauthn": ["rp_id": "proxy.example"]]
            if policy == .hardwareKey { auth["private_key_policy"] = "hardware_key" }
            if policy == .deviceTrust { auth["device_trust"] = ["auto_enroll": true] }
            let ping = try JSONSerialization.data(withJSONObject: ["auth": auth, "proxy": ["tls_routing_enabled": true],
                                                                   "cluster_name": "cluster", "server_version": "18.11.4"])
            do {
                _ = try await DeviceCredentialAuthentication.loginPasswordless(proxy: proxy, username: "alice", ttl: 3600,
                                                                               prompt: "Test login", store: store, keys: keys,
                                                                               request: { path, _, _ in
                    guard path == "v1/webapi/ping" else { throw DeviceTestFailure.request }
                    return ping
                })
                XCTFail("passwordless login bypassed a disabled server policy")
            } catch let error as TeleportError { XCTAssertEqual(error, .unsupportedPolicy(policy)) }
        }
        let count = await keys.signCount
        XCTAssertEqual(count, 0)
    }

    func testCanceledPasswordlessApprovalPreservesTheExistingIdentity() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), keys = DeviceTestKeys(mode: .wait), material = await keys.material()
        let previous = try await Self.identity(issuer: issuer, proxy: proxy)
        let store = DeviceTestStore(credential: .init(clusterName: "cluster", credentialID: DeviceTestServer.defaultCredentialID,
                                                     protectedKey: material.protectedKey, userHandle: DeviceTestServer.userHandle))
        let server = try await DeviceTestServer(issuer: issuer, keys: keys, usage: .passwordless)
        let identityStore = DeviceTestIdentityStore(identity: previous), client = TeleportClient(proxy: proxy, identityStore: identityStore)
        let login = Task { try await Self.login(client: client, proxy: proxy, store: store, keys: keys, server: server, usage: .passwordless) }
        await keys.waitForSign()
        login.cancel()
        do { _ = try await login.value; XCTFail("canceled passwordless approval issued certificates") }
        catch is CancellationError {}
        let stored = await identityStore.load(), writes = await identityStore.writeCount
        let snapshot = await server.snapshot()
        XCTAssertEqual(stored?.tlsCertificateDER, previous.tlsCertificateDER)
        XCTAssertEqual(writes, 0)
        XCTAssertEqual(snapshot.finishes, 0)
    }

    func testInvalidRegistrationAcknowledgmentDoesNotPersistTheCredential() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), identity = try await Self.identity(issuer: issuer, proxy: proxy)
        for fault in [DeviceTestServer.AckFault.id, .rp, .key, .deviceType] {
            let keys = DeviceTestKeys(), store = DeviceTestStore()
            let server = try await DeviceTestServer(issuer: issuer, keys: keys, ackFault: fault)
            do {
                try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server)
                XCTFail("registration with an invalid acknowledgment succeeded")
            } catch is TeleportError {}
            let saved = await store.load(username: "alice")
            let writes = await store.writeCount
            XCTAssertNil(saved)
            XCTAssertEqual(writes, 0)
        }
    }

    func testUnavailableBiometricsAndFailedSignatureDoNotRegisterOrPersistAKey() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), identity = try await Self.identity(issuer: issuer, proxy: proxy)
        for mode in [DeviceTestKeys.Mode.unavailable, .deny] {
            let keys = DeviceTestKeys(mode: mode), store = DeviceTestStore()
            let server = try await DeviceTestServer(issuer: issuer, keys: keys)
            do {
                try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server)
                XCTFail("registration bypassed a failed key operation")
            } catch let error as TeleportError {
                XCTAssertTrue(error == .secureEnclaveUnavailable || error == .biometricsUnavailable)
            }
            let saved = await store.load(username: "alice")
            let snapshot = await server.snapshot()
            XCTAssertNil(saved)
            XCTAssertEqual(snapshot.registrations, 0)
        }
    }

    func testCancelDuringRegistrationApprovalLeavesNoLocalCredential() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), identity = try await Self.identity(issuer: issuer, proxy: proxy)
        let keys = DeviceTestKeys(mode: .wait), store = DeviceTestStore()
        let server = try await DeviceTestServer(issuer: issuer, keys: keys)
        let task = Task { try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server) }
        await keys.waitForSign()
        task.cancel()
        do { try await task.value; XCTFail("canceled registration succeeded") }
        catch is CancellationError {}
        let saved = await store.load(username: "alice")
        let snapshot = await server.snapshot()
        XCTAssertNil(saved)
        XCTAssertEqual(snapshot.registrations, 0)
    }

    func testCredentialStorageFailureAfterServerRegistrationIsReported() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), identity = try await Self.identity(issuer: issuer, proxy: proxy)
        let keys = DeviceTestKeys(), store = DeviceTestStore(failWrites: true)
        let server = try await DeviceTestServer(issuer: issuer, keys: keys)
        do {
            try await Self.register(proxy: proxy, identity: identity, store: store, keys: keys, server: server)
            XCTFail("failed local storage was accepted")
        } catch let error as TeleportError { XCTAssertEqual(error, .deviceCredentialStorage) }
        let saved = await store.load(username: "alice")
        let snapshot = await server.snapshot()
        XCTAssertNil(saved)
        XCTAssertEqual(snapshot.registrations, 1)
    }

    func testMissingCredentialMissingKeyAndChangedClusterNeverRequestCertificates() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy()
        for failure in [DeviceTestMissing.credential, .key, .cluster] {
            let keys = DeviceTestKeys(mode: failure == .key ? .missing : .ready)
            let material = await keys.material()
            let record = DeviceCredential(clusterName: failure == .cluster ? "other" : "cluster",
                                          credentialID: DeviceTestServer.defaultCredentialID, protectedKey: material.protectedKey)
            let store = DeviceTestStore(credential: failure == .credential ? nil : record)
            let server = try await DeviceTestServer(issuer: issuer, keys: keys)
            do {
                _ = try await DeviceCredentialAuthentication.login(proxy: proxy, username: "alice", password: "test-password",
                                                                   ttl: 3600, prompt: "Test login", store: store, keys: keys,
                                                                   request: { try await server.request(path: $0, query: $1, body: $2) })
                XCTFail("unusable local device credential was accepted")
            } catch is TeleportError {}
            let snapshot = await server.snapshot()
            XCTAssertEqual(snapshot.finishes, 0)
        }
    }

    func testWrongCertificateBindingsCannotReplaceAnExistingIdentity() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), previous = try await Self.identity(issuer: issuer, proxy: proxy)
        for (usage, fault) in [DeviceCredentialUsage.mfa, .passwordless].flatMap({ usage in
            [BrowserMFACertificateIssuer.Fault.account, .cluster, .sshKey, .tlsKey].map { (usage, $0) }
        }) {
            let keys = DeviceTestKeys(), material = await keys.material()
            let store = DeviceTestStore(credential: .init(clusterName: "cluster", credentialID: DeviceTestServer.defaultCredentialID,
                                                         protectedKey: material.protectedKey,
                                                         userHandle: usage == .passwordless ? DeviceTestServer.userHandle : nil))
            let server = try await DeviceTestServer(issuer: issuer, keys: keys, certificateFault: fault, usage: usage)
            let identityStore = DeviceTestIdentityStore(identity: previous)
            let client = TeleportClient(proxy: proxy, identityStore: identityStore)
            do {
                _ = try await Self.login(client: client, proxy: proxy, store: store, keys: keys, server: server, usage: usage)
                XCTFail("identity with wrong certificate binding was stored")
            } catch is TeleportError {}
            let preserved = await identityStore.load()
            let writes = await identityStore.writeCount
            XCTAssertTrue(preserved?.tlsCertificateDER == previous.tlsCertificateDER)
            XCTAssertEqual(writes, 0)
        }
    }

    func testFailedIdentityWritePreservesPreviousIdentityAndAllowsRetry() async throws {
        let issuer = try BrowserMFACertificateIssuer()
        defer { issuer.remove() }
        let proxy = try Self.proxy(), previous = try await Self.identity(issuer: issuer, proxy: proxy)
        let keys = DeviceTestKeys(), material = await keys.material()
        let store = DeviceTestStore(credential: .init(clusterName: "cluster", credentialID: DeviceTestServer.defaultCredentialID,
                                                     protectedKey: material.protectedKey))
        let server = try await DeviceTestServer(issuer: issuer, keys: keys)
        let identityStore = DeviceTestIdentityStore(identity: previous, failWrites: true)
        let client = TeleportClient(proxy: proxy, identityStore: identityStore)
        do {
            _ = try await Self.login(client: client, proxy: proxy, store: store, keys: keys, server: server)
            XCTFail("failed identity write was accepted")
        } catch DeviceTestFailure.identityWrite {}
        let preserved = await identityStore.load()
        XCTAssertTrue(preserved?.tlsCertificateDER == previous.tlsCertificateDER)
        await identityStore.setFailWrites(false)
        let retried = try await Self.login(client: client, proxy: proxy, store: store, keys: keys, server: server)
        let saved = await identityStore.load()
        let writes = await identityStore.writeCount
        XCTAssertTrue(saved?.tlsCertificateDER == retried.tlsCertificateDER)
        XCTAssertEqual(writes, 1)
    }

    private static func identity(issuer: BrowserMFACertificateIssuer, proxy: TeleportProxy) async throws -> TeleportIdentity {
        let key = try CredentialKey()
        let request = LoginFinish(user: "alice", password: "test-password", totp_code: "123456",
                                  ssh_pub_key: Data(key.sshPublicKey.utf8), tls_pub_key: Data(key.tlsPublicKeyPEM.utf8), ttl: 3_600_000_000_000)
        let response = try JSONDecoder().decode(LoginResponse.self, from: issuer.response(to: JSONEncoder().encode(request)))
        let exports = try issuer.authorityExports()
        let trust = try await UserAuthorityTrust.load(proxy: proxy, request: { _, query, _ in
            guard let type = query.first(where: { $0.name == "type" })?.value, let data = exports[type] else { throw DeviceTestFailure.request }
            return data
        })
        return try response.identity(proxy: proxy, username: "alice", cluster: "cluster", key: key, userTrust: trust, ttl: 3600)
    }
    private static func register(proxy: TeleportProxy, identity: TeleportIdentity, store: DeviceTestStore,
                                 keys: DeviceTestKeys, server: DeviceTestServer, otp: String = "123456",
                                 usage: DeviceCredentialUsage = .mfa) async throws {
        try await DeviceCredentialAuthentication.register(proxy: proxy, identity: identity, name: "Test device", otp: otp,
                                                          presenter: nil, prompt: "Register test device", store: store, keys: keys, usage: usage,
                                                          request: { try await server.request(path: $0, query: $1, body: $2) },
                                                          rpc: { try await server.rpc(path: $0, body: $1) })
    }
    private static func login(client: TeleportClient, proxy: TeleportProxy, store: DeviceTestStore,
                              keys: DeviceTestKeys, server: DeviceTestServer, usage: DeviceCredentialUsage = .mfa) async throws -> TeleportIdentity {
        try await client.sharedLogin(method: .deviceCredential("alice")) {
            if usage == .passwordless {
                return try await DeviceCredentialAuthentication.loginPasswordless(proxy: proxy, username: "alice", ttl: 3600,
                                                                                  prompt: "Authenticate test device", store: store, keys: keys,
                                                                                  request: { try await server.request(path: $0, query: $1, body: $2) })
            }
            return try await DeviceCredentialAuthentication.login(proxy: proxy, username: "alice", password: "test-password", ttl: 3600,
                                                           prompt: "Authenticate test device", store: store, keys: keys,
                                                           request: { try await server.request(path: $0, query: $1, body: $2) })
        }
    }
    #endif

    private static func proxy() throws -> TeleportProxy { try TeleportProxy(url: XCTUnwrap(URL(string: "https://proxy.example"))) }
    private static func assertionChallenge(credentialID: Data?, rpID: String = "proxy.example",
                                           verification: String = "discouraged") throws -> DeviceWebAuthn.AssertionChallenge {
        let options: [String: Any] = ["challenge": DeviceTestServer.challenge.base64EncodedString(), "rpId": rpID,
                                      "allowCredentials": credentialID.map { [["type": "public-key", "id": $0.base64EncodedString()]] } ?? [],
                                      "userVerification": verification]
        return try JSONDecoder().decode(DeviceWebAuthn.AssertionChallenge.self, from: JSONSerialization.data(withJSONObject: ["publicKey": options]))
    }
    private static func urlData(_ string: String) throws -> Data {
        var value = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.utf8.count % 4) % 4)
        return try XCTUnwrap(Data(base64Encoded: value))
    }
}

private enum DeviceTestFailure: Error { case request, identityWrite }
private enum DeviceTestMissing: Equatable { case credential, legacy, key, cluster }

private actor DeviceTestKeys: DeviceKeyOperations {
    enum Mode: Equatable, Sendable { case ready, unavailable, deny, wait, missing }
    private let key = P256.Signing.PrivateKey()
    private let mode: Mode
    private let setupKeys: DeviceTestKeys?
    private var signWaiters: [CheckedContinuation<Void, Never>] = []
    private(set) var createCount = 0
    private(set) var signCount = 0
    init(mode: Mode = .ready, setupKeys: DeviceTestKeys? = nil) { self.mode = mode; self.setupKeys = setupKeys }
    func withAuthentication<Result: Sendable>(
        prompt: String, operation: @Sendable (any DeviceKeyOperations) async throws -> Result
    ) async throws -> Result {
        try await operation(setupKeys ?? self)
    }
    func material() -> DeviceKeyMaterial { .init(protectedKey: key.rawRepresentation, publicKeyX963: key.publicKey.x963Representation) }
    func create(prompt: String) throws -> DeviceKeyMaterial {
        createCount += 1
        if mode == .unavailable { throw TeleportError.secureEnclaveUnavailable }
        return material()
    }
    func sign(_ data: Data, protectedKey: Data, prompt: String) async throws -> Data {
        signCount += 1
        let waiters = signWaiters; signWaiters.removeAll()
        waiters.forEach { $0.resume() }
        if mode == .deny { throw TeleportError.biometricsUnavailable }
        guard mode != .missing, let signingKey = try? P256.Signing.PrivateKey(rawRepresentation: protectedKey) else {
            throw TeleportError.deviceCredentialMissing
        }
        if mode == .wait { try await Task.sleep(for: .seconds(10)) }
        return try signingKey.signature(for: data).derRepresentation
    }
    func waitForSign() async {
        if signCount != 0 { return }
        await withCheckedContinuation { signWaiters.append($0) }
    }
}

private actor DeviceTestStore: DeviceCredentialStorage {
    private var credentials: [String: DeviceCredential] = [:]
    private let failWrites: Bool
    private(set) var writeCount = 0
    init(credential: DeviceCredential? = nil, failWrites: Bool = false) {
        self.failWrites = failWrites
        if let credential { credentials["alice"] = credential }
    }
    func load(username: String) -> DeviceCredential? { credentials[username] }
    func add(_ credential: DeviceCredential, username: String) throws {
        if failWrites { throw TeleportError.deviceCredentialStorage }
        guard credentials[username] == nil else { throw TeleportError.deviceCredentialExists }
        credentials[username] = credential; writeCount += 1
    }
    func delete(username: String) { credentials[username] = nil }
}

private actor DeviceTestIdentityStore: TeleportIdentityStore {
    private var identity: TeleportIdentity?
    private var failWrites: Bool
    private(set) var writeCount = 0
    init(identity: TeleportIdentity? = nil, failWrites: Bool = false) { self.identity = identity; self.failWrites = failWrites }
    func load() -> TeleportIdentity? { identity }
    func replace(with identity: TeleportIdentity?) throws {
        if failWrites { throw DeviceTestFailure.identityWrite }
        self.identity = identity; writeCount += 1
    }
    func setFailWrites(_ value: Bool) { failWrites = value }
}

private actor DeviceTestServer {
    enum CreationFault: Equatable, Sendable { case none, rp, account, algorithm, attestation, resident, attachment, verification }
    enum AckFault: Equatable, Sendable { case none, id, rp, key, deviceType, resident }
    enum Approval: Equatable, Sendable { case none, totp, browser }
    struct Snapshot: Sendable {
        let registrations: Int
        let finishes: Int
        let assertionSignatureVerified: Bool
        let browserApprovalMapped: Bool
    }
    static let challenge = Data([0xfb, 0xff, 0x01, 0x02, 0x03, 0x04])
    static let defaultCredentialID = Data([1, 2, 3])
    static let userHandle = Data("opaque-user-handle".utf8)
    static let browserRequestID = "27cdb56a-a651-4e8e-b606-228897091c5f"
    private var credentialID = DeviceTestServer.defaultCredentialID
    private var registrations = 0, finishes = 0
    private var assertionSignatureVerified = false
    private var browserApprovalMapped = false
    #if os(macOS)
    private let issuer: BrowserMFACertificateIssuer
    private let exports: [String: Data]
    private let publicKey: P256.Signing.PublicKey
    private let ackFault: AckFault
    private let certificateFault: BrowserMFACertificateIssuer.Fault
    private let approval: Approval
    private let usage: DeviceCredentialUsage
    private var callbackURL: URL?
    init(issuer: BrowserMFACertificateIssuer, keys: DeviceTestKeys, ackFault: AckFault = .none,
         certificateFault: BrowserMFACertificateIssuer.Fault = .none, approval: Approval = .totp,
         usage: DeviceCredentialUsage = .mfa) async throws {
        self.issuer = issuer; exports = try issuer.authorityExports()
        let material = await keys.material()
        publicKey = try P256.Signing.PublicKey(x963Representation: material.publicKeyX963)
        self.ackFault = ackFault; self.certificateFault = certificateFault
        self.approval = approval
        self.usage = usage
    }
    func request(path: String, query: [URLQueryItem], body: Data?) throws -> Data {
        switch path {
        case "v1/webapi/ping":
            return Data(#"{"auth":{"type":"local","second_factor":"on","allow_passwordless":true,"webauthn":{"rp_id":"proxy.example"}},"proxy":{"tls_routing_enabled":true},"cluster_name":"cluster","server_version":"18.11.4"}"#.utf8)
        case "v1/webapi/mfa/login/begin":
            guard let body, let value = try JSONSerialization.jsonObject(with: body) as? [String: Any] else { throw DeviceTestFailure.request }
            switch usage {
            case .mfa:
                guard value["user"] as? String == "alice", value["pass"] as? String == "test-password",
                      value["passwordless"] == nil else { throw DeviceTestFailure.request }
            case .passwordless:
                guard value["passwordless"] as? Bool == true, value.count == 1 else { throw DeviceTestFailure.request }
            }
            return try JSONSerialization.data(withJSONObject: ["webauthn_challenge": ["publicKey": [
                "challenge": Self.challenge.base64EncodedString(), "rpId": "proxy.example",
                "allowCredentials": usage == .passwordless ? [] : [["type": "public-key", "id": credentialID.base64EncodedString()]],
                "userVerification": usage == .passwordless ? "required" : "discouraged",
            ]]])
        case "v1/webapi/mfa/login/finish":
            guard let body, let value = try JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let object = value["webauthn_challenge_response"] else { throw DeviceTestFailure.request }
            let assertion = try JSONDecoder().decode(BrowserMFAAssertion.self, from: JSONSerialization.data(withJSONObject: object))
            try assertion.validate()
            switch usage {
            case .mfa:
                guard value["user"] as? String == "alice", value["password"] as? String == "test-password",
                      assertion.response.userHandle == nil else { throw DeviceTestFailure.request }
            case .passwordless:
                guard value["user"] as? String == "", value["password"] as? String == "", value["totp_code"] as? String == "",
                      try urlData(XCTUnwrap(assertion.response.userHandle)) == Self.userHandle else { throw DeviceTestFailure.request }
            }
            let clientData = try urlData(assertion.response.clientDataJSON)
            let client = try XCTUnwrap(JSONSerialization.jsonObject(with: clientData) as? [String: Any])
            let auth = try urlData(assertion.response.authenticatorData)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: urlData(assertion.response.signature))
            guard try urlData(assertion.rawId) == credentialID, auth.count == 37, auth[32] == 0x05,
                  auth.prefix(32) == Data(SHA256.hash(data: Data("proxy.example".utf8))),
                  client["type"] as? String == "webauthn.get", client["origin"] as? String == "https://proxy.example",
                  try urlData(XCTUnwrap(client["challenge"] as? String)) == Self.challenge,
                  publicKey.isValidSignature(signature, for: auth + Data(SHA256.hash(data: clientData))) else { throw DeviceTestFailure.request }
            assertionSignatureVerified = true; finishes += 1
            return try issuer.response(to: body, fault: certificateFault)
        case "v1/webapi/auth/export":
            guard let type = query.first(where: { $0.name == "type" })?.value, let value = exports[type] else { throw DeviceTestFailure.request }
            return value
        default: throw DeviceTestFailure.request
        }
    }
    func rpc(path: String, body: Data) throws -> Data {
        switch path {
        case DeviceAuthRPC.authenticatePath:
            let request = try Teleportkit_Deviceauth_CreateAuthenticateChallengeRequest(serializedBytes: body)
            guard request.hasContextUser, request.challengeExtensions.scope == 4, request.challengeExtensions.allowReuse == 2 else { throw DeviceTestFailure.request }
            var response = Teleportkit_Deviceauth_MFAAuthenticateChallenge()
            switch approval {
            case .browser:
                guard let callbackURL = URL(string: request.browserMfaTshRedirectURL), callbackURL.scheme == "http",
                      callbackURL.host == "127.0.0.1", callbackURL.path == "/callback" else { throw DeviceTestFailure.request }
                self.callbackURL = callbackURL
                response.browserMfaChallenge.requestID = Self.browserRequestID
            case .totp:
                response.totp = Teleportkit_Deviceauth_TOTPChallenge()
            case .none:
                response.mfaRequired = 2 // NO
            }
            return try response.serializedData()
        case DeviceAuthRPC.registrationPath:
            let request = try Teleportkit_Deviceauth_CreateRegisterChallengeRequest(serializedBytes: body)
            guard request.deviceType == 3, request.deviceUsage == usage.rawValue else { throw DeviceTestFailure.request }
            switch approval {
            case .browser:
                guard case .browser(let response)? = request.existingMfaResponse.response,
                      response.requestID == Self.browserRequestID, response.webauthnResponse.type == "public-key",
                      response.webauthnResponse.rawID == Data([1, 2, 3]),
                      response.webauthnResponse.response.clientDataJson == Data("{}".utf8),
                      response.webauthnResponse.response.authenticatorData == Data([1, 2, 3]),
                      response.webauthnResponse.response.signature == Data([4, 5, 6]) else { throw DeviceTestFailure.request }
                browserApprovalMapped = true
            case .totp:
                guard request.existingMfaResponse.totp.code == "123456" else { throw DeviceTestFailure.request }
            case .none:
                guard !request.hasExistingMfaResponse else { throw DeviceTestFailure.request }
            }
            return try Self.creation(usage: usage)
        case DeviceAuthRPC.addPath:
            let request = try Teleportkit_Deviceauth_AddMFADeviceSyncRequest(serializedBytes: body)
            let creation = request.newMfaResponse.webauthn
            guard request.deviceUsage == usage.rawValue, creation.extensions.credProps.rk == (usage == .passwordless) else {
                throw DeviceTestFailure.request
            }
            var cbor = DeviceTestCBOR(bytes: Array(creation.response.attestationObject))
            let auth = try cbor.registrationAuthData()
            guard creation.type == "public-key", auth.count >= 55,
                  auth.prefix(32) == Data(SHA256.hash(data: Data("proxy.example".utf8))), auth[32] == 0x45,
                  auth[33..<53].allSatisfy({ $0 == 0 }) else { throw DeviceTestFailure.request }
            let length = Int(auth[53]) * 256 + Int(auth[54])
            guard length > 0, length <= auth.count - 55 else { throw DeviceTestFailure.request }
            credentialID = Data(auth[55..<(55 + length)])
            guard creation.rawID == credentialID else { throw DeviceTestFailure.request }
            let cose = Data(auth.dropFirst(55 + length))
            var response = Teleportkit_Deviceauth_AddMFADeviceSyncResponse()
            var device = Teleportkit_Deviceauth_WebauthnDevice()
            device.credentialID = ackFault == .id ? Data([9]) : credentialID
            device.credentialRpID = ackFault == .rp ? "other.example" : "proxy.example"
            device.publicKeyCbor = ackFault == .key ? Data([0]) : cose
            device.residentKey = usage == .passwordless && ackFault != .resident
            response.device.webauthn = device
            if ackFault == .deviceType { response.device.totp = Teleportkit_Deviceauth_UnsupportedDevice() }
            registrations += 1
            return try response.serializedData()
        default: throw DeviceTestFailure.request
        }
    }
    func openBrowser(_ url: URL) async throws {
        guard url.absoluteString == "https://proxy.example/web/mfa/browser/" + Self.browserRequestID,
              let callbackURL, var callback = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let secret = callback.queryItems?.first(where: { $0.name == "secret_key" })?.value, secret.utf8.count == 64 else {
            throw DeviceTestFailure.request
        }
        var keyBytes = Data(), index = secret.startIndex
        while index < secret.endIndex {
            let end = secret.index(index, offsetBy: 2)
            guard let byte = UInt8(secret[index..<end], radix: 16) else { throw DeviceTestFailure.request }
            keyBytes.append(byte); index = end
        }
        let payload = Data(#"{"browser_mfa_webauthn_response":{"id":"AQID","type":"public-key","rawId":"AQID","response":{"clientDataJSON":"e30","authenticatorData":"AQID","signature":"BAUG"}}}"#.utf8)
        let box = try AES.GCM.seal(payload, using: SymmetricKey(data: keyBytes))
        let encrypted = try JSONSerialization.data(withJSONObject: ["ciphertext": (box.ciphertext + box.tag).base64EncodedString(),
                                                                  "nonce": box.nonce.withUnsafeBytes { Data($0) }.base64EncodedString()])
        callback.queryItems = [URLQueryItem(name: "response", value: String(decoding: encrypted, as: UTF8.self))]
        guard let callbackURL = callback.url else { throw DeviceTestFailure.request }
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let (_, response) = try await session.data(from: callbackURL)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw DeviceTestFailure.request }
    }
    #endif
    func snapshot() -> Snapshot {
        .init(registrations: registrations, finishes: finishes,
              assertionSignatureVerified: assertionSignatureVerified, browserApprovalMapped: browserApprovalMapped)
    }
    nonisolated static func creation(fault: CreationFault = .none, usage: DeviceCredentialUsage = .mfa) throws -> Data {
        var response = Teleportkit_Deviceauth_MFARegisterChallenge()
        response.webauthn.publicKey.challenge = challenge
        response.webauthn.publicKey.rp.id = fault == .rp ? "example" : "proxy.example"
        response.webauthn.publicKey.user.id = userHandle
        response.webauthn.publicKey.user.name = fault == .account ? "other" : "alice"
        var parameter = Teleportkit_Deviceauth_CredentialParameter()
        parameter.type = "public-key"; parameter.alg = fault == .algorithm ? -257 : -7
        response.webauthn.publicKey.credentialParameters = [parameter]
        response.webauthn.publicKey.attestation = fault == .attestation ? "direct" : "none"
        response.webauthn.publicKey.authenticatorSelection.requireResidentKey = (usage == .passwordless) != (fault == .resident)
        response.webauthn.publicKey.authenticatorSelection.userVerification = usage == .passwordless && fault != .verification ? "required" : "discouraged"
        response.webauthn.publicKey.authenticatorSelection.authenticatorAttachment = fault == .attachment ? "cross-platform" : "platform"
        return try response.serializedData()
    }
    private func urlData(_ string: String) throws -> Data {
        var value = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.utf8.count % 4) % 4)
        guard let data = Data(base64Encoded: value) else { throw DeviceTestFailure.request }
        return data
    }
}

#if os(macOS)
private struct DeviceTestBrowser: TeleportBrowserPresenter {
    let server: DeviceTestServer
    @MainActor func open(_ url: URL) async throws { try await server.openBrowser(url) }
}
#endif

/// Reads only the standard none-attestation map used by this test server.
private struct DeviceTestCBOR {
    let bytes: [UInt8]
    private var offset = 0
    init(bytes: [UInt8]) { self.bytes = bytes }
    mutating func registrationAuthData() throws -> Data {
        guard try length(major: 5) == 3 else { throw DeviceTestFailure.request }
        var auth: Data?
        for _ in 0..<3 {
            let key = try text()
            switch key {
            case "fmt": guard try text() == "none" else { throw DeviceTestFailure.request }
            case "attStmt": guard try length(major: 5) == 0 else { throw DeviceTestFailure.request }
            case "authData":
                let count = try length(major: 2)
                auth = try read(count: count)
            default: throw DeviceTestFailure.request
            }
        }
        guard offset == bytes.count, let auth else { throw DeviceTestFailure.request }
        return auth
    }
    private mutating func text() throws -> String {
        let count = try length(major: 3)
        guard let result = String(data: try read(count: count), encoding: .utf8) else { throw DeviceTestFailure.request }
        return result
    }
    private mutating func length(major: UInt8) throws -> Int {
        let first = try read(count: 1)[0]
        guard first >> 5 == major else { throw DeviceTestFailure.request }
        let value = first & 31
        if value < 24 { return Int(value) }
        if value == 24 { return Int(try read(count: 1)[0]) }
        throw DeviceTestFailure.request
    }
    private mutating func read(count: Int) throws -> Data {
        guard count >= 0, count <= bytes.count - offset else { throw DeviceTestFailure.request }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }
}
