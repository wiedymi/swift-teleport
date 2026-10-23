import Foundation
import LocalAuthentication
import XCTest
@testable import TeleportKit

final class DeviceKeyAuthenticationScopeTests: XCTestCase, @unchecked Sendable {
    func testSetupScopeSharesItsContextAndLaterOperationsUseFreshContexts() async throws {
        let context = ScopeAuthenticationContext()
        let authentication = AuthenticationPrompt(reason: "Test setup", context: context)
        let driver = SecureEnclaveDeviceKeyOperations()
        let escaped = try await driver.withAuthentication(authentication) { keys in
            let scoped = try XCTUnwrap(keys as? SecureEnclaveDeviceKeyOperations)
            XCTAssertTrue(scoped.authenticationPrompt(reason: "Test registration") === authentication)
            XCTAssertTrue(scoped.authenticationPrompt(reason: "Test certificate") === authentication)
            XCTAssertEqual(context.touchIDAuthenticationAllowableReuseDuration, 0)
            XCTAssertFalse(context.wasInvalidated)
            return scoped
        }
        XCTAssertTrue(context.wasInvalidated)
        XCTAssertTrue(escaped.authenticationPrompt(reason: "Late use") === authentication)
        let first = driver.authenticationPrompt(reason: "Later login")
        let second = driver.authenticationPrompt(reason: "Another login")
        defer { first.context.invalidate(); second.context.invalidate() }
        XCTAssertFalse(first === authentication)
        XCTAssertFalse(first === second)
        XCTAssertEqual(first.context.touchIDAuthenticationAllowableReuseDuration, 0)
    }

    func testFailedSetupInvalidatesItsAuthenticationContext() async throws {
        let context = ScopeAuthenticationContext()
        let driver = SecureEnclaveDeviceKeyOperations()
        do {
            _ = try await driver.withAuthentication(AuthenticationPrompt(reason: "Test setup", context: context)) { _ -> Int in
                throw ScopeFailure.expected
            }
            XCTFail("failed setup returned a result")
        } catch ScopeFailure.expected {}
        XCTAssertTrue(context.wasInvalidated)
    }

    func testCancellationInvalidatesContextBeforeUncooperativeWorkEnds() async throws {
        let context = ScopeAuthenticationContext(), gate = ScopeOperationGate()
        let driver = SecureEnclaveDeviceKeyOperations()
        let setup = Task {
            try await driver.withAuthentication(AuthenticationPrompt(reason: "Test setup", context: context)) { _ in
                await gate.pause()
                return 1
            }
        }
        await gate.waitForEntry()
        setup.cancel()
        XCTAssertTrue(context.wasInvalidated)
        await gate.release()
        do { _ = try await setup.value; XCTFail("canceled setup returned a result") }
        catch is CancellationError {}
    }

    func testAlreadyCanceledSetupDoesNotUseTheContext() async throws {
        let context = ScopeAuthenticationContext(), driver = SecureEnclaveDeviceKeyOperations()
        let setup = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await driver.withAuthentication(AuthenticationPrompt(reason: "Test setup", context: context)) { _ in
                XCTFail("canceled setup started key work")
                return 1
            }
        }
        do { _ = try await setup.value; XCTFail("canceled setup returned a result") }
        catch is CancellationError {}
        XCTAssertTrue(context.wasInvalidated)
    }
}

private enum ScopeFailure: Error { case expected }

private final class ScopeAuthenticationContext: LAContext, @unchecked Sendable {
    private let lock = NSLock()
    private var invalidated = false
    var wasInvalidated: Bool { lock.withLock { invalidated } }

    override func invalidate() {
        lock.withLock { invalidated = true }
        super.invalidate()
    }
}

private actor ScopeOperationGate {
    private var observer: CheckedContinuation<Void, Never>?
    private var pending: CheckedContinuation<Void, Never>?

    func pause() async {
        await withCheckedContinuation { continuation in
            pending = continuation
            observer?.resume(); observer = nil
        }
    }
    func waitForEntry() async {
        if pending != nil { return }
        await withCheckedContinuation { observer = $0 }
    }
    func release() { pending?.resume(); pending = nil }
}
