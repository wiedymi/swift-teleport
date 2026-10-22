import Foundation

/// Open a login URL in a browser. Return after the browser opens.
/// SSO and browser MFA use an authenticated IPv4 loopback callback.
/// Initial device setup receives its certificates through the pending HTTPS request.
public protocol TeleportBrowserPresenter: Sendable {
    @MainActor func open(_ url: URL) async throws
}
