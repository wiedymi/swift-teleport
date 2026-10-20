import Foundation

/// Open a login URL in a browser. Return after the browser opens.
/// The package receives the final HTTP callback on an IPv4 loopback listener.
public protocol TeleportBrowserPresenter: Sendable {
    @MainActor func open(_ url: URL) async throws
}
