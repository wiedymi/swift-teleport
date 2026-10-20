import Darwin
import Foundation
import TeleportCore
import NIOCore

/// A prepared SSH path. Keep this object alive until the SSH engine has stopped.
/// The package owns the transport; SSH channels and commands belong to the app.
public final class TeleportConnection: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let node: TeleportNode
    public let login: String
    private let identity: TeleportIdentity
    private let session: HTTP2Session
    private let stream: any Channel
    private let pump: any Channel
    private let lock = NSLock()
    private enum SocketOwnership { case owned(Int32), transferred, closed }
    private var ownership: SocketOwnership

    init(node: TeleportNode, login: String, identity: TeleportIdentity,
         session: HTTP2Session, stream: any Channel, pump: any Channel, descriptor: Int32) {
        self.node = node; self.login = login; self.identity = identity
        self.session = session; self.stream = stream; self.pump = pump
        ownership = .owned(descriptor)
    }

    /// Explicit secret access for the SSH engine. Do not log these values.
    public var sshCertificateOpenSSH: String { identity.sshCertificateOpenSSH }
    public var sshPrivateKeyPEM: String { identity.sshPrivateKeyPEM }

    /// Transfer the nonblocking socket once. The caller must close it only after
    /// every SSH operation has stopped. The package never closes a transferred FD.
    public func takeSocketDescriptor() throws -> Int32 {
        guard identity.isUsable() else {
            closeOwnedSocket()
            stream.close(promise: nil)
            pump.close(promise: nil)
            throw TeleportError.authenticationRequired
        }
        lock.lock()
        defer { lock.unlock() }
        guard case .owned(let descriptor) = ownership else { throw TeleportError.transport("socket ownership was already released") }
        ownership = .transferred
        return descriptor
    }

    /// Call after key exchange and before user authentication. The SSH engine must
    /// also verify the key-exchange signature using this certificate's public key.
    public func verifyHostCertificate(_ certificate: Data, at date: Date = Date()) throws {
        guard identity.isUsable(at: date) else { throw TeleportError.authenticationRequired }
        var reader = try SSHReader(certificate)
        let type = try reader.string()
        let parsed = try TeleportSSHCertificate(openSSH: "\(type) \(certificate.base64EncodedString())")
        let principal = parsed.principals.contains(node.id) ? node.id : node.id + "." + node.clusterName
        try parsed.verify(authorities: identity.sshHostCAKeys, principal: principal, kind: .host, at: date)
    }

    /// Closing the pump wakes a transferred socket. The SSH engine then stops and
    /// closes its own descriptor. Calling close more than once is safe.
    public func close() async {
        closeOwnedSocket()
        async let upstream: Void? = try? stream.close().get()
        async let local: Void? = try? pump.close().get()
        _ = await (upstream, local)
    }

    deinit {
        closeOwnedSocket()
        stream.close(promise: nil)
        pump.close(promise: nil)
    }

    private func closeOwnedSocket() {
        lock.lock()
        let previous = ownership
        ownership = .closed
        lock.unlock()
        if case .owned(let descriptor) = previous { Darwin.close(descriptor) }
    }

    public var description: String { "TeleportConnection" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
