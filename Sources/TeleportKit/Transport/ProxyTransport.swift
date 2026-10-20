import Darwin
import Foundation
import CryptoKit
import TeleportCore
import NIOCore
import NIOPosix
import NIOHTTP2

/// One profile uses one cached HTTP/2 connection per current identity. Existing
/// leases retain an earlier connection across an identity replacement.
actor ProxyTransport {
    private final class Attempt: Sendable {
        let fingerprint: Data
        let task: Task<HTTP2Session, any Error>
        init(fingerprint: Data, task: Task<HTTP2Session, any Error>) {
            self.fingerprint = fingerprint; self.task = task
        }
    }
    private var active: Attempt?

    func connect(identity: TeleportIdentity, node: TeleportNode, login: String) async throws -> TeleportConnection {
        guard node.clusterName == identity.clusterName else { throw TeleportError.unsupportedPolicy(.leafCluster) }
        guard identity.allowedLogins.contains(login) else { throw TeleportError.invalidConfiguration("OS login is not permitted by the SSH certificate") }
        let session = try await session(identity: identity)
        let cancellation = ChannelCancellation()

        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let pair = try makeSocketPair()
            var ownsSSH = true
            var ownsPump = true
            defer {
                if ownsSSH { Darwin.close(pair.ssh) }
                if ownsPump { Darwin.close(pair.pump) }
            }
            // A stream must exist before the local handler can write to it. Start
            // with no reads until both handlers have been installed.
            let stream = try await session.createStream { channel in
                cancellation.install(channel)
                return channel.setOption(ChannelOptions.autoRead, value: false)
            }
            var pump: (any Channel)?
            do {
                // SocketChannel consumes this FD even if registration fails.
                ownsPump = false
                let socket = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
                    .channelOption(ChannelOptions.autoRead, value: false)
                    .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                    .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
                    .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 32_768))
                    .channelOption(ChannelOptions.writeBufferWaterMark, value: .init(low: 32_768, high: 65_536))
                    .channelInitializer { socket in socket.pipeline.addHandler(SocketPump(upstream: stream)) }
                    .withConnectedSocket(pair.pump).get()
                pump = socket
                try Task.checkCancellation()
                let ready = stream.eventLoop.makePromise(of: Void.self)
                let handler = ProxySSHHandler(target: node.id + ":0", cluster: node.clusterName,
                                              authority: identity.proxy.url.host!, socket: socket, ready: ready)
                do { try await stream.pipeline.addHandler(handler).get() }
                catch {
                    try? await stream.eventLoop.submit { handler.failBeforeStart(error) }.get()
                    throw error
                }
                try await ready.futureResult.get()
                try Task.checkCancellation()
                guard identity.isUsable() else { throw TeleportError.authenticationRequired }
                ownsSSH = false
                return TeleportConnection(node: node, login: login, identity: identity, session: session,
                                          stream: stream, pump: socket, descriptor: pair.ssh)
            } catch {
                try? await stream.close().get()
                if let pump { try? await pump.close().get() }
                // withConnectedSocket consumes the descriptor once construction
                // succeeds. Its failure path also closes the newly created channel.
                throw error
            }
        } onCancel: { cancellation.cancel() }
    }

    func unary(path: String, message: Data, identity: TeleportIdentity) async throws -> Data {
        let session = try await HTTP2Session.connect(
            host: identity.proxy.url.host!, port: identity.proxy.url.port ?? 443,
            route: .auth(clusterName: identity.clusterName), material: material(identity))
        return try await session.unary(path: path, authority: "teleport.cluster.local", message: message)
    }

    func reset() { active = nil }

    private func session(identity: TeleportIdentity) async throws -> HTTP2Session {
        let fingerprint = fingerprint(identity)
        let attempt: Attempt
        if let active, active.fingerprint == fingerprint {
            attempt = active
        } else {
            attempt = Attempt(fingerprint: fingerprint, task: Task {
                try await HTTP2Session.connect(
                    host: identity.proxy.url.host!, port: identity.proxy.url.port ?? 443,
                    route: .sshProxy, material: material(identity))
            })
            active = attempt
        }
        do {
            let session = try await SharedTaskWaiter.wait(for: attempt.task)
            if !session.channel.isActive {
                if active === attempt { active = nil }
                throw TeleportError.transport("proxy connection is closed")
            }
            return session
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            if active === attempt { active = nil }
            throw error
        }
    }

    private nonisolated func material(_ identity: TeleportIdentity) -> TLSMaterial {
        TLSMaterial(certificateDER: identity.tlsCertificateDER, privateKeyDER: identity.tlsPrivateKeyDER,
                    authorityDER: identity.tlsCACertificatesDER)
    }

    private nonisolated func fingerprint(_ identity: TeleportIdentity) -> Data {
        credentialContextHash([
            [Data(identity.proxy.url.absoluteString.utf8), Data(identity.username.utf8),
             Data(identity.clusterName.utf8), identity.tlsCertificateDER,
             Data(identity.sshCertificateOpenSSH.utf8)],
            identity.tlsCACertificatesDER,
            identity.tlsUserCACertificatesDER,
            identity.sshHostCAKeys.map { Data($0.utf8) },
            identity.sshUserCAKeys.map { Data($0.utf8) },
        ])
    }
}

/// Preserve both field and trust-group boundaries when deriving a connection key.
func credentialContextHash(_ sections: [[Data]]) -> Data {
    var hash = SHA256()
    func addCount(_ count: Int) {
        var value = UInt64(count).bigEndian
        withUnsafeBytes(of: &value) { hash.update(data: $0) }
    }
    for section in sections {
        addCount(section.count)
        for value in section {
            addCount(value.count)
            hash.update(data: value)
        }
    }
    return Data(hash.finalize())
}
