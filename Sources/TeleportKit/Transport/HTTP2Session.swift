import Foundation
@preconcurrency import Network
@preconcurrency import Security
import NIOCore
import NIOHTTP2
import NIOTransportServices
import NIOTLS

struct TLSMaterial: Sendable {
    let certificateDER: Data
    let privateKeyDER: Data
    let authorityDER: [Data]
}

/// A cancel action also covers cancellation before the channel is installed.
final class ChannelCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private enum State { case waiting, active(any Channel), cancelled }
    private var state: State = .waiting

    func install(_ channel: any Channel) {
        lock.lock()
        let shouldClose: Bool
        if case .cancelled = state { shouldClose = true }
        else { state = .active(channel); shouldClose = false }
        lock.unlock()
        if shouldClose { channel.close(promise: nil) }
    }

    func cancel() {
        lock.lock()
        let previous = state
        state = .cancelled
        lock.unlock()
        if case .active(let channel) = previous { channel.close(promise: nil) }
    }

}

final class HTTP2Session: @unchecked Sendable {
    let channel: any Channel
    let multiplexer: HTTP2StreamMultiplexer.SendableView

    init(channel: any Channel, multiplexer: HTTP2StreamMultiplexer.SendableView) {
        self.channel = channel
        self.multiplexer = multiplexer
    }

    deinit { channel.close(promise: nil) }

    func createStream(_ initializer: @escaping NIOChannelInitializer) async throws -> any Channel {
        let promise = channel.eventLoop.makePromise(of: (any Channel).self)
        multiplexer.createStreamChannel(promise: promise, initializer)
        return try await promise.futureResult.get()
    }

    static func connect(host: String, port: Int, route: TransportRoute,
                        material: TLSMaterial) async throws -> HTTP2Session {
        let group = NIOTSEventLoopGroup.singleton
        let cancellation = ChannelCancellation()
        try Task.checkCancellation()
        let options = try tlsOptions(serverName: "teleport.cluster.local", protocols: route.offeredProtocols(), material: material)
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let (session, ready) = try await NIOTSConnectionBootstrap(group: group)
                .connectTimeout(.seconds(20))
                .tlsOptions(options)
                .channelOption(NIOTSChannelOptions.waitForActivity, value: false)
                .channelOption(ChannelOptions.writeBufferWaterMark,
                               value: .init(low: 32_768, high: 65_536))
                .connect(host: host, port: port) { channel in
                    cancellation.install(channel)
                    let ready = channel.eventLoop.makePromise(of: Void.self)
                    let validator = ALPNValidator(ready: ready)
                    return channel.pipeline.addHandler(validator).flatMap {
                        channel.configureHTTP2Pipeline(
                            mode: .client,
                            initialLocalSettings: [
                                .init(parameter: .enablePush, value: 0),
                                .init(parameter: .maxHeaderListSize, value: 16_384),
                                .init(parameter: .initialWindowSize, value: 65_535),
                            ],
                            inboundStreamInitializer: { stream in stream.close() }
                        ).map { (HTTP2Session(channel: channel, multiplexer: $0.sendableView), ready.futureResult) }
                    }.flatMapErrorThrowing { error in
                        validator.failBeforeStart(error)
                        throw error
                    }
                }
            do {
                try await ready.get()
                try Task.checkCancellation()
                return session
            } catch {
                try? await session.channel.close().get()
                throw error
            }
        } onCancel: { cancellation.cancel() }
    }

    func unary(path: String, authority: String, message: Data) async throws -> Data {
        let cancellation = ChannelCancellation()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let result = channel.eventLoop.makePromise(of: Data.self)
            let handler = UnaryHandler(path: path, authority: authority, request: message, result: result)
            do {
                let stream = try await createStream { channel in
                    cancellation.install(channel)
                    return channel.pipeline.addHandler(handler)
                }
                defer { stream.close(promise: nil) }
                return try await result.futureResult.get()
            } catch {
                try? await channel.eventLoop.submit { handler.failBeforeStart(error) }.get()
                throw error
            }
        } onCancel: { cancellation.cancel() }
    }

    private static func tlsOptions(serverName: String, protocols: [String],
                                   material: TLSMaterial) throws -> NWProtocolTLS.Options {
        guard let certificate = SecCertificateCreateWithData(nil, material.certificateDER as CFData),
              !material.authorityDER.isEmpty else { throw TransportError.invalidResponse }
        var error: Unmanaged<CFError>?
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        guard let key = SecKeyCreateWithData(material.privateKeyDER as CFData,
                                             attributes as CFDictionary, &error),
              let identity = SecIdentityCreate(nil, certificate, key),
              let protocolIdentity = sec_identity_create(identity) else {
            throw TransportError.invalidResponse
        }
        let certificates = material.authorityDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certificates.count == material.authorityDER.count else { throw TransportError.invalidResponse }
        let options = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(options.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_local_identity(options.securityProtocolOptions, protocolIdentity)
        sec_protocol_options_set_challenge_block(options.securityProtocolOptions, { _, complete in
            complete(protocolIdentity)
        }, DispatchQueue.global(qos: .userInitiated))
        for value in protocols { sec_protocol_options_add_tls_application_protocol(options.securityProtocolOptions, value) }
        sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, serverName)
        sec_protocol_options_set_peer_authentication_required(options.securityProtocolOptions, true)
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            do {
                try verifyInternalServerTrust(trust, authorities: certificates, serverName: serverName)
                complete(true)
            } catch { complete(false) }
        }, DispatchQueue.global(qos: .userInitiated))
        return options
    }
}

final class ALPNValidator: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let ready: EventLoopPromise<Void>
    private var completed = false

    init(ready: EventLoopPromise<Void>) {
        self.ready = ready
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case .handshakeCompleted(let negotiated) = event as? TLSUserEvent {
            guard negotiated == "h2" else {
                fail(TransportError.invalidResponse, context: context)
                return
            }
            if !completed { completed = true; ready.succeed(()) }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) { fail(error, context: context) }

    func channelInactive(context: ChannelHandlerContext) {
        failBeforeStart(TransportError.closed)
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) { failBeforeStart(TransportError.closed) }

    /// A channel can close before activation, without a channelInactive event.
    func failBeforeStart(_ error: any Error) {
        if !completed { completed = true; ready.fail(error) }
    }

    private func fail(_ error: any Error, context: ChannelHandlerContext) {
        failBeforeStart(error)
        context.close(promise: nil)
    }
}
