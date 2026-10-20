import Darwin
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOHTTP2
import NIOHPACK
import SwiftProtobuf
import TeleportCore

enum PumpEvent: Sendable { case upstreamWritable }

/// All mutable state belongs to the socket's NIO event loop.
final class SocketPump: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let upstream: any Channel
    private var writing = false
    private var inputClosed = false

    init(upstream: any Channel) { self.upstream = upstream }

    func channelActive(context: ChannelHandlerContext) { readIfReady(context) }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let bytes = unwrapInboundIn(data)
        guard !writing, !inputClosed, bytes.readableBytes <= 32_768 else {
            context.close(promise: nil)
            upstream.close(promise: nil)
            return
        }
        writing = true
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        var request = Teleport_Transport_V1_ProxySSHRequest()
        request.ssh.payload = Data(bytes.readableBytesView)
        do {
            let data = try request.serializedData()
            let frame = try grpcMessage(data, allocator: upstream.allocator)
            upstream.writeAndFlush(HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(frame))))
                .hop(to: context.eventLoop).whenComplete { [self] result in
                    let context = bound.value
                    writing = false
                    switch result {
                    case .success: readIfReady(context)
                    case .failure: context.close(promise: nil)
                    }
                }
        } catch {
            context.close(promise: nil)
            upstream.close(promise: nil)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is PumpEvent { readIfReady(context); return }
        if case .inputClosed = event as? ChannelEvent {
            inputClosed = true
            // SSH has finished sending. The other direction can still carry its final bytes.
            upstream.writeAndFlush(HTTP2Frame.FramePayload.data(.init(
                data: .byteBuffer(upstream.allocator.buffer(capacity: 0)), endStream: true)), promise: nil)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        upstream.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) {
        upstream.close(promise: nil)
        context.close(promise: nil)
    }

    private func readIfReady(_ context: ChannelHandlerContext) {
        if !writing && !inputClosed && upstream.isWritable && context.channel.isActive { context.read() }
    }
}

/// Mutable state is confined to the HTTP/2 stream's event loop.
final class ProxySSHHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload
    private let target: String
    private let cluster: String
    private let authority: String
    private let ready: EventLoopPromise<Void>
    private let socket: any Channel
    private var status = GRPCResponseState()
    private var decoder = GRPCDecoder(maximumMessageBytes: 262_144)
    private enum Phase { case idle, waitingForDetails, streaming, finished }
    private var phase: Phase = .idle
    private var pendingBytes = 0
    private var timeout: Scheduled<Void>?

    init(target: String, cluster: String, authority: String, socket: any Channel,
         ready: EventLoopPromise<Void>) {
        self.target = target; self.cluster = cluster; self.authority = authority
        self.socket = socket; self.ready = ready
    }

    func handlerAdded(context: ChannelHandlerContext) {
        guard context.channel.isActive else { fail(TransportError.closed, context: context); return }
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        timeout = context.eventLoop.scheduleTask(in: .seconds(30)) { [self] in
            fail(TransportError.deadlineExceeded, context: bound.value)
        }
        if context.channel.isActive { start(context: context) }
    }

    func channelActive(context: ChannelHandlerContext) { start(context: context) }

    private func start(context: ChannelHandlerContext) {
        guard phase == .idle else { return }
        phase = .waitingForDetails
        do {
            let headers = HPACKHeaders([
                (":method", "POST"), (":scheme", "https"),
                (":path", "/teleport.transport.v1.TransportService/ProxySSH"),
                (":authority", authority), ("content-type", "application/grpc"), ("te", "trailers"),
            ])
            context.write(wrapOutboundOut(.headers(.init(headers: headers))), promise: nil)
            var request = Teleport_Transport_V1_ProxySSHRequest()
            request.dialTarget.hostPort = target
            request.dialTarget.cluster = cluster
            let data = try grpcMessage(request.serializedData(), allocator: context.channel.allocator)
            context.writeAndFlush(wrapOutboundOut(.data(.init(data: .byteBuffer(data)))), promise: nil)
            context.read()
        } catch { fail(error, context: context) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard phase != .finished else { return }
        do {
            switch unwrapInboundIn(data) {
            case .headers(let headers):
                try status.headers(headers.headers, endStream: headers.endStream)
                if headers.endStream {
                    try decoder.finish()
                    guard phase == .streaming else { throw TransportError.invalidResponse }
                    phase = .finished
                    finishOutputIfDrained()
                }
            case .data(let part):
                try status.data(endStream: part.endStream)
                guard case .byteBuffer(var bytes) = part.data else { throw TransportError.invalidResponse }
                // A frame has at most 16 KiB by our HTTP/2 settings. Decode and forward without a queue.
                var currentDecoder = decoder
                defer { decoder = currentDecoder }
                try currentDecoder.append(&bytes) { try receive($0, context: context) }
            case .rstStream: throw TransportError.closed
            default: break
            }
        } catch { fail(error, context: context) }
    }

    private func receive(_ message: ByteBuffer, context: ChannelHandlerContext) throws {
        var options = BinaryDecodingOptions()
        options.discardUnknownFields = true
        options.messageDepthLimit = 8
        let response = try Teleport_Transport_V1_ProxySSHResponse(
            serializedBytes: Data(message.readableBytesView), options: options)
        if phase == .waitingForDetails {
            guard response.hasDetails else { throw TransportError.invalidResponse }
            guard !response.details.fipsEnabled else { throw TeleportError.unsupportedPolicy(.fips) }
            phase = .streaming
            timeout?.cancel()
            ready.succeed(())
        } else if response.hasDetails { throw TransportError.invalidResponse }
        switch response.frame {
        case .ssh(let frame):
            guard !frame.payload.isEmpty else { return }
            guard frame.payload.count <= 262_144, frame.payload.count <= 524_288 - pendingBytes else {
                throw TransportError.oversizedMessage
            }
            pendingBytes += frame.payload.count
            let byteCount = frame.payload.count
            let bytes = socket.allocator.buffer(bytes: frame.payload)
            let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
            socket.writeAndFlush(bytes).hop(to: context.eventLoop).whenComplete { [self] result in
                pendingBytes -= byteCount
                switch result {
                case .success:
                    if phase == .finished { finishOutputIfDrained() }
                    else if pendingBytes == 0 { bound.value.read() }
                case .failure(let error): fail(error, context: bound.value)
                }
            }
        case .agent:
            // This matches the pinned upstream client when no SSH agent is supplied.
            break
        case nil: break
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        if phase != .finished && pendingBytes == 0 { context.read() }
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable {
            let socket = socket
            socket.eventLoop.execute { socket.pipeline.fireUserInboundEventTriggered(PumpEvent.upstreamWritable) }
        }
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        if phase != .finished { fail(TransportError.missingStatus, context: context) }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) { fail(error, context: context) }

    private func finishOutputIfDrained() {
        if pendingBytes == 0 { socket.close(mode: .output, promise: nil) }
    }

    private func fail(_ error: any Error, context: ChannelHandlerContext) {
        failBeforeStart(error)
        socket.close(promise: nil)
        context.close(promise: nil)
    }

    /// Called on the stream event loop if adding the handler fails.
    func failBeforeStart(_ error: any Error) {
        if phase == .waitingForDetails || phase == .idle { ready.fail(error) }
        phase = .finished
        timeout?.cancel()
    }
}

func makeSocketPair() throws -> (ssh: Int32, pump: Int32) {
    var pair: [Int32] = [-1, -1]
    guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw TransportError.socket(errno) }
    do {
        for descriptor in pair {
            let flags = fcntl(descriptor, F_GETFL)
            let fdFlags = fcntl(descriptor, F_GETFD)
            var one: Int32 = 1
            guard flags >= 0, fdFlags >= 0,
                  fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(descriptor, F_SETFD, fdFlags | FD_CLOEXEC) == 0,
                  setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
                throw TransportError.socket(errno)
            }
        }
        return (pair[0], pair[1])
    } catch {
        Darwin.close(pair[0]); Darwin.close(pair[1]); throw error
    }
}
