import Foundation
import NIOCore
import NIOFoundationCompat
import NIOHTTP2
import NIOHPACK

final class UnaryHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload
    private let path: String
    private let authority: String
    private let request: Data
    private let result: EventLoopPromise<Data>
    private var response: Data?
    private var decoder = GRPCDecoder()
    private var status = GRPCResponseState()
    private var finished = false
    private var timeout: Scheduled<Void>?

    init(path: String, authority: String, request: Data, result: EventLoopPromise<Data>) {
        self.path = path; self.authority = authority; self.request = request; self.result = result
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        timeout = context.eventLoop.scheduleTask(in: .seconds(30)) { [self] in
            fail(TransportError.deadlineExceeded, context: bound.value)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        do {
            let headers = HPACKHeaders([
                (":method", "POST"), (":scheme", "https"), (":path", path),
                (":authority", authority), ("content-type", "application/grpc"),
                ("te", "trailers"), ("grpc-timeout", "30S"),
            ])
            context.write(wrapOutboundOut(.headers(.init(headers: headers))), promise: nil)
            let bytes = try grpcMessage(request, allocator: context.channel.allocator)
            context.writeAndFlush(wrapOutboundOut(.data(.init(data: .byteBuffer(bytes), endStream: true))), promise: nil)
        } catch { fail(error, context: context) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !finished else { return }
        do {
            switch unwrapInboundIn(data) {
            case .headers(let part):
                try status.headers(part.headers, endStream: part.endStream)
                if part.endStream {
                    try decoder.finish()
                    guard let response else { throw TransportError.invalidResponse }
                    finished = true
                    timeout?.cancel()
                    result.succeed(response)
                }
            case .data(let part):
                try status.data(endStream: part.endStream)
                guard case .byteBuffer(var bytes) = part.data else { throw TransportError.invalidResponse }
                var received = response
                try decoder.append(&bytes) { message in
                    guard received == nil else { throw TransportError.invalidResponse }
                    received = Data(message.readableBytesView)
                }
                response = received
            case .rstStream: throw TransportError.closed
            default: break
            }
        } catch { fail(error, context: context) }
    }

    func errorCaught(context: ChannelHandlerContext, error: any Error) { fail(error, context: context) }
    func channelInactive(context: ChannelHandlerContext) {
        if !finished { fail(TransportError.missingStatus, context: context) }
        context.fireChannelInactive()
    }

    /// Called on the parent event loop if stream creation fails before activation.
    func failBeforeStart(_ error: any Error) {
        if !finished {
            finished = true
            timeout?.cancel()
            result.fail(error)
        }
    }

    private func fail(_ error: any Error, context: ChannelHandlerContext) {
        failBeforeStart(error)
        context.close(promise: nil)
    }
}
