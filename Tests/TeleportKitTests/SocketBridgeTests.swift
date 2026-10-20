import Darwin
import Foundation
import Testing
import NIOCore
import NIOEmbedded
import NIOHTTP2
import NIOHPACK
import NIOPosix
import SwiftProtobuf
@testable import TeleportKit

/// Holds native write completions to model a socket whose peer does not read.
private final class DelayedSocketSink: ChannelOutboundHandler, @unchecked Sendable {
    typealias OutboundIn = ByteBuffer
    private var pending: [(ByteBuffer, EventLoopPromise<Void>?)] = []
    private(set) var delivered = Data()
    private(set) var outputClosed = false
    private(set) var allClosed = false
    var pendingCount: Int { pending.count }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        pending.append((unwrapOutboundIn(data), promise))
    }

    func flush(context: ChannelHandlerContext) {}

    func close(context: ChannelHandlerContext, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        if mode == .output {
            outputClosed = true
            promise?.succeed(())
            return
        }
        allClosed = true
        let abandoned = pending
        pending.removeAll()
        for (_, writePromise) in abandoned { writePromise?.fail(ChannelError.ioOnClosedChannel) }
        context.close(mode: mode, promise: promise)
    }

    func deliver(_ count: Int) {
        let amount = min(count, pending.count)
        let completed = Array(pending.prefix(amount))
        pending.removeFirst(amount)
        for (bytes, promise) in completed {
            delivered.append(contentsOf: bytes.readableBytesView)
            promise?.succeed(())
        }
    }
}

@Test func slowSocketPreservesSmallMessagesAndFinalBytesBeforeEOF() throws {
    let loop = EmbeddedEventLoop()
    let sink = DelayedSocketSink()
    let socket = EmbeddedChannel(handler: sink, loop: loop)
    let stream = EmbeddedChannel(loop: loop)
    let ready = loop.makePromise(of: Void.self)
    try socket.connect(to: .init(ipAddress: "127.0.0.1", port: 1)).wait()
    try stream.connect(to: .init(ipAddress: "127.0.0.1", port: 1)).wait()
    try stream.pipeline.addHandler(ProxySSHHandler(
        target: "node:0", cluster: "cluster", authority: "proxy.test",
        socket: socket, ready: ready)).wait()
    defer {
        sink.deliver(Int.max)
        _ = try? stream.finish(acceptAlreadyClosed: true)
        _ = try? socket.finish(acceptAlreadyClosed: true)
    }

    try stream.writeInbound(HTTP2Frame.FramePayload.headers(.init(headers: HPACKHeaders([
        (":status", "200"), ("content-type", "application/grpc")
    ]))))
    var details = Teleport_Transport_V1_ProxySSHResponse()
    details.details = .init()
    var encoded = try grpcMessage(details.serializedData(), allocator: stream.allocator)
    var expected = Data()
    // These messages fit inside one HTTP/2 receive window. Message count must
    // not terminate a valid byte stream when the socket applies backpressure.
    for index in 0..<6_000 {
        let byte = UInt8(index % 251)
        expected.append(byte)
        var response = Teleport_Transport_V1_ProxySSHResponse()
        response.ssh.payload = Data([byte])
        var frame = try grpcMessage(response.serializedData(), allocator: stream.allocator)
        encoded.writeBuffer(&frame)
    }
    #expect(encoded.readableBytes <= 65_535)
    while encoded.readableBytes > 0 {
        let bytes = encoded.readSlice(length: min(16_384, encoded.readableBytes))!
        stream.pipeline.fireChannelRead(HTTP2Frame.FramePayload.data(
            .init(data: .byteBuffer(bytes))))
    }
    stream.pipeline.fireChannelReadComplete()
    try ready.futureResult.wait()
    #expect(!sink.allClosed)
    #expect(sink.pendingCount == 6_000)

    try stream.writeInbound(HTTP2Frame.FramePayload.headers(.init(
        headers: HPACKHeaders([("grpc-status", "0")]), endStream: true)))
    #expect(!sink.outputClosed)
    sink.deliver(5_999)
    loop.run()
    #expect(!sink.outputClosed)
    sink.deliver(1)
    loop.run()
    #expect(sink.outputClosed)
    #expect(!sink.allClosed)
    #expect(sink.delivered == expected)
}

@Test func repeatedCancellationDoesNotCloseReusedDescriptor() async throws {
    for cancelBeforeInstall in [false, true] {
        let pair = try makeSocketPair()
        defer { Darwin.close(pair.ssh) }
        let cancellation = ChannelCancellation()
        if cancelBeforeInstall { cancellation.cancel() }
        let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelOption(ChannelOptions.autoRead, value: false)
            .withConnectedSocket(pair.pump).get()
        cancellation.install(channel)
        cancellation.cancel()
        try await channel.closeFuture.get()

        let replacement = try makeSocketPair()
        defer { Darwin.close(replacement.ssh); Darwin.close(replacement.pump) }
        let reused: Int32
        if replacement.ssh == pair.pump || replacement.pump == pair.pump {
            reused = pair.pump
        } else {
            reused = dup2(replacement.ssh, pair.pump)
            #expect(reused == pair.pump)
        }
        defer {
            if reused != replacement.ssh && reused != replacement.pump { Darwin.close(reused) }
        }
        cancellation.cancel()
        _ = try? await channel.close().get()
        #expect(fcntl(reused, F_GETFD) >= 0)
        var byte: UInt8 = 42
        #expect(Darwin.write(replacement.ssh, &byte, 1) == 1)
        var received: UInt8 = 0
        #expect(Darwin.read(replacement.pump, &received, 1) == 1)
        #expect(received == byte)
    }
}

@Test func setupFailureSettlesOnceAndInactiveProxyClosesImmediately() throws {
    let loop = EmbeddedEventLoop()
    let unaryResult = loop.makePromise(of: Data.self)
    let unary = UnaryHandler(path: "/example/RPC", authority: "proxy.test",
                             request: Data(), result: unaryResult)
    unary.failBeforeStart(TransportError.closed)
    unary.failBeforeStart(TransportError.deadlineExceeded)
    #expect(throws: TransportError.closed) { try unaryResult.futureResult.wait() }

    let socket = EmbeddedChannel(loop: loop)
    try socket.connect(to: .init(ipAddress: "127.0.0.1", port: 1)).wait()
    // The stream became inactive before the setup handler could be installed.
    let stream = EmbeddedChannel(loop: loop)
    let ready = loop.makePromise(of: Void.self)
    let observed = NIOLoopBoundBox<Result<Void, any Error>?>(nil, eventLoop: loop)
    ready.futureResult.whenComplete { observed.value = $0 }
    let handler = ProxySSHHandler(target: "node:0", cluster: "cluster",
                                  authority: "proxy.test", socket: socket, ready: ready)
    defer {
        handler.failBeforeStart(TransportError.closed)
        _ = try? stream.finish(acceptAlreadyClosed: true)
        _ = try? socket.finish(acceptAlreadyClosed: true)
    }
    try stream.pipeline.addHandler(handler).wait()
    loop.run()
    // No clock advance: cancellation must not depend on the 30-second timer.
    if case .failure(let error)? = observed.value {
        #expect(error as? TransportError == .closed)
    } else {
        Issue.record("Inactive ProxySSH setup did not fail immediately")
    }
    #expect(!socket.isActive)
    #expect(!stream.isActive)
    handler.failBeforeStart(TransportError.deadlineExceeded)
}

@Test func tlsSetupFailureAndPreActivationCloseReleaseReadiness() async throws {
    let material = TLSMaterial(certificateDER: Data(), privateKeyDER: Data(), authorityDER: [])
    await #expect(throws: TransportError.invalidResponse) {
        _ = try await HTTP2Session.connect(host: "127.0.0.1", port: 1, route: .sshProxy, material: material)
    }
    let cancelled = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        _ = try await HTTP2Session.connect(host: "127.0.0.1", port: 1, route: .sshProxy, material: material)
    }
    await #expect(throws: CancellationError.self) { try await cancelled.value }

    let loop = EmbeddedEventLoop()
    let channel = EmbeddedChannel(loop: loop)
    let ready = loop.makePromise(of: Void.self)
    let validator = ALPNValidator(ready: ready)
    let observed = NIOLoopBoundBox<Result<Void, any Error>?>(nil, eventLoop: loop)
    ready.futureResult.whenComplete { observed.value = $0 }
    defer { validator.failBeforeStart(TransportError.closed) }
    try await channel.pipeline.addHandler(validator).get()
    // A failed connection never becomes active, so it emits no channelInactive.
    _ = try channel.finish()
    loop.run()
    if case .failure(let error)? = observed.value {
        #expect(error as? TransportError == .closed)
    } else {
        Issue.record("TLS readiness remained pending after pre-activation close")
    }
}
