import Foundation
import Testing
import NIOCore
import NIOEmbedded
import NIOHTTP2
import NIOHPACK
@testable import TeleportKit

@Test func grpcFragmentationAndCoalescing() throws {
    let allocator = ByteBufferAllocator()
    let expected = [Data(), Data("hello".utf8), Data(repeating: 42, count: 65_536), Data("last".utf8)]
    var joined = allocator.buffer(capacity: 70_000)
    for data in expected { var frame = try grpcMessage(data, allocator: allocator); joined.writeBuffer(&frame) }
    for fragmentSize in [1, 4, 5, 16_384, 100_000] {
        var input = joined
        var decoder = GRPCDecoder()
        var result: [Data] = []
        while input.readableBytes > 0 {
            var part = input.readSlice(length: min(fragmentSize, input.readableBytes))!
            try decoder.append(&part) { result.append(Data($0.readableBytesView)) }
        }
        try decoder.finish()
        #expect(result == expected)
    }
}

@Test func grpcBoundsCompressionAndEOF() throws {
    var decoder = GRPCDecoder(maximumMessageBytes: 16)
    var oversized = ByteBuffer(bytes: [0, 255, 255, 255, 255])
    #expect(throws: TransportError.oversizedMessage) { try decoder.append(&oversized) { _ in } }
    var compressed = ByteBuffer(bytes: [1, 0, 0, 0, 0])
    var other = GRPCDecoder()
    #expect(throws: TransportError.unsupportedCompression) { try other.append(&compressed) { _ in } }
    for prefix in [[UInt8(0)], [0, 0, 0, 0], [0, 0, 0, 0, 2, 42]] {
        var bytes = ByteBuffer(bytes: prefix)
        var decoder = GRPCDecoder()
        try decoder.append(&bytes) { _ in }
        #expect(throws: TransportError.truncatedMessage) { try decoder.finish() }
    }
}

private let initialHeaders = HPACKHeaders([(":status", "200"), ("content-type", "application/grpc")])

@Test func tlsRouteHintIsDistinctFromNegotiatedProtocol() throws {
    let auth = TransportRoute.auth(clusterName: "ab")
    #expect(try auth.offeredProtocols() == ["teleport-auth@6162.teleport.cluster.local", "h2"])
    #expect(try TransportRoute.sshProxy.offeredProtocols() == ["teleport-proxy-ssh-grpc", "h2"])
    #expect(throws: TeleportError.self) { try TransportRoute.auth(clusterName: String(repeating: "x", count: 110)).offeredProtocols() }
}

@Test func cachedTLSContextCannotMergeDifferentAuthorityGroups() {
    let a = Data([1]), b = Data([2]), c = Data([3])
    #expect(credentialContextHash([[a, b], [c]]) != credentialContextHash([[a], [b, c]]))
    #expect(credentialContextHash([[a + b], [c]]) != credentialContextHash([[a], [b + c]]))
}

@Test func grpcStatusIsMandatoryAndValidated() throws {
    var state = GRPCResponseState()
    try state.headers(initialHeaders, endStream: false)
    try state.data(endStream: false)
    #expect(throws: TransportError.missingStatus) { try state.data(endStream: true) }
    #expect(throws: TransportError.missingStatus) { try state.headers(HPACKHeaders(), endStream: true) }
    #expect(throws: TeleportError.accessDenied) {
        try state.headers(HPACKHeaders([("grpc-status", "7")]), endStream: true)
    }
    try state.headers(HPACKHeaders([("grpc-status", "0")]), endStream: true)
    #expect(state.completed)
    #expect(throws: TransportError.invalidResponse) { try state.data(endStream: false) }
}

@Test func grpcRejectsInvalidHeaders() throws {
    for headers in [
        HPACKHeaders([(":status", "404"), ("content-type", "application/grpc")]),
        HPACKHeaders([(":status", "200"), ("content-type", "text/html")]),
        HPACKHeaders([(":status", "200"), ("content-type", "application/grpc"), ("grpc-status", "0")]),
    ] {
        var state = GRPCResponseState()
        #expect(throws: TransportError.invalidResponse) { try state.headers(headers, endStream: false) }
    }
    var state = GRPCResponseState()
    #expect(throws: TransportError.unsupportedCompression) {
        try state.headers(HPACKHeaders([(":status", "200"), ("content-type", "application/grpc"), ("grpc-encoding", "gzip")]), endStream: false)
    }
    var large = GRPCResponseState()
    #expect(throws: TransportError.oversizedMessage) {
        try large.headers(HPACKHeaders([(":status", "200"), ("content-type", "application/grpc"), ("x", String(repeating: "a", count: 16_384))]), endStream: false)
    }
}

@Test func unaryWaitsForTrailersAndPreservesLastMessage() throws {
    let channel = EmbeddedChannel()
    let result = channel.eventLoop.makePromise(of: Data.self)
    try channel.pipeline.addHandler(UnaryHandler(path: "/example/RPC", authority: "example.test", request: Data(), result: result)).wait()
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 1)).wait()
    try channel.writeInbound(HTTP2Frame.FramePayload.headers(.init(headers: initialHeaders)))
    let bytes = try grpcMessage(Data("final".utf8), allocator: channel.allocator)
    try channel.writeInbound(HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(bytes))))
    try channel.writeInbound(HTTP2Frame.FramePayload.headers(.init(headers: HPACKHeaders([("grpc-status", "0")]), endStream: true)))
    #expect(try result.futureResult.wait() == Data("final".utf8))
    _ = try channel.finish()
}

@Test func unaryTimeoutAndMissingStatusFail() throws {
    for timeOut in [true, false] {
        let channel = EmbeddedChannel()
        let result = channel.eventLoop.makePromise(of: Data.self)
        try channel.pipeline.addHandler(UnaryHandler(path: "/example/RPC", authority: "example.test", request: Data(), result: result)).wait()
        try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 1)).wait()
        if timeOut { channel.embeddedEventLoop.advanceTime(by: .seconds(31)) }
        else { try channel.close().wait() }
        #expect(throws: timeOut ? TransportError.deadlineExceeded : TransportError.missingStatus) {
            try result.futureResult.wait()
        }
        _ = try channel.finish(acceptAlreadyClosed: true)
    }
}

@Test(arguments: [true, false])
func unaryRejectsMultipleResponses(inOneFrame: Bool) throws {
    let channel = EmbeddedChannel()
    let result = channel.eventLoop.makePromise(of: Data.self)
    try channel.pipeline.addHandler(UnaryHandler(
        path: "/example/RPC", authority: "example.test", request: Data(), result: result
    )).wait()
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 1)).wait()
    try channel.writeInbound(HTTP2Frame.FramePayload.headers(.init(headers: initialHeaders)))
    var first = try grpcMessage(Data("first".utf8), allocator: channel.allocator)
    var second = try grpcMessage(Data("second".utf8), allocator: channel.allocator)
    if inOneFrame {
        first.writeBuffer(&second)
        try channel.writeInbound(HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(first))))
    } else {
        try channel.writeInbound(HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(first))))
        try channel.writeInbound(HTTP2Frame.FramePayload.data(.init(data: .byteBuffer(second))))
    }
    #expect(throws: TransportError.invalidResponse) { try result.futureResult.wait() }
    _ = try channel.finish(acceptAlreadyClosed: true)
}

@Test func socketPairIsNonblockingAndDoesNotInheritAcrossExec() throws {
    let pair = try makeSocketPair()
    defer { Darwin.close(pair.ssh); Darwin.close(pair.pump) }
    #expect(fcntl(pair.ssh, F_GETFL) & O_NONBLOCK != 0)
    #expect(fcntl(pair.pump, F_GETFD) & FD_CLOEXEC != 0)
}
