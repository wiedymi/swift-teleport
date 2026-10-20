import Foundation
import NIOCore
import NIOHTTP2
import NIOHPACK
import TeleportCore

enum TransportError: Error, Equatable, Sendable {
    case invalidResponse
    case oversizedMessage
    case unsupportedCompression
    case truncatedMessage
    case missingStatus
    case remoteStatus(Int)
    case closed
    case deadlineExceeded
    case socket(Int32)
}

/// A single message is capped before its length can reserve storage.
struct GRPCDecoder {
    let maximumMessageBytes: Int
    private var buffer = ByteBuffer()

    init(maximumMessageBytes: Int = 1_048_576) {
        precondition(maximumMessageBytes > 0 && maximumMessageBytes <= Int(UInt32.max))
        self.maximumMessageBytes = maximumMessageBytes
    }

    mutating func append(_ input: inout ByteBuffer, consume: (ByteBuffer) throws -> Void) throws {
        // Copy at most one message into retained storage. A read can contain many messages.
        while input.readableBytes > 0 {
            let needed: Int
            if buffer.readableBytes < 5 {
                needed = 5 - buffer.readableBytes
            } else {
                guard buffer.getInteger(at: buffer.readerIndex, as: UInt8.self) == 0 else {
                    throw TransportError.unsupportedCompression
                }
                let length = Int(buffer.getInteger(at: buffer.readerIndex + 1, as: UInt32.self)!)
                guard length <= maximumMessageBytes else { throw TransportError.oversizedMessage }
                needed = length + 5 - buffer.readableBytes
            }
            if needed > 0 {
                let amount = min(needed, input.readableBytes)
                var slice = input.readSlice(length: amount)!
                buffer.writeBuffer(&slice)
            }
            guard buffer.readableBytes >= 5 else { continue }
            guard buffer.getInteger(at: buffer.readerIndex, as: UInt8.self) == 0 else {
                throw TransportError.unsupportedCompression
            }
            let length = Int(buffer.getInteger(at: buffer.readerIndex + 1, as: UInt32.self)!)
            guard length <= maximumMessageBytes else { throw TransportError.oversizedMessage }
            guard buffer.readableBytes >= length + 5 else { continue }
            buffer.moveReaderIndex(forwardBy: 5)
            let message = buffer.readSlice(length: length)!
            try consume(message)
            buffer.clear()
        }
    }

    func finish() throws {
        guard buffer.readableBytes == 0 else { throw TransportError.truncatedMessage }
    }
}

func grpcMessage(_ data: Data, allocator: ByteBufferAllocator) throws -> ByteBuffer {
    guard data.count <= 1_048_576, let length = UInt32(exactly: data.count) else {
        throw TransportError.oversizedMessage
    }
    var result = allocator.buffer(capacity: data.count + 5)
    result.writeInteger(UInt8(0))
    result.writeInteger(length)
    result.writeBytes(data)
    return result
}

/// HTTP/2 validates header syntax; this validates gRPC semantics and metadata bounds.
struct GRPCResponseState {
    private enum Phase { case waitingForHeaders, receiving, complete }
    private var phase = Phase.waitingForHeaders
    var completed: Bool { phase == .complete }
    private var metadataBytes = 0

    mutating func headers(_ headers: HPACKHeaders, endStream: Bool) throws {
        guard !completed else { throw TransportError.invalidResponse }
        for header in headers {
            let size = header.name.utf8.count + header.value.utf8.count
            guard size <= 16_384 - metadataBytes else { throw TransportError.oversizedMessage }
            metadataBytes += size
        }
        if phase == .waitingForHeaders {
            guard headers[canonicalForm: ":status"] == ["200"],
                  headers[canonicalForm: "content-type"].count == 1,
                  let type = headers.first(name: "content-type"),
                  type == "application/grpc" || type.hasPrefix("application/grpc+") else {
                throw TransportError.invalidResponse
            }
            let encoding = headers[canonicalForm: "grpc-encoding"]
            guard encoding.isEmpty || encoding == ["identity"] else {
                throw TransportError.unsupportedCompression
            }
            phase = .receiving
        } else if headers.contains(name: ":status") {
            throw TransportError.invalidResponse
        }
        let status = headers[canonicalForm: "grpc-status"]
        if endStream {
            guard status.count == 1, let code = Int(status[0]), (0...16).contains(code) else {
                throw TransportError.missingStatus
            }
            if code == 7 { throw TeleportError.accessDenied }
            if code == 16 { throw TeleportError.authenticationRequired }
            guard code == 0 else { throw TransportError.remoteStatus(code) }
            phase = .complete
        } else if !status.isEmpty {
            throw TransportError.invalidResponse
        }
    }

    func data(endStream: Bool) throws {
        guard phase == .receiving else { throw TransportError.invalidResponse }
        guard !endStream else { throw TransportError.missingStatus }
    }
}
