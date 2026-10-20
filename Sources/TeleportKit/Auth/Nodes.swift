import Foundation
import SwiftProtobuf
import TeleportCore

extension TeleportClient {
    /// Return one bounded page. Pass its nextKey to obtain the next page.
    public func nodes(limit: Int = 100, startKey: String = "") async throws -> TeleportNodePage {
        guard (1...500).contains(limit), startKey.utf8.count <= 4096 else { throw TeleportError.invalidConfiguration("node page bounds") }
        let identity = try await identity()
        var request = Teleportkit_Resources_ListResourcesRequest()
        request.resourceType = "node"; request.namespace = "default"; request.limit = Int32(limit); request.startKey = startKey
        let bytes = try await resourceRequest(message: request.serializedData(), identity: identity)
        return try NodePageDecoder.decode(bytes, clusterName: identity.clusterName, limit: limit, startKey: startKey)
    }

    /// Resolve an exact stable ID or exact display name. Reject duplicate names.
    public func resolveNode(_ nameOrID: String) async throws -> TeleportNode {
        guard !nameOrID.isEmpty, nameOrID.utf8.count <= 1024 else { throw TeleportError.invalidConfiguration("node name") }
        var key = "", seen = Set<String>(), matches = [TeleportNode]()
        for _ in 0..<100 {
            let page = try await nodes(limit: 100, startKey: key)
            for node in page.nodes {
                guard seen.insert(node.id).inserted else { throw TeleportError.invalidResponse("repeated node") }
                if node.id == nameOrID { return node }
                if node.name == nameOrID { matches.append(node) }
            }
            if page.nextKey.isEmpty {
                guard matches.count <= 1 else { throw TeleportError.ambiguousNode }
                guard let match = matches.first else { throw TeleportError.nodeNotFound }; return match
            }
            key = page.nextKey
        }
        throw TeleportError.limitExceeded("node lookup pages")
    }
}

enum NodePageDecoder {
    static func decode(_ bytes: Data, clusterName: String, limit: Int, startKey: String) throws -> TeleportNodePage {
        guard bytes.count <= 1_048_576 else { throw TeleportError.limitExceeded("node response") }
        var options = BinaryDecodingOptions(); options.messageDepthLimit = 8; options.discardUnknownFields = true
        var bounded = LimitedNodeResponse(limit: limit)
        try bounded.merge(serializedBytes: bytes, options: options)
        let response = bounded.response
        guard response.nextKey.utf8.count <= 4096,
              response.nextKey.isEmpty || response.nextKey != startKey else { throw TeleportError.invalidResponse("node pagination") }
        var ids = Set<String>()
        let nodes = try response.resources.map { resource -> TeleportNode in
            guard resource.hasNode, resource.node.kind == "node", resource.node.hasMetadata, resource.node.hasSpec,
                  !resource.requiresRequest, resource.node.metadata.labels.count <= 128,
                  resource.node.metadata.labels.allSatisfy({ $0.key.utf8.count <= 1024 && $0.value.utf8.count <= 4096 }),
                  ids.insert(resource.node.metadata.name).inserted else { throw TeleportError.invalidResponse("node resource") }
            return try TeleportNode(id: resource.node.metadata.name, name: resource.node.spec.hostname,
                                    clusterName: clusterName, labels: resource.node.metadata.labels)
        }
        return TeleportNodePage(nodes: nodes, nextKey: response.nextKey)
    }

}

/// Decode each entry with SwiftProtobuf, applying the page limit before retaining it.
/// This avoids a large repeated-field allocation before validating the page.
private struct LimitedNodeResponse: SwiftProtobuf.Message {
    static let protoMessageName = Teleportkit_Resources_ListResourcesResponse.protoMessageName
    private let limit: Int
    var response = Teleportkit_Resources_ListResourcesResponse()
    var unknownFields: SwiftProtobuf.UnknownStorage {
        get { response.unknownFields }
        set { response.unknownFields = newValue }
    }
    init() { limit = 0 }
    init(limit: Int) { self.limit = limit }

    mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
        while let field = try decoder.nextFieldNumber() {
            switch field {
            case 1:
                if response.resources.count >= limit {
                    // SwiftProtobuf treats a known field with another wire type as
                    // unknown. Preserve that behavior without allocating a Resource.
                    var extra: Google_Protobuf_Empty?
                    try decoder.decodeSingularMessageField(value: &extra)
                    if extra != nil { throw TeleportError.limitExceeded("node page resources") }
                } else {
                    var resource: Teleportkit_Resources_Resource?
                    try decoder.decodeSingularMessageField(value: &resource)
                    if let resource { response.resources.append(resource) }
                }
            case 2: try decoder.decodeSingularStringField(value: &response.nextKey)
            default: break
            }
        }
    }
    func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws { try response.traverse(visitor: &visitor) }
    func isEqualTo(message: any SwiftProtobuf.Message) -> Bool {
        guard let other = message as? Self else { return false }
        return response == other.response
    }
}

public struct TeleportNodePage: Sendable, Equatable {
    public let nodes: [TeleportNode]
    public let nextKey: String
    public var hasMore: Bool { !nextKey.isEmpty }
}
