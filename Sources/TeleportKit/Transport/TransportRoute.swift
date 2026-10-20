import Foundation
import TeleportCore

/// Auth uses an ALPN route hint plus h2. ProxySSH also uses h2 with its own route hint.
enum TransportRoute: Sendable {
    case sshProxy
    case auth(clusterName: String)

    func offeredProtocols() throws -> [String] {
        switch self {
        case .sshProxy: return ["teleport-proxy-ssh-grpc", "h2"]
        case .auth(let cluster):
            // The hex name and suffix must fit one TLS ALPN identifier (255 bytes).
            let prefix = "teleport-auth@", suffix = ".teleport.cluster.local"
            let maximumNameBytes = (255 - prefix.utf8.count - suffix.utf8.count) / 2
            guard !cluster.isEmpty, cluster.utf8.count <= maximumNameBytes else {
                throw TeleportError.invalidConfiguration("cluster name exceeds the ALPN route limit")
            }
            let encoded = cluster.utf8.map { String(format: "%02x", $0) }.joined()
            let hint = prefix + encoded + suffix
            guard hint.utf8.count <= 255 else { throw TeleportError.invalidConfiguration("ALPN route length") }
            return [hint, "h2"]
        }
    }
}
