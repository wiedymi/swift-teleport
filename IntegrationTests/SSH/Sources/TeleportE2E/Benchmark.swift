import Darwin
import Foundation
import TeleportKit
import CTeleportSSHEngine

private struct BenchmarkResources: Codable, Sendable {
    let residentBytes: UInt64?
    let processPeakResidentBytes: UInt64?
    let openDescriptorCount: Int?

    static func read() -> Self {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let status = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        var usage = rusage()
        let usageStatus = getrusage(RUSAGE_SELF, &usage)
        return Self(
            residentBytes: status == KERN_SUCCESS ? UInt64(info.resident_size) : nil,
            processPeakResidentBytes: usageStatus == 0 && usage.ru_maxrss >= 0 ? UInt64(usage.ru_maxrss) : nil,
            openDescriptorCount: (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd"))?.count
        )
    }
}

private struct BenchmarkDistribution: Codable, Sendable {
    let samples: [Double]
    let p50: Double
    let p95: Double
    let p99: Double

    init(_ samples: [Double]) {
        precondition(!samples.isEmpty)
        self.samples = samples
        let sorted = samples.sorted()
        func percentile(_ fraction: Double) -> Double {
            sorted[max(0, Int(ceil(Double(sorted.count) * fraction)) - 1)]
        }
        p50 = percentile(0.50); p95 = percentile(0.95); p99 = percentile(0.99)
    }
}

private enum BenchmarkProxyState: String, Codable, Sendable { case cold, warm }

private struct BenchmarkBatch: Codable, Sendable {
    let proxyState: BenchmarkProxyState
    let preparedLiveLeases: Int
    let proxyPrepareMilliseconds: BenchmarkDistribution
    let sshHandshakeAuthCommandCleanupMilliseconds: BenchmarkDistribution
    let preparePlusSSHMilliseconds: BenchmarkDistribution
    let batchWallMilliseconds: Double
    let before: BenchmarkResources
    let afterAllLeasesPrepared: BenchmarkResources
    let afterAllLeasesClosed: BenchmarkResources
}

private struct BenchmarkSFTP: Codable, Sendable {
    let filePayloadBytes: Int
    let totalPayloadBytes: Int
    let prepareHandshakeRoundtripCleanupMilliseconds: Double
    let aggregatePayloadMiBPerSecond: Double
    let exactBytesVerified: Bool
    let afterLeaseClosed: BenchmarkResources
}

private struct BenchmarkReport: Codable, Sendable {
    let schemaVersion: Int
    let measuredAt: String
    let system: String
    let clock: String
    let batchMeaning: String
    let memoryMeaning: String
    let fdMeaning: String
    let beforeFreshClient: BenchmarkResources
    let batches: [BenchmarkBatch]
    let sftp: BenchmarkSFTP
    let afterSignOutImmediate: BenchmarkResources
}

private struct PreparedBenchmarkLease: Sendable {
    let connection: TeleportConnection
    let preparationMilliseconds: Double
    let marker: String
}

private func benchmarkMilliseconds(_ duration: Duration) -> Double {
    let parts = duration.components
    return Double(parts.seconds) * 1_000 + Double(parts.attoseconds) / 1_000_000_000_000_000
}

private func benchmarkSSH(_ connection: TeleportConnection, command: String,
                          operation: TeleportSSHOperation = TELEPORT_SSH_EXEC,
                          input: Data = Data(), path: String = "") async throws -> SSHResult {
    try await withTaskCancellationHandler {
        try Task.checkCancellation()
        return try await runSSH(connection, command: command, operation: operation,
                                input: input, sftpPath: path)
    } onCancel: {
        Task { await connection.close() }
    }
}

private func benchmarkBatch(client: TeleportClient, node: TeleportNode, login: String,
                            count: Int, proxyState: BenchmarkProxyState) async throws -> BenchmarkBatch {
    let before = BenchmarkResources.read()
    FileHandle.standardError.write(Data("Benchmark \(proxyState.rawValue): \(count) prepared connections\n".utf8))
    let batchStart = ContinuousClock.now
    var leases: [PreparedBenchmarkLease] = []
    do {
        for index in 0..<count {
            try Task.checkCancellation()
            let start = ContinuousClock.now
            let connection = try await client.connect(to: node, login: login)
            leases.append(PreparedBenchmarkLease(
                connection: connection,
                preparationMilliseconds: benchmarkMilliseconds(start.duration(to: .now)),
                marker: "TELEPORT_BENCH_" + UUID().uuidString + "_" + String(index)
            ))
        }
        let prepared = BenchmarkResources.read()
        let measurements = try await withThrowingTaskGroup(of: (Double, Double).self) { group in
            for lease in leases {
                group.addTask {
                    do {
                        let start = ContinuousClock.now
                        let result = try await benchmarkSSH(lease.connection,
                            command: "printf %s " + lease.marker)
                        let milliseconds = benchmarkMilliseconds(start.duration(to: .now))
                        await lease.connection.close()
                        try require(result.code == 0 && result.exit == 0 &&
                                    result.output == Data(lease.marker.utf8), "Benchmark command failed (result \(result.code), native \(result.native), exit \(result.exit), output bytes \(result.output.count), expected \(lease.marker.utf8.count), test output \(String(reflecting: String(decoding: result.output.prefix(512), as: UTF8.self)))))")
                        return (lease.preparationMilliseconds, milliseconds)
                    } catch {
                        await lease.connection.close()
                        throw error
                    }
                }
            }
            var values: [(Double, Double)] = []
            for try await value in group { values.append(value) }
            return values
        }
        leases.removeAll()
        return BenchmarkBatch(
            proxyState: proxyState, preparedLiveLeases: count,
            proxyPrepareMilliseconds: BenchmarkDistribution(measurements.map(\.0)),
            sshHandshakeAuthCommandCleanupMilliseconds: BenchmarkDistribution(measurements.map(\.1)),
            preparePlusSSHMilliseconds: BenchmarkDistribution(measurements.map { $0.0 + $0.1 }),
            batchWallMilliseconds: benchmarkMilliseconds(batchStart.duration(to: .now)),
            before: before, afterAllLeasesPrepared: prepared,
            afterAllLeasesClosed: BenchmarkResources.read()
        )
    } catch {
        for lease in leases { await lease.connection.close() }
        throw error
    }
}

private func benchmarkTransfer(client: TeleportClient, node: TeleportNode, login: String) async throws -> BenchmarkSFTP {
    let payload = Data((0..<1_048_576).map { UInt8($0 & 255) })
    let start = ContinuousClock.now
    let connection = try await client.connect(to: node, login: login)
    let result: SSHResult
    do {
        result = try await benchmarkSSH(connection, command: "", operation: TELEPORT_SSH_SFTP_ROUNDTRIP,
            input: payload, path: "/tmp/teleport-benchmark-" + UUID().uuidString)
        await connection.close()
    } catch {
        await connection.close()
        throw error
    }
    let elapsed = benchmarkMilliseconds(start.duration(to: .now))
    try require(result.code == 0 && result.output == payload && elapsed > 0,
                "Benchmark SFTP exact bytes, cleanup, or clock")
    return BenchmarkSFTP(filePayloadBytes: payload.count, totalPayloadBytes: payload.count * 2,
        prepareHandshakeRoundtripCleanupMilliseconds: elapsed,
        aggregatePayloadMiBPerSecond: 2 / (elapsed / 1_000), exactBytesVerified: true,
        afterLeaseClosed: BenchmarkResources.read())
}

func runBenchmarks(client: TeleportClient, node: TeleportNode) async throws {
    let before = BenchmarkResources.read()
    let identity = try await client.identity()
    guard let login = identity.allowedLogins.first else {
        throw HarnessFailure(description: "Benchmark identity has no OS login")
    }
    let store = MemoryIdentityStore()
    await store.replace(with: identity)
    // A separate public client gives a cold transport without repeating human
    // login or changing the fixture client's authenticated record.
    let measuredClient = TeleportClient(proxy: identity.proxy, identityStore: store)
    do {
        var batches = [BenchmarkBatch]()
        batches.append(try await benchmarkBatch(client: measuredClient, node: node, login: login,
                                                count: 1, proxyState: .cold))
        for count in [1, 10, 25] {
            batches.append(try await benchmarkBatch(client: measuredClient, node: node, login: login,
                                                    count: count, proxyState: .warm))
        }
        let transfer = try await benchmarkTransfer(client: measuredClient, node: node, login: login)
        try await measuredClient.signOut()
        let report = BenchmarkReport(
            schemaVersion: 1, measuredAt: Date().ISO8601Format(),
            system: ProcessInfo.processInfo.operatingSystemVersionString, clock: "ContinuousClock",
            batchMeaning: "All proxy leases are prepared before concurrent SSH commands; no claim of steady authenticated session count",
            memoryMeaning: "Current RSS and process-lifetime peak RSS include the harness, libssh2, and shared event loops",
            fdMeaning: "Snapshots include /dev/fd enumeration and shared event-loop descriptors; pooled connection remains between batches",
            beforeFreshClient: before, batches: batches, sftp: transfer,
            afterSignOutImmediate: BenchmarkResources.read())
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let bytes = try encoder.encode(report)
        if let path = ProcessInfo.processInfo.environment["TELEPORT_BENCHMARK_OUTPUT"], !path.isEmpty {
            try bytes.write(to: URL(fileURLWithPath: path), options: .atomic)
        }
        print(String(decoding: bytes, as: UTF8.self))
    } catch {
        try? await measuredClient.signOut()
        throw error
    }
}
