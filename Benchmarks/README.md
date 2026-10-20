# Native SSH benchmarks

Run the optional `TeleportE2E` executable with `benchmark` after starting the
versioned Docker lab. Use the same fixture and native login as the functional
suite. Set `TELEPORT_BENCHMARK_OUTPUT` to save the public JSON report. The report
contains timings and resource counts, with no credentials or node identifiers.

The benchmark creates a fresh public client with the already validated identity.
Its first ProxySSH preparation is cold. It then measures warm batches of 1, 10,
and 25 prepared connections. All connections in a batch remain open until
preparation finishes, then SSH commands run concurrently and verify exact
per-command output. A prepared connection is a live proxy tunnel. These short
commands do not establish 25 steady authenticated SSH sessions.

Measurements use `ContinuousClock`:

| JSON metric | Included work |
| --- | --- |
| `proxyPrepareMilliseconds` | Cold or pooled TLS/HTTP2 access, node route, and first cluster response |
| `sshHandshakeAuthCommandCleanupMilliseconds` | Test executor wait, SSH KEX, CA verification, user-certificate auth, command, output, native SSH cleanup |
| `preparePlusSSHMilliseconds` | Sum of each connection's two measurements; excludes its deliberate wait for the other prepared connections |
| `batchWallMilliseconds` | All sequential preparation, concurrent commands, and public lease close calls |
| `prepareHandshakeRoundtripCleanupMilliseconds` | Warm ProxySSH preparation, SSH setup, SFTP create/write/read/compare/remove, and lease cleanup |

The SFTP test writes a 1 MiB payload, reads it back, checks every byte, and removes
the remote file. Its aggregate payload throughput counts 2 MiB transferred.
This measurement includes handshake and file operations. It is not a bulk-only
transport rate or an interactive echo measurement.

Each batch records current resident memory and open descriptors before
preparation, after all leases are prepared, and after their close calls finish.
Peak resident memory is the operating system's process-lifetime value. It
includes the C harness output buffers, SSH engine, and shared NIO event loops.
The proxy pool remains active between batches. The final snapshot is immediate
after sign-out; asynchronous operating-system cleanup may still be pending.
Descriptor counts include the directory used to enumerate `/dev/fd`.

Percentiles use nearest-rank selection. Small batches, especially one sample,
do not establish reliable tail latency. The report supplies raw samples.
No latency, throughput, or memory budget is inferred from a missing baseline.
Impaired-network comparison, idle wakeups, CPU, allocation counts, and a
same-route reference client require separate measurements.

## Recorded local baseline: 20 October 2026

Full samples are in [benchmark-results.json](../docs/benchmark-results.json).
The native client used a Release build on Apple M5 Max, macOS 27.2, and Swift 6.4.
OrbStack 2.2.4 ran the pinned arm64 Teleport 18.11.4 server.
The node had 0.5 CPU, 1536 MiB memory, 384 MiB allowed swap, and 512 process slots.
Auth/Proxy had 1 CPU, 768 MiB memory, and 128 process slots.
These server limits affect SSH process startup. The client and server run on the same Mac.

| Proxy state | Prepared leases | Proxy prepare p50, ms | SSH setup/command/cleanup p50, ms | SSH p95, ms |
| --- | ---: | ---: | ---: | ---: |
| cold | 1 | 48.24 | 186.79 | 186.79 |
| warm | 1 | 2.85 | 183.90 | 183.90 |
| warm | 10 | 1.79 | 4780.65 | 5074.07 |
| warm | 25 | 2.37 | 10941.37 | 11943.54 |

Every warm batch returned to 25 open descriptors after its leases closed.
The 25-lease batch reached 75 descriptors while prepared. Sign-out reduced the
count to 24; shared NIO event-loop descriptors remain for the process lifetime.
Client process peak RSS was 88.36 MiB, including the test harness and SSH engine.
The verified 1 MiB SFTP round trip reported 3.18 MiB/s aggregate payload, including setup and cleanup.
This is one baseline with short commands, not a steady terminal-session or bulk-only throughput result.
