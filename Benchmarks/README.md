# Native SSH benchmarks

Supply the external engine required by [TeleportE2E](../docs/SSH-ENGINE.md), then
run its `benchmark` mode with the pinned lab:

```sh
TELEPORT_BENCHMARK_OUTPUT=/path/to/report.json \
  ./IntegrationTests/Scripts/test-e2e.sh --suite full -- /path/to/TeleportE2E benchmark
```

The report contains timings and resource counts, without credentials or node IDs.
The wrapper removes the lab. Remove the report and task build files after review.

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

Earlier samples used a removed, locally changed SSH engine. They do not validate
the current upstream engine or define a performance budget. See
[current test limits](../docs/VALIDATION.md).
