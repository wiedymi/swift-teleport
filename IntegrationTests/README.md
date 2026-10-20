# Real Teleport test lab

This lab runs a fresh Teleport Community 18.11.4 cluster in Docker. The Swift client runs on the native Apple host. `tctl` is used only for setup. `tsh` runs only the separate infrastructure control checks.

The lab uses one Auth/Proxy service and three Linux nodes. Nodes A and B allow the test user. The denied node has a different label. All nodes have the Unix account `vvterm-test`, Bash, core utilities, a writable home, and tmux. Each node connects through a reverse tunnel. No node port is published.

## Before use

Install Docker Engine with Compose and a native `linux/arm64` or `linux/amd64` runtime. Use OrbStack on this Mac. Also install Python 3.9 or later and OpenSSL on the controller host. Allow at least 4 CPUs and 8 GiB RAM for the runtime, including all service caps and system memory. A complete initial image build can use several GiB of temporary disk. The controller records the selected Docker context for each run.

The default name is `teleport.localhost`. It must resolve to loopback on the native host. The controller checks this requirement. Docker resolves the same name to the proxy in that run's private network. If the host does not resolve this name, use `--host` with an explicit local DNS or hosts entry. Tests do not change system DNS.

Review the [Community distribution terms](https://goteleport.com/blog/teleport-community-license/) for your operator and CI use. The official server distribution has separate terms from this Swift package. The node image contains the official server binary. Build it locally for tests; do not publish it or put it in an app. The lab does not install or reset a trial license. OIDC and SAML checks need a separate licensed Enterprise setup. No SSO provider is included in this baseline.

## Commands

```sh
./IntegrationTests/Scripts/lab.sh preflight
./IntegrationTests/Scripts/lab.sh up
./IntegrationTests/Scripts/lab.sh status --run-id teleport-e2e-012345abcdef
./IntegrationTests/Scripts/lab.sh control --run-id teleport-e2e-012345abcdef
./IntegrationTests/Scripts/lab.sh down --run-id teleport-e2e-012345abcdef
./IntegrationTests/Scripts/lab.sh clean-stale
```

`up` prints only the client fixture path on stdout. It keeps the lab for native client or manual app tests. `down` deletes that run's containers, named volumes, and local secrets. It also removes project-owned runtime helpers that Compose does not track. It is safe to repeat. `clean-stale` deletes lab-owned runs whose two-hour lease has expired. Run it after an abrupt host or process stop. No command runs global Docker cleanup.

Use `up --without-enrollment` for a transport-only fixture. Its report explicitly excludes local login. The full default completes real password/TOTP enrollment with a disposable Chromium process. Chromium imports the per-run HTTPS CA into its own NSS trust database. It performs the actual web enrollment requests. It reads the machine-readable QR data returned by Teleport to get the new user's TOTP seed. It uses no image text recognition or Auth database access. The browser's session is destroyed before the native login suite starts. This proves enrollment API behavior; it does not test the visual enrollment form.

The test wrapper always removes its lab:

```sh
./IntegrationTests/Scripts/test-e2e.sh --suite infrastructure
./IntegrationTests/Scripts/test-e2e.sh --suite transport -- /path/to/native-harness
./IntegrationTests/Scripts/test-e2e.sh --suite login -- /path/to/native-harness
./IntegrationTests/Scripts/test-e2e.sh --suite full -- /path/to/native-harness
```

The native command receives `TELEPORT_E2E_FIXTURE` and `TELEPORT_E2E_SUITE`. It must fail if a required test cannot run. The wrapper fails when a native suite has no native command. The infrastructure suite is server-fixture coverage. It is not Swift or VVTerm coverage.

The proxy binds only `127.0.0.1`. The macOS and iOS Simulator clients use this same fixture and receive its public HTTPS CA through `TeleportProxy`. No system trust change is needed. Physical device tests need a separate reachable test environment and are outside this local run.

The [Apple test app](../Examples/AppleSmoke/README.md) has the exact-domain ATS setting that Apple requires for URLSession manual private-CA trust. It applies only to `teleport.localhost`; the package still validates HTTPS, CA, hostname, and certificate dates. Public CA proxies do not need it. See Apple's [manual trust documentation](https://developer.apple.com/documentation/Foundation/performing-manual-server-trust-authentication).

## Client fixture

`client/fixture.json` has these fields:

| Field | Value |
| --- | --- |
| `schemaVersion` | `1` |
| `proxyURL` | HTTPS proxy endpoint |
| `clusterName` | Actual isolated cluster name |
| `serverVersion` | Verified server patch |
| `httpsCAFile` | Public HTTPS CA PEM file path |
| `identityFile` | Complete short-lived `tctl auth sign --format=file` identity path |
| `localCredentialsFile` | Restricted username, fresh password, and TOTP seed file path; present only after enrollment |
| `nodes` | Node name, actual resource ID, and expected authorization |
| `policy` | Expected local authentication, TOTP, and TLS routing policy |

Only the `client` directory belongs in the native harness's inputs. It contains private user material and must stay private. It has no server signing keys, invitation tokens, administrative identity, or server state. Do not upload it as a CI artifact.

The full identity export keeps all user key/certificate bindings together. Its private key algorithm is the server default; it is not a fixed RSA fixture. A native login suite must ignore that file, read only the local credentials and public HTTPS CA, and obtain fresh certificates through the package.

## Checks and bounds

Readiness requires `teleport debug readyz`, verified HTTPS discovery, the locked server patch, local/TOTP policy, TLS multiplexing, and all three registered node IDs. The selected 18.11.4 binary returns `ready (PID:...)` from the debug command. A running container alone is insufficient.

The official-client control checks exact successful command stdout and stderr on A and B, remote exit status 23, a real Unix PTY with exact `37 91` size output, a tmux session, server authorization denial with no marker on the denied node, no direct TCP 3022 listener, failed direct connections from the node network, and failed access while node A is stopped. It restarts node A and waits for readiness before returning the fixture. The PTY control changes size inside the remote shell; the native client suite must test the SSH resize request separately.

Each run has its own project name, state volumes, credentials, HTTPS CA, and port. Ports are selected from 18443 through 18543. A demonstrated bind collision is retried at most three times. Setup, readiness, external commands, and teardown have deadlines. Containers have CPU, memory, process, and log limits. No privileged mode, Docker socket mount, host network, PAM, or enhanced session recording is used.

Each node permits at most 512 processes. The earlier 128 limit caused a real `fork/exec /bin/bash` resource error during the ten-connection batch. At 512 processes, the 384 MiB node memory cap caused a measured out-of-memory termination during that batch. A 1 GiB cap passed, but peak memory reached 1,067,429,888 bytes, with only about 6 MiB free. The reusable fixture therefore permits 1536 MiB per node and preserves the prior 384 MiB swap allowance. The CPU limit stays at 0.5 CPU per node. The successful measured run reached 325 processes and recorded no further out-of-memory event.

The node process allows CHOWN for PTY ownership, KILL to stop sessions under the test user, and SETGID/SETUID for Unix identity changes. It does not have SYS_ADMIN or SYS_CHROOT. Auth/Proxy drops all capabilities. The disposable browser drops all capabilities and uses the Chromium sandbox exception needed for its root container; it has only public HTTPS trust and one new user's invitation, and no server volume or Docker access.

## Pins and evidence

[`Docker/versions.lock.json`](Docker/versions.lock.json) records official registry manifest hashes, both native platform manifests, a Debian snapshot, and the enrollment tool version. Server inputs come from [Teleport's official registry](https://gallery.ecr.aws/gravitational/teleport-distroless). Debian packages use a fixed signed archive snapshot. The enrollment npm lock records package integrity. No image tag is used as the server trust pin.

The controller loads missing base images into the Docker engine by their exact digest before BuildKit builds the fixtures. This avoids a registry metadata error observed with a fresh OrbStack image store. Cached base images are reused without a separate pull. The node and browser builds can run in parallel.

The 18.11.4 image was obtained from the registry and reports `Teleport v18.11.4 git:v18.11.4-0-g34583b39 go1.26.8`. The public source tag was unavailable during this review. Do not treat a different public source snapshot as the exact server source.

A run's small `report.json` contains only the server version, platform, and named infrastructure checks. The controller does not print raw enrollment errors, credentials, administrative output, or server logs. Keep any result summary you need before teardown. Server state and raw logs must not become build artifacts.

The lab is one reusable server fixture. VVTerm should consume its manifest at the selected package revision. Do not make a second Compose stack in the app repository. See the [Linear E2E plan](https://linear.app/vivytech/document/teleport-docker-e2e-test-plan-2026-10-16-8434dd2ea251) for the separate native functional, fault, performance, and device release checks.

## Local validation

On 20 October 2026, two independent full runs completed real browser enrollment and the infrastructure control checks on Apple M5 Max hardware, macOS 27.2, and a native arm64 Colima 0.10.3 VM (4 CPUs, 4 GiB RAM). Docker Engine was 29.5.2 and Compose was 5.6.0. A separate PTY/tmux check passed with the four listed node capabilities. One full run was removed twice; its local secrets and all of its Docker containers, volumes, and networks were absent after teardown.

The default test wrapper also runs this same control suite and removes its own run. The Linux workflow is provided but has not been executed remotely. AMD64 registry manifests were checked; AMD64 execution and physical devices have not been tested in this local validation. These results establish the server fixture only. Native Swift results are recorded separately.

A new full run also passed on OrbStack 2.2.4 with Docker Engine 29.8.2, using the same locked images. It completed real browser enrollment and all eight infrastructure checks. A separate OpenSSL probe used the native login identity to complete verified Auth mTLS with SNI `teleport.cluster.local` and negotiated `h2`. The earlier task Colima VM, its disk, and its test runs were removed when the runtime changed to OrbStack.

The [native Apple test app](../docs/apple-smoke-results.txt) also passed on the arm64 iPhone Duo Simulator with iOS 27.1 against that OrbStack run. It used fresh password/TOTP login through the public package API and rejected a wrong HTTPS CA. Its SSH command, live PTY resize, 256 KiB SFTP, and local sign-out checks passed. The app, private config, and its exact default DerivedData directory were removed after the result was saved. No physical device or browser SSO test was run.

The final [native benchmark](../docs/benchmark-results.json) passed at the 1536 MiB node cap, including 1, 10, and 25 concurrent connections and an exact 1 MiB SFTP round trip. Final teardown verified zero containers, volumes, images, and build cache records in the fresh task runtime. The run directory and secrets were removed. OrbStack reported no Linux machines and was stopped normally; the app and normal Docker setup remain installed.
