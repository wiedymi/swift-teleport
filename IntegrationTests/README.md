# Real Teleport test lab

This lab runs a fresh Teleport Community 18.11.4 cluster in Docker. The Swift client runs on the native Apple host. `tctl` is used only for setup. `tsh` runs only the separate infrastructure control checks.

The lab uses one Auth/Proxy service and three Linux nodes. Nodes A and B allow the test user. The denied node has a different label. All nodes have the Unix account `teleport-test`, Bash, core utilities, a writable home, and tmux. Each node connects through a reverse tunnel. No node port is published.

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

The native command receives `TELEPORT_E2E_FIXTURE` and `TELEPORT_E2E_SUITE`. It must fail if a required test cannot run. The wrapper fails when a native suite has no native command. The infrastructure suite is server-fixture coverage. It is not native Swift client coverage.

### Optional browser MFA check

The default lab keeps its password/TOTP policy. `up --browser-mfa` instead enables
TOTP and WebAuthn, sets the test hostname as the WebAuthn RP ID, and permits CLI
browser approval. Test provisioning uses the enrolled user's TOTP to register
one virtual USB security key through the browser's WebAuthn API and the server's
normal device APIs. This browser MFA check uses an existing test device.

Run the public Swift API test from this repository on macOS:

```sh
./IntegrationTests/Scripts/test-e2e.sh --suite browser-mfa -- swift test --filter BrowserMFALiveTests
```

The wrapper removes the lab after the command ends. For a lab kept for inspection,
use `lab.sh up --browser-mfa`, set `TELEPORT_BROWSER_MFA_FIXTURE` to its printed
fixture path, and run the same Swift test. Then remove that run with `lab.sh down`.
Without this environment variable, the live test reports a skip.

The test first requests certificates with password/TOTP. It then uses two shared
browser MFA callers, checks their issued SSH and TLS identity, reads the stored
identity, and signs out. Browser MFA is local WebAuthn authentication; it does
not use the GitHub, OIDC, or SAML browser SSO routes.

Chromium uses a disposable virtual authenticator through its test interface.
It calls the real HTTPS and WebAuthn APIs; it does not test the visual web forms,
a physical key, an Apple passkey, or system browser presentation. The browser
container cannot reach the Mac's `127.0.0.1`. A test-only relay therefore carries
the encrypted callback URL through private files to the Mac listener. It permits
only the loopback callback target, does not follow redirects, and leaves callback
authentication to the library. The browser has only its test credential files and
public HTTPS CA. These files are deleted with the lab and must not be uploaded.

This new mode has **not run against the pinned server**. On 20 October 2026, the
first pinned server image pull showed no progress for five minutes. After that
command stopped, Docker completed the download. The next attempt reached the
pinned Chromium fixture build, but its 233 MB package download did not finish
within the 15-minute limit. Auth startup and enrollment did not run. No version,
TLS check, or system trust setting was changed. Syntax and unit checks do not
establish real browser MFA support. Real-provider SSO remains outside this lab.

### Device credential protocol check

`up --auth-only` starts only the same pinned Auth/Proxy. It does not build
Chromium or SSH nodes. The fixture uses WebAuthn and TOTP, verified HTTPS, and a
new local user invitation. Auth/Proxy runs with the controller's numeric UID
and GID so it can read private `0600` files and write its own `0700` state
directory without extra capabilities. This mode does not run SSH transport
control checks.

On macOS, run the native test with:

```sh
./IntegrationTests/Scripts/test-e2e.sh --suite device-credential -- swift test --filter DeviceCredentialLiveTests
```

The wrapper removes its lab after the command ends. For a lab kept for review,
use `lab.sh up --auth-only`, set `TELEPORT_DEVICE_CREDENTIAL_FIXTURE` to its
printed fixture path, and run the same Swift test. Then remove the run with
`lab.sh down`. Without this variable, the live test reports a skip. Each run
needs a new invitation; do not reuse a fixture after its enrollment completes.

The test uses Apple's Vision QR reader to get the new user's TOTP seed from
Teleport's enrollment API. It verifies password/TOTP certificate login, device
registration through Auth mTLS, a fresh device credential login, certificate
and identity storage checks, and local deletion. An internal test-only software
P-256 key replaces the Secure Enclave. TOTP authorizes registration. These
checks can establish real server protocol support. They do not test Secure
Enclave hardware, Face ID, Touch ID, browser approval for device registration,
or a physical device. Production code does not use the test key.

On 20 October 2026, the auth-only fixture and this native test passed on the
arm64 macOS host with OrbStack 2.2.4 and Docker Engine 29.8.2. Verified HTTPS
discovery and the exact 18.11.4 binary check passed. The native test passed all
its registration, device login, certificate, wrong-password rejection, local
deletion, and retained-identity checks in 61.984 seconds. A final run with a
fresh fixture passed these checks again in 53.174 seconds. The software test
key and TOTP approval limits above still apply.

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
| `identityFile` | Complete short-lived `tctl auth sign --format=file` identity path; absent from the auth-only fixture |
| `localCredentialsFile` | Restricted username, fresh password, and TOTP seed file path; present only after enrollment |
| `nodes` | Node name, actual resource ID, and expected authorization |
| `policy` | Expected local authentication, TOTP, and TLS routing policy |
| `browserMFA` | `true` only for the optional WebAuthn fixture |
| `authOnly` | `true` only for the native authentication fixture; no SSH nodes or control checks |
| `enrollmentInvitationFile` | Private invitation token file, present only for the auth-only fixture |

Only the `client` directory belongs in the native SSH harness's inputs. The optional browser MFA test also uses the lab-owned browser helper directory. Both contain private user material and must stay private. Neither has server signing keys, an administrative identity, or server state. Do not upload them as CI artifacts.

The full identity export keeps all user key/certificate bindings together. Its private key algorithm is the server default; it is not a fixed RSA fixture. A native login suite must ignore that file, read only the local credentials and public HTTPS CA, and obtain fresh certificates through the package.

## Checks and bounds

Readiness requires `teleport debug readyz`, verified HTTPS discovery, the locked server patch, the selected local MFA policy, TLS multiplexing, and all three registered node IDs. The selected 18.11.4 binary returns `ready (PID:...)` from the debug command. A running container alone is insufficient.

The official-client control checks exact successful command stdout and stderr on A and B, remote exit status 23, a real Unix PTY with exact `37 91` size output, a tmux session, server authorization denial with no marker on the denied node, no direct TCP 3022 listener, failed direct connections from the node network, and failed access while node A is stopped. It restarts node A and waits for readiness before returning the fixture. The PTY control changes size inside the remote shell; the native client suite must test the SSH resize request separately.

Each run has its own project name, state volumes, credentials, HTTPS CA, and port. Ports are selected from 18443 through 18543. A demonstrated bind collision is retried at most three times. Setup, readiness, external commands, and teardown have deadlines. Containers have CPU, memory, process, and log limits. No privileged mode, Docker socket mount, host network, PAM, or enhanced session recording is used.

Each node permits at most 512 processes. The earlier 128 limit caused a real `fork/exec /bin/bash` resource error during the ten-connection batch. At 512 processes, the 384 MiB node memory cap caused a measured out-of-memory termination during that batch. A 1 GiB cap passed, but peak memory reached 1,067,429,888 bytes, with only about 6 MiB free. The reusable fixture therefore permits 1536 MiB per node and preserves the prior 384 MiB swap allowance. The CPU limit stays at 0.5 CPU per node. The successful measured run reached 325 processes and recorded no further out-of-memory event.

The node process allows CHOWN for PTY ownership, KILL to stop sessions under the test user, and SETGID/SETUID for Unix identity changes. It does not have SYS_ADMIN or SYS_CHROOT. Auth/Proxy drops all capabilities. The disposable browser drops all capabilities and uses the Chromium sandbox exception needed for its root container; it has only public HTTPS trust and one new user's invitation, and no server volume or Docker access.

## Pins and evidence

[`Docker/versions.lock.json`](Docker/versions.lock.json) records official registry manifest hashes, both native platform manifests, a Debian snapshot, and the enrollment tool version. Server inputs come from [Teleport's official registry](https://gallery.ecr.aws/gravitational/teleport-distroless). Debian packages use a fixed signed archive snapshot. The enrollment npm lock records package integrity. No image tag is used as the server trust pin.

The controller loads missing base images into the Docker engine by their exact digest before BuildKit builds the fixtures. This avoids a registry metadata error observed with a fresh OrbStack image store. Cached base images are reused without a separate pull. The node and browser builds can run in parallel.

The 18.11.4 image was obtained from the registry and reports `Teleport v18.11.4 git:v18.11.4-0-g34583b39 go1.26.8`. The public source tag was unavailable during this review. Do not treat a different public source snapshot as the exact server source.

A run's small `report.json` contains only the server version, platform, and named infrastructure checks. The controller does not print raw enrollment errors, credentials, administrative output, or server logs. Keep any result summary you need before teardown. Server state and raw logs must not become build artifacts.

If initial Auth readiness fails before any user or node token is created, the controller reports only container status, numeric bind ownership and modes, and a fixed permission-failure classification. It never prints the server log text.

The lab is one reusable server fixture. A consuming app can use its manifest at a selected package revision. Keep the server fixture here rather than duplicating the Compose stack. Native functional, fault, performance, and device checks belong to the consuming app; the server control suite does not replace them.

The native SSH harness requires a compatible external upstream libssh2 build.
See [the engine contract](../docs/SSH-ENGINE.md) for its inputs. This repository
does not download or build that engine.

## Local validation

On 20 October 2026, two independent full runs completed real browser enrollment and the infrastructure control checks on Apple M5 Max hardware, macOS 27.2, and a native arm64 Colima 0.10.3 VM (4 CPUs, 4 GiB RAM). Docker Engine was 29.5.2 and Compose was 5.6.0. A separate PTY/tmux check passed with the four listed node capabilities. One full run was removed twice; its local secrets and all of its Docker containers, volumes, and networks were absent after teardown.

The default test wrapper also runs this same control suite and removes its own run. Earlier Linux workflow attempts failed on ECR download limits. The latest attempt built the images, then failed at Auth readiness: the server process could not read the private config owned by the runner UID. Its safe diagnostics confirmed that access failure. File modes were not loosened; Linux ownership still needs a fix and a real rerun. AMD64 execution and physical devices are not established by the historical local results. Native Swift results are recorded separately.

A new full run also passed on OrbStack 2.2.4 with Docker Engine 29.8.2, using the same locked images. It completed real browser enrollment and all eight infrastructure checks. A separate OpenSSL probe used the native login identity to complete verified Auth mTLS with SNI `teleport.cluster.local` and negotiated `h2`. The earlier task Colima VM, its disk, and its test runs were removed when the runtime changed to OrbStack.

The [native Apple test app](../docs/apple-smoke-results.txt) also passed on the arm64 iPhone Duo Simulator with iOS 27.1 against that OrbStack run. It used fresh password/TOTP login through the public package API and rejected a wrong HTTPS CA. Its SSH command, live PTY resize, 256 KiB SFTP, and local sign-out checks passed. The app, private config, and its exact default DerivedData directory were removed after the result was saved. No physical device or browser SSO test was run.

The recorded native app and benchmark runs used a temporary libssh2 1.11.1
engine with local changes. Those changes are removed. The records do not
validate a new upstream engine.

The final [native benchmark](../docs/benchmark-results.json) passed at the 1536 MiB node cap, including 1, 10, and 25 concurrent connections and an exact 1 MiB SFTP round trip. Final teardown verified zero containers, volumes, images, and build cache records in the fresh task runtime. The run directory and secrets were removed. OrbStack reported no Linux machines and was stopped normally; the app and normal Docker setup remain installed.
