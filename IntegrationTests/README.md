# Real Teleport test lab

This lab runs a pinned Teleport Community 18.11.4 cluster in Docker. The Swift
client runs on the Apple host. `tctl` handles setup; `tsh` runs separate server
control checks.

The default fixture has one Auth/Proxy and three reverse-tunnel nodes. Nodes A
and B allow `teleport-test`; a differently labeled node denies that user. Nodes
have Bash, core utilities, a writable home, and tmux. No node port is published.
The smaller auth-only fixture has no nodes or browser container.

## Before use

Install Docker Engine with Compose, Python 3.9+, and OpenSSL. Use a native
`linux/arm64` or `linux/amd64` runtime with at least 4 CPUs and 8 GiB RAM. Initial
builds can use several GiB of temporary disk. The controller records the Docker
context for each run. AMD64 execution remains unverified.

`teleport.localhost` must resolve to loopback on the host. Docker resolves it to
the proxy in the private test network. If needed, use `--host` with an existing
local DNS or hosts entry. Tests do not change system DNS.

The server has separate [Community distribution terms](https://goteleport.com/blog/teleport-community-license/).
Build test images locally; do not publish them or include them in an app. The lab
does not install or reset a trial license. It has no SSO provider. OIDC and SAML
need a separate permitted Enterprise setup.

## Commands

```sh
./IntegrationTests/Scripts/lab.sh preflight
./IntegrationTests/Scripts/lab.sh up
./IntegrationTests/Scripts/lab.sh status --run-id teleport-e2e-012345abcdef
./IntegrationTests/Scripts/lab.sh control --run-id teleport-e2e-012345abcdef
./IntegrationTests/Scripts/lab.sh down --run-id teleport-e2e-012345abcdef
./IntegrationTests/Scripts/lab.sh clean-stale
```

`up` prints the fixture path and leaves the lab running. `down` removes that run's
containers, volumes, helpers, and secrets; repeated calls are safe. After an
abrupt stop, `clean-stale` removes runs older than two hours. No command runs
global Docker cleanup.

`up --without-enrollment` creates a transport-only fixture. The default uses
disposable Chromium for real password/TOTP enrollment. It reads Teleport's QR
data, imports the test HTTPS CA into its own trust store, and destroys its session
before native login. This checks enrollment APIs, not visual forms.

The test wrapper always removes its lab:

```sh
./IntegrationTests/Scripts/test-e2e.sh --suite infrastructure
./IntegrationTests/Scripts/test-e2e.sh --suite transport -- /path/to/native-harness
./IntegrationTests/Scripts/test-e2e.sh --suite login -- /path/to/native-harness
./IntegrationTests/Scripts/test-e2e.sh --suite full -- /path/to/native-harness
```

Native commands receive `TELEPORT_E2E_FIXTURE` and `TELEPORT_E2E_SUITE`. They must
fail if a required check cannot run. All native suites require a command after
`--`. The infrastructure suite checks the server fixture, not the Swift client.

### Optional browser MFA check

`up --browser-mfa` enables TOTP, WebAuthn, and CLI browser approval. It uses the
test hostname as the RP ID and registers a virtual security key with TOTP through
the normal device APIs.

Run the public Swift API test from this repository on macOS:

```sh
./IntegrationTests/Scripts/test-e2e.sh --suite browser-mfa -- swift test --filter BrowserMFALiveTests
```

The wrapper removes the lab after the command ends. For a lab kept for inspection,
use `lab.sh up --browser-mfa`, set `TELEPORT_BROWSER_MFA_FIXTURE` to its printed
fixture path, and run the same Swift test. Then remove that run with `lab.sh down`.
Without this environment variable, the live test reports a skip.

The test checks password/TOTP, two callers sharing browser MFA, issued SSH/TLS
identity, storage, and sign-out. It uses local WebAuthn, not browser SSO.

Chromium uses a virtual authenticator. A private-file relay carries the encrypted
callback to the host loopback listener. It permits only that target, rejects
redirects, and leaves callback authentication to the library. The browser has
only test credentials and the public HTTPS CA. Never upload these files.

This mode has **not passed against the pinned server**. It does not establish
visual forms, physical keys, Apple passkeys, or system browser presentation.
Real-provider SSO is outside this lab. See [Validation](../docs/VALIDATION.md).

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

The native test passed password/TOTP enrollment and login, Auth mTLS registration,
device credential login, certificate validation, wrong-password rejection, local
deletion, and identity preservation. Apple's Vision reads Teleport's TOTP QR code;
an injected software P-256 key replaces the Secure Enclave. TOTP approves setup.
This is server-protocol evidence, not Secure Enclave, biometric, browser setup,
or physical-device evidence. Production has no software-key fallback.

The proxy binds only `127.0.0.1`. Native macOS and iOS Simulator clients receive
the public HTTPS CA through `TeleportProxy`. Physical devices need a separate
reachable environment.

The [Apple test app](../Examples/AppleSmoke/README.md) has an ATS setting for
manual private-CA trust at `teleport.localhost`. HTTPS, CA, hostname, and date
checks stay active. Public CA proxies need no such setting. See Apple's
[manual trust documentation](https://developer.apple.com/documentation/Foundation/performing-manual-server-trust-authentication).

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

Give the native SSH harness only the `client` directory. Browser MFA also uses
the browser helper directory. Both contain private user data, but no server keys,
administrative identity, or server state. Do not upload either as CI artifacts.

The exported identity uses the server's default key algorithm. Native login tests
must ignore it and obtain fresh certificates using local credentials and the
public HTTPS CA.

## Checks and bounds

Readiness checks `teleport debug readyz`, verified HTTPS discovery, server patch,
MFA policy, TLS multiplexing, and registered nodes when present. A running
container alone is insufficient.

The `tsh` control checks commands/output, exit status, PTY, tmux, denied-node
authorization, blocked direct SSH, and reverse-tunnel outage. It restarts node A
and waits for readiness. Its PTY check changes size inside the shell; native
clients must test the SSH resize request separately.

Each run has separate state, credentials, HTTPS CA, and a port from 18443–18543.
A bind collision permits at most three retries. Commands have deadlines, and
containers have CPU, memory, process, and log limits. No privileged mode, Docker
socket mount, host network, PAM, or enhanced session recording is used. See
[Compose limits](Docker/compose.yaml).

Nodes allow only CHOWN, KILL, SETGID, and SETUID for SSH sessions. Auth/Proxy and
Chromium drop all capabilities. Chromium uses the sandbox exception for its root
container and has no server volume or Docker access.

## Pins and evidence

[`Docker/versions.lock.json`](Docker/versions.lock.json) pins registry manifests,
platform images, Debian snapshot, and enrollment tools. Server images come from
[Teleport's official registry](https://gallery.ecr.aws/gravitational/teleport-distroless).
Debian uses a signed snapshot; npm records package integrity. Image tags are not
trust pins. See [protocol provenance](../docs/PROVENANCE.md) for source inputs.

The controller loads missing base images by digest before building fixtures and
reuses cached images. Node and browser builds can run in parallel.

A run's `report.json` contains only version, platform, and named server checks.
The controller does not print credentials, raw enrollment errors, administrative
output, or server logs. Review the report before teardown. Never upload server
state or raw logs as build artifacts.

Before user/node tokens exist, readiness failures report only container status,
bind ownership/modes, and a fixed permission classification, never server logs.

Reuse this fixture by package revision instead of duplicating its Compose stack.
Server controls do not replace native functional, fault, performance, or device
checks.

The native SSH harness requires a compatible external upstream libssh2 build.
See [the engine contract](../docs/SSH-ENGINE.md) for its inputs. This repository
does not download or build that engine.

## Test limits

The auth-only native software-key test passed. Browser MFA, real-provider SSO,
Secure Enclave hardware, physical devices, and AMD64 execution remain unverified.
Earlier SSH results used a removed, locally changed engine; upstream libssh2
needs a fresh real-server run.

The default Linux fixture has an open private-config ownership failure: Auth
cannot read the runner-owned `0600` config. Its permissions must stay private;
the ownership fix still needs a real rerun. The auth-only mode uses the host's
numeric UID/GID and does not fix the default fixture.

See [Validation](../docs/VALIDATION.md) for the current results and limits.
