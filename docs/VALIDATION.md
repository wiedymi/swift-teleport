# Validation

Date: 20 October 2026. These are local checks.

The records below distinguish package tests, SSH engine tests, server controls,
and native app tests. A server control result is not a Swift client result.

| Check | Observed result |
| --- | --- |
| macOS package unit/fault tests | 33 tests passed (9 auth, 14 transport/trust/FD, 10 certificate/configuration/parser) |
| macOS release package build | Passed |
| iOS package build | Passed, default Xcode output path |
| iOS Simulator package tests | 29 tests passed on iPhone Duo, iOS 27.1 |
| Local libssh2 engine matrix | 34 checks passed; exact OpenSSL 3.2.0 headers and VVTerm archives |
| C adapter bounds and FD cleanup | 8 checks passed |
| Patched engine platform builds | macOS arm64 13.3, iOS arm64 16.1, iOS Simulator arm64 16.1 |
| Teleport server infrastructure | Local/TOTP enrollment, two allowed nodes, denied node, PTY/tmux, reverse-tunnel outage, no direct SSH route passed |
| Native public password/TOTP login | Passed against Teleport 18.11.4; both issued certificate chains and identity record checked |
| Native node/SSH path | Full fresh-login public-API run passed on OrbStack; both nodes, PTY resize, 256 KiB SFTP, concurrent streams, denials, and sign-out |
| Native benchmark | Release cold/warm 1/10/25 prepared leases and verified 1 MiB SFTP round trip passed |
| AppleSmoke simulator | Full live run passed; includes wrong HTTPS CA rejection |
| Browser provider sign-in | Pending a permitted provider fixture |

The first native login and server controls ran in a temporary Colima runtime.
That VM, its containers, and its credentials were removed when the user selected
OrbStack. OrbStack is installed under the user's approved setup; new live checks
use it. No old fixture is treated as a result for the new runtime.
The final server controls also passed on OrbStack.

The redacted records are [native-e2e-results.txt](native-e2e-results.txt) and
[apple-smoke-results.txt](apple-smoke-results.txt). The native run uses the same
public package API as a consuming app. The simulator app includes one ATS domain
setting for its private test HTTPS CA; certificate validation stays active and
the wrong-CA check fails as required.

The measured baseline and its limits are in [the benchmark notes](../Benchmarks/README.md)
and [raw samples](benchmark-results.json). It includes resource snapshots and
short concurrent commands. Interactive echo latency, CPU/allocation profiles,
idle wakeups, impaired-network runs, and a same-route reference comparison
remain separate performance checks. No performance budget is claimed.

The local SSH report is [ssh-engine-results.json](ssh-engine-results.json).
It proves host/user certificate handling, command execution, PTY resize, SFTP,
bad signatures, expiry, login denial, and failure cleanup on the test engine.
Platform archive builds alone do not prove a device session.

The final transport checks cover exact TLS route order and the long-lived private
PKI certificates issued by Teleport. They retain CA, name, usage, signature, and
time checks. The host SSH parser accepts the exact OpenSSH no-expiry value;
the user identity still expires at its earliest applicable certificate limit.
Physical-device execution was excluded at the user's request.

The Community server uses fixed GitHub SSO endpoints. A local OIDC provider needs
a permitted Enterprise setup. The package browser code has real loopback,
encrypted-payload, tamper, cancellation, and stale-input tests. Those tests do not
establish a real provider sign-in, sandboxed Mac presentation, or physical-device
background/foreground behavior.

Only the current pinned server patch and native arm64 lab are verified here.
Other v18 patches, v17, FIPS, AMD64 execution, impaired-network performance, and
provider/device combinations need their own evidence before a release claim.

Local builds used Xcode 27.1 and Swift 6.4. The Apple CI workflow selects Xcode
26.3 with Swift 6.2.3 for the resolved dependency graph. Remote results are
tracked in the repository's GitHub Actions runs.

References were absent during every package build. There is no `.gitmodules`,
Git link, mandatory reference clone, or recursive-fetch step in this repository.

After testing, all lab containers, volumes, networks, task images, build cache,
credentials, and temporary SSH archives were removed. The simulator test app,
task DerivedData, SwiftPM build directories, and temporary logs were removed.
OrbStack is stopped and remains installed. Colima and Lima were removed.
The source repository is below 1 MiB. Repeated lab teardown returned success.

Before the first push, an independent security review covered all 106 source,
configuration, test, license, and documentation files. It found no confirmed
security vulnerability. Two review changes make native callback object lifetimes
explicit and defer the lab's exported test identity until the enrollment browser
exits. The browser can then read only the public CA and its invitation during
startup. Python and shell syntax, the seven-package SBOM, and absent optional
references were checked again.

The 20 October 2026 follow-up checked published repository advisories for all
seven locked Swift dependencies. No listed affected range included the locked
versions. SwiftNIO 2.104.0 exceeds the latest listed fix, 2.101.0
([upstream advisory](https://github.com/apple/swift-nio/security/advisories/GHSA-qcc5-f287-vgmq));
SwiftNIO HTTP/2 1.46.0 exceeds its latest listed fix, 1.45.0
([upstream advisory](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-q3g2-m552-3r9c)).
The enrollment npm lock audit reported zero known vulnerabilities. These checks
cover published source dependency reports, not every test image or local crypto
archive. The package ships neither test images nor those archives.

After the review changes, the 33 macOS tests and the Release package build
passed again. All three patched SSH engine archives rebuilt, including the
failed-key-exchange cleanup check. The native Release harness and the Release
iOS Simulator smoke app both built. The full live macOS/Simulator session records
above were produced before these two test-tool changes; they were not rerun for
this review.
