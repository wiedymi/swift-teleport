# Validation

Date: 20 October 2026. Results below distinguish local tests, real server traffic,
Apple CI, and hardware checks. A build or mock test does not prove device support.

## Readability review

- `swift test`: 71 passed; both live-server tests skipped without a fixture.
- `swift build -c release`: passed.
- iOS Release package build: passed with default Derived Data and code signing disabled.
- Registration now maps protobuf directly to typed options. Existing tests still
  cover policy, account/RP/key binding, callbacks, storage, and cancellation.
- A new unary test checks rejection of two replies in one frame or separate frames.
  It passed before and after removing the temporary message array.
- Guide links, heading anchors, code blocks, wording, diff checks, and absent
  optional references passed.

This review changes no public API. Real-server and hardware checks were not
repeated; the earlier results below retain their stated limits.

## Secure Enclave MFA change

The protocol was checked before implementation against the pinned source. Setup
uses Auth mTLS with fresh `MANAGE_DEVICES` approval. Login uses the public WebAuthn
endpoints. The lab uses the exact Teleport Community 18.11.4 arm64 image digest.
No production dependency was added.

| Check | Result |
| --- | --- |
| Full package run with a fresh auth-only fixture | 70 passed; one browser live test skipped |
| Native server registration/login test | Passed in 53.174 seconds |
| Operation tests after moving identity loading inside exclusive setup | All three passed |
| macOS release and iOS package builds | Passed in default build locations |
| Python lab checks | Five passed; shell syntax and diff checks also passed |
| Apple CI at `670d819` | [Passed](https://github.com/wiedymi/swift-teleport/actions/runs/39442239346) |

The real-server test used an injected software P-256 key and memory storage.
It covered password/TOTP login, WebAuthn registration/login, a fresh RSA key for
SSH/TLS certificates, complete identity validation, wrong-password HTTP 403,
local deletion, missing-credential failure, and identity preservation after
failures. HTTPS verification and Auth mTLS stayed active. Production has no
software-key fallback. This auth-only fixture has no SSH nodes or transport control.

Unit tests cover signatures; account/RP/cluster/key binding; server acknowledgment;
unsupported policies; cancellation; storage failures; operation exclusion; and
sign-out. A loopback test checks fresh browser management scope and callback
mapping. Existing password/TOTP and SSO callback checks remain in the suite.

Still unverified:

- Secure Enclave key use and signed Data Protection Keychain access.
- Face ID/Touch ID prompts, cancellation, lockout, restart persistence,
  biometric-set changes, and physical-device recovery.
- Real browser management approval and real provider SSO.

Linux infrastructure CI is separate. At `670d819`, the UID 0 server could not read
the private config owned by runner UID 1001. At `ade6ae3`, an image pull failed with
`toomanyrequests: Data limit exceeded`. Neither run reached readiness. Permissions
were not loosened. The local auth-only fixture uses the host UID and passed.

See [authentication choices](AUTHENTICATION.md#optional-secure-enclave-mfa) and
[app settings and recovery](INTEGRATION.md#optional-biometric-device-credential).

## Earlier local browser MFA change

At `dd0ee2c`, 45 package tests passed and one live browser test was skipped.
Release and iOS builds passed, as did Apple CI. The twelve new tests covered
challenge/assertion checks, callback authentication, cancellation, timeout, input
bounds, shared login, failed storage, and certificate/account/root/key binding.
Three mock certificate tests used the existing OpenSSL 3 installation; they skip
when it is absent. Lab syntax and absent-reference checks also passed.

The real browser test did not reach Auth startup or enrollment. After the pinned
server image became available, the pinned Chromium fixture download exceeded its
15-minute build limit. No version, TLS check, or system trust setting was changed.

The optional test uses a virtual WebAuthn key and a private file relay for the
encrypted callback. Even a pass would not prove system browser UI, physical keys,
Apple app lifecycle, or sandboxed Mac presentation. Local browser MFA returns an
assertion for certificate issuance; SSO returns certificates in its callback.
Only the authenticated callback transport is shared.

## Earlier checks

These results predate the biometric feature. SSH results used temporary changes
to libssh2 1.11.1. Those changes and build tools are removed. They do not validate
a caller-supplied upstream engine.

| Check | Recorded result |
| --- | --- |
| macOS package tests | 33 passed: 9 auth, 14 transport/trust/FD, 10 certificate/parser |
| iOS Simulator package tests | 29 passed on iPhone Duo, iOS 27.1 |
| Package builds | macOS release and iOS passed |
| Historical SSH engine matrix | 34 checks passed; pinned OpenSSL 3.2.0 headers and static archives |
| C adapter bounds and descriptor cleanup | Eight checks passed |
| Engine archive builds | macOS arm64 13.3, iOS arm64 16.1, Simulator arm64 16.1 |
| Official-client server controls | TOTP enrollment, allowed/denied nodes, PTY/tmux, reverse-tunnel outage, no direct SSH route passed |
| Native public login | Password/TOTP, SSH/TLS chains, and identity checks passed on Teleport 18.11.4 |
| Native node/SSH path on OrbStack | Fresh login, both nodes, PTY resize, 256 KiB SFTP, concurrent streams, denials, and sign-out passed |
| Release benchmark | Cold/warm 1/10/25 prepared leases and verified 1 MiB SFTP round trip passed |
| Simulator smoke app | Live run and wrong-HTTPS-CA rejection passed |
| Provider sign-in | Unverified |

Records: [native E2E](native-e2e-results.txt), [Apple smoke](apple-smoke-results.txt),
[SSH matrix](ssh-engine-results.json), and [benchmark samples](benchmark-results.json).
The [benchmark notes](../Benchmarks/README.md) list measurement limits. Interactive
latency, CPU/allocation profiles, idle wakeups, impaired networks, and reference
comparisons remain unmeasured. No performance budget is claimed.

Transport tests cover TLS route order and Teleport's long-lived private PKI,
including CA, name, usage, signature, and time checks. The host SSH parser accepts
the OpenSSH no-expiry value; user identities still expire at their earliest
certificate limit. Archive builds alone do not prove a device session.

The earlier tests used the public Swift API, not `tsh` as the client. A temporary
Colima runtime was removed when OrbStack was selected; final controls and native
runs passed on OrbStack. Physical-device execution was excluded at the user's
request. Community supports GitHub SSO; local OIDC requires a permitted Enterprise
setup. Real provider, device lifecycle, and sandboxed browser checks remain open.

Only the pinned server patch and native arm64 lab have real-server evidence here.
Other v18 patches, v17, AMD64 execution, and provider/device combinations need
separate checks. Local builds used Xcode 27.1/Swift 6.4; Apple CI selects Xcode
26.3/Swift 6.2.3. References were absent during builds: no submodules, mandatory
reference clones, or recursive fetch steps are used.

The earlier dependency review checked all seven locked Swift packages on
20 October 2026. No published affected range included those versions. SwiftNIO
2.104.0 exceeds the listed fix 2.101.0
([advisory](https://github.com/apple/swift-nio/security/advisories/GHSA-qcc5-f287-vgmq));
HTTP/2 1.46.0 exceeds the listed fix 1.45.0
([advisory](https://github.com/apple/swift-nio-http2/security/advisories/GHSA-q3g2-m552-3r9c)).
The enrollment npm lock audit reported zero known vulnerabilities. These checks
exclude test images and local crypto archives; neither ships in the library.

Historical lab credentials, containers, task images, build files, and logs were
removed. OrbStack remains installed and stopped. User files and shared caches
were preserved.
