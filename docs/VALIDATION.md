# Validation

Date: 20 October 2026. Builds, mock tests, real-server tests, and hardware checks
are separate evidence. A build or mock test does not prove device support.

## Readability review

| Check | Result |
| --- | --- |
| `swift test` | 71 passed; both live-server tests skipped without a fixture |
| macOS Release build | Passed |
| iOS Release package build | Passed; default Derived Data, code signing disabled |
| Guide links, heading anchors, code blocks, and diff checks | Passed |

The review kept the public API and security checks. Existing tests cover policy,
account/RP/key binding, callbacks, storage, and cancellation. A new unary test
rejects two replies in one frame or separate frames. Real-server and hardware
checks were not repeated.

The repository has no Git submodules or research checkouts. CI checks for
`.gitmodules` and tracked Git links. Removed run reports remain in
[Git history](https://github.com/wiedymi/swift-teleport/tree/9d7378c6450ed68e4e6fc0a5f3c6aea1fc97ecea/docs).

## Secure Enclave MFA change

The protocol was checked before implementation. Setup uses Auth mTLS and fresh
`MANAGE_DEVICES` approval. Login uses the public WebAuthn endpoints. No production
dependency was added.

| Check | Result |
| --- | --- |
| Full run with a fresh auth-only fixture | 70 passed; one browser live test skipped |
| Native server registration/login | Passed in 53.174 seconds against the pinned Teleport Community 18.11.4 arm64 image |
| Operation tests after moving identity loading into exclusive setup | All three passed |
| macOS Release and iOS package builds | Passed |
| Python lab checks | Five passed; shell syntax also passed |
| Apple CI at `670d819` | [Passed](https://github.com/wiedymi/swift-teleport/actions/runs/39442239346) |

The real-server test used an injected software P-256 key and memory storage.
It covered password/TOTP login, WebAuthn registration/login, a fresh RSA key for
SSH/TLS certificates, identity validation, wrong-password HTTP 403, local deletion,
missing-credential failure, and identity preservation after failures. Verified
HTTPS and Auth mTLS stayed active. Production has no software-key fallback.
The auth-only fixture has no SSH nodes or transport control.

Still unverified:

- Secure Enclave key use and signed Data Protection Keychain access.
- Face ID/Touch ID prompts, cancellation, lockout, restart persistence,
  biometric-set changes, and physical-device recovery.
- Real browser management approval, provider SSO, and Apple browser lifecycle.

Default Linux infrastructure CI cannot reach readiness because its UID 0 server
cannot read the private runner-owned config. File modes were not loosened. The
local auth-only fixture uses the host UID and passed. Registry download limits
also blocked a separate CI attempt. See [lab instructions](../IntegrationTests/README.md).

See [authentication choices](AUTHENTICATION.md#optional-secure-enclave-mfa) and
[app settings and recovery](INTEGRATION.md#optional-biometric-device-credential).

## Earlier local browser MFA change

Local browser MFA has mock certificate tests and authenticated loopback coverage
for invalid input, tampering, timeout, cancellation, shared login, failed storage,
and identity binding. Three certificate tests need an existing OpenSSL 3 tool and
skip when it is absent. The real browser test did not reach Auth startup or
enrollment because the pinned Chromium download exceeded its time limit.
Virtual WebAuthn tests do not prove system browser UI or physical keys/passkeys.

## Earlier checks

Earlier SSH, simulator smoke, and benchmark runs used a modified libssh2 1.11.1
build that is now removed. Their raw reports remain in Git history, linked above.
They do not validate a selected upstream SSH engine. Run the
[engine proof](SSH-ENGINE.md) and live tests with matching headers and crypto.
A platform archive build alone does not prove a device session.

Only the pinned server patch and native arm64 lab have real-server evidence.
Other v18 patches, v17, AMD64 execution, and provider/device combinations need
separate checks. No performance budget is claimed; see
[benchmark limits](../Benchmarks/README.md).

Local builds used Xcode 27.1/Swift 6.4. Apple CI selects Xcode 26.3/Swift 6.2.3.
Task credentials, containers, build files, and logs are removed after testing.
User files and shared caches are preserved.
