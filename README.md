# TeleportKit

A native Swift package for SSH access through a Teleport proxy. It handles sign-in,
short-lived SSH/TLS certificates, node lookup, and proxy streams. Your SSH engine
handles commands, terminals, PTY, and SFTP.

Requires Swift 6.2 or later with the checked-in dependency lock, and
iOS/iPadOS 16.1 or later or macOS 13.3 or later. The only public product is
`TeleportKit`. It includes no Go runtime, `tsh`, server binary, UI framework, or
SSH engine.

## Add the package

Use an exact source revision in your app's `Package.swift`:

```swift
// In Package.dependencies:
.package(
    url: "https://github.com/wiedymi/swift-teleport.git",
    revision: "670d819ce7013af4e993ca55c3a12a93d1f34b13"
)

// In your app target's dependencies:
.product(name: "TeleportKit", package: "swift-teleport")
```

In Xcode, add the same URL and select **Commit** with that revision. This revision
includes the authentication APIs below. The app keeps its own dependency lock.
Reference repositories are optional research inputs. They are not submodules or
package dependencies and are not fetched when the package resolves.

## Create one client per profile

```swift
import Foundation
import TeleportKit

let proxy = try TeleportProxy(url: URL(string: "https://teleport.example.com")!)
let client = TeleportClient(proxy: proxy)
let discovery = try await client.discover()
```

Share this client across tabs and nodes for the same proxy/account profile.
`discovery` reports the root cluster, server version, authentication type, and
advertised connectors. HTTPS verification stays active.

System HTTPS trust is the default. For a private HTTPS CA, supply its DER bytes:

```swift
let proxy = try TeleportProxy(
    url: URL(string: "https://teleport.example.com")!,
    httpsCACertificatesDER: [privateHTTPSCAInDER]
)
```

This does not disable certificate checks or change system browser trust. iOS ATS
and browser trust can need app or device settings; see
[HTTPS requirements](docs/INTEGRATION.md#profile-and-storage).

The default identity store is memory only. For durable storage, supply your
app's `TeleportIdentityStore`:

```swift
let client = TeleportClient(proxy: proxy, identityStore: secureStore)
```

`secureStore` is an app-supplied store. Its `replace(with:)` must replace the
complete identity in one atomic write and preserve the old record if the write
fails. Store private keys in secure, device-only storage. Keep them out of logs
and cloud configuration sync. See the [storage contract](docs/INTEGRATION.md#profile-and-storage).

The examples below use account input from your app: `username`, `password`,
`oneTimeCode`, and a browser `presenter`. Do not put credentials in source code.
Each login returns a complete, validated `TeleportIdentity` and stores it through
the configured identity store.

## Password and TOTP

```swift
let identity = try await client.login(
    username: username,
    password: password,
    otp: oneTimeCode,
    ttl: 3600
)
let osLogins = identity.allowedLogins
let expiresAt = identity.validBefore
```

Use an empty `otp` only when the server offers login without TOTP. The server can
shorten the requested lifetime. Re-authenticate when the identity expires; there
is no automatic refresh token.

## Browser MFA for a local account

Approve a password login with an existing passkey or security key in the system
browser:

```swift
let identity = try await client.login(
    username: username,
    password: password,
    browser: presenter
)
```

This still requires the local account password. It does not register a credential.
`discovery.webAuthnConfigured` can show this action, but the server's login
challenge decides whether browser MFA is allowed. Handle
`TeleportError.unsupportedPolicy(.browserMFA)` when it is disabled.

## Browser SSO

Use a connector returned by discovery. For example, use an advertised GitHub
connector:

```swift
if let connector = discovery.connectors.first(where: { $0.kind == .github }) {
    let identity = try await client.login(browser: presenter, connector: connector)
}
```

OIDC and SAML use the same high-level call when the server advertises a supported
connector. SSO and local browser MFA use different Teleport protocols. SSO returns
certificates in its callback; local MFA returns an assertion for a later
certificate request. Required login banners and SAML HTTP-POST binding are
unsupported. Real provider validation remains pending.

### Supply the browser presenter

The library has no UI dependency. An app can adapt its browser owner with a
closure:

```swift
struct AppBrowserPresenter: TeleportBrowserPresenter {
    let openURL: @MainActor @Sendable (URL) async throws -> Void

    @MainActor
    func open(_ url: URL) async throws {
        try await openURL(url)
    }
}
```

Your `openURL` action presents the system authentication browser and returns after
it opens. Keep one app-owned browser/login operation per profile. Retain its browser
until the shared login completes or its last owner leaves. Matching login callers
share one task; a canceled individual waiter must not close a browser still used
by another waiter. Cancel the operation when its last owner leaves or the user
cancels the browser, then close the browser.

The final callback uses an authenticated, encrypted IPv4 loopback listener. It is
not a custom app URL scheme. A sandboxed Mac app needs incoming network permission.
See [browser presentation and app settings](docs/INTEGRATION.md#browser-presentation).

## Optional Secure Enclave MFA

This creates a custom, device-bound P-256 MFA credential. It uses Face ID or
Touch ID for authentication signatures. It is separate from SSH/TLS keys and does
not read saved Apple passkeys. Sign-in still requires a password.

Enable it with a stable app-specific Keychain service:

```swift
let deviceConfiguration = try TeleportSecureEnclaveConfiguration(
    keychainService: "com.example.app.teleport.device-credentials"
)
let client = TeleportClient(
    proxy: proxy,
    identityStore: secureStore,
    secureEnclave: deviceConfiguration
)
```

First sign in with an existing method. Then authorize setup with a **fresh** TOTP
code. A code already used for login can be rejected as a replay:

```swift
try await client.login(username: username, password: password, otp: oneTimeCode)
// Obtain a fresh code before this separate setup request.
try await client.registerSecureEnclaveCredential(
    name: "This device",
    otp: freshSetupCode,
    prompt: "Set up Teleport sign-in"
)
```

Or use a new browser approval from an existing passkey or security key:

```swift
try await client.registerSecureEnclaveCredential(
    name: "This device",
    browser: presenter,
    prompt: "Set up Teleport sign-in"
)
```

These are alternative setup calls. Supply a code or a presenter, not both. The
server decides which approval is required. Setup uses the current verified
identity and a new device-management MFA request.

Later, sign in with the registered credential:

```swift
let identity = try await client.loginWithSecureEnclave(
    username: username,
    password: password,
    prompt: "Approve Teleport sign-in"
)
```

Remove only the local credential:

```swift
try await client.deleteSecureEnclaveCredential(username: username)
```

Local deletion does not remove Teleport's device entry, sign out, or revoke issued
access. Remove the server entry through Teleport separately. Keep another login
method for recovery. A changed biometric set or device replacement can make the
key unusable. Failed setup can leave a server entry without a local credential.

The app supplies setup/recovery screens, localized prompts,
`NSFaceIDUsageDescription`, signing settings, and the Keychain namespace. No
Associated Domains capability is needed. There is no software-key fallback.
The RP must equal the proxy host. The response does not prove Secure Enclave
storage to Teleport, and it uses a zero signature counter. Hardware SSH-key and
Device Trust policies remain unsupported. See
[setup, signing, and recovery](docs/INTEGRATION.md#optional-biometric-device-credential)
and [authentication choices](docs/AUTHENTICATION.md#optional-secure-enclave-mfa).

## Find nodes and prepare SSH

Read one page at a time. Request the next page only when needed:

```swift
let firstPage = try await client.nodes(limit: 100)
if firstPage.hasMore {
    let nextPage = try await client.nodes(limit: 100, startKey: firstPage.nextKey)
}
```

Select an exact stable node ID and an OS login from `identity.allowedLogins`:

```swift
let node = try await client.resolveNode(stableNodeID)
let connection = try await client.connect(to: node, login: "alice")
let socket = try connection.takeSocketDescriptor()
```

The Teleport account and OS login are separate. This package supports the root
cluster only. Duplicate display names return `TeleportError.ambiguousNode`; prefer
the stable ID.

Pass these three inputs to your compatible SSH engine:

- The transferred nonblocking `socket`.
- `connection.sshCertificateOpenSSH` and `connection.sshPrivateKeyPEM` from that
  same connection.
- A host-check callback that calls the following before user authentication:

```swift
try connection.verifyHostCertificate(hostCertificateBytes)
```

`hostCertificateBytes` is the complete SSH wire-format host certificate from key
exchange. The engine must also verify the key-exchange signature with its certified
key. A fingerprint-only check is insufficient.

Keep `connection` alive until SSH work stops. The engine owns the transferred
socket and must close it after its final SSH call. Then close the package path:

```swift
await connection.close()
```

On cancellation, closing the connection wakes pending socket work. Wait for the
engine to stop before closing its descriptor. Read the
[socket ownership contract](docs/INTEGRATION.md#socket-ownership) and
[SSH engine requirements](docs/SSH-ENGINE.md) before wiring commands, PTY, or SFTP.
The library does not bundle an SSH engine or expose those channel operations.

## Sign out and handle failures

```swift
try await client.signOut()
```

The app must close its dependent SSH sessions. Sign-out cancels pending
authentication and clears the issued identity. It keeps the registered device
credential and does not revoke server certificates.

Handle `CancellationError` separately from failure. Use fixed, localized messages
for `TeleportError` cases such as `authenticationRequired`, `accessDenied`,
`biometricsUnavailable`, and `deviceCredentialMissing`. Unsupported policy errors
must not trigger a weaker login or direct SSH fallback. Keep passwords, private
keys, browser URLs, callback secrets, and authentication responses out of logs.

## Documentation and checks

| Guide | Contents |
| --- | --- |
| [App integration](docs/INTEGRATION.md) | Storage, browser lifetime, app settings, signing, recovery, and socket ownership |
| [Authentication](docs/AUTHENTICATION.md) | Protocols, key/certificate checks, limits, and material choices |
| [Compatibility](docs/COMPATIBILITY.md) | Supported server/platform scope and unsupported policies |
| [SSH engine](docs/SSH-ENGINE.md) | Required certificate, descriptor, and channel behavior |
| [Validation](docs/VALIDATION.md) | Exact passed, skipped, and unverified checks |
| [Pinned server lab](IntegrationTests/README.md) | Disposable fixtures, real-server commands, and cleanup |
| [Protocol inputs](docs/PROVENANCE.md) | Source pins, schema licenses, and independent implementation limits |

Run package checks in the default build locations:

```sh
swift test
swift build -c release
```

The pinned Teleport 18.11.4 lab passed native registration/login with an injected
software test key, including real password/TOTP login and issued SSH/TLS
certificates. This does not prove Secure Enclave, biometric prompts, or signed
Keychain access. Real browser MFA, physical keys, provider SSO, and device lifecycle
checks remain pending. See the exact [validation record](docs/VALIDATION.md).

The lab wrapper removes its containers, networks, credentials, and run files on
exit. A lab started with `lab.sh up` needs an explicit `lab.sh down`. SSH tests need
a caller-supplied compatible upstream libssh2 build and matching crypto libraries.
The repository does not download or build an SSH engine.

This project is independent and is not affiliated with Teleport or its publisher.
