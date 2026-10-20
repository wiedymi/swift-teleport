# TeleportKit

A native Swift package for SSH access through a Teleport proxy. It handles sign-in,
short-lived SSH/TLS certificates, node lookup, and proxy streams. Your SSH engine
handles commands, terminals, PTY, and SFTP.

The locked dependencies require Swift 6.2+. Runs on iOS/iPadOS 16.1+ and macOS
13.3+. The only public product is `TeleportKit`. It includes no Go runtime, `tsh`,
server binary, or UI framework.

## Add the package

Use an exact source revision in your app's `Package.swift`:

```swift
// In Package.dependencies:
.package(
    url: "https://github.com/wiedymi/swift-teleport.git",
    revision: "aad06a2128df1ae03aeb26e59d34cae7223c196a"
)

// In your app target's dependencies:
.product(name: "TeleportKit", package: "swift-teleport")
```

In Xcode, add the same URL and select **Commit** with that revision. The app keeps
its own dependency lock. The package has no Git submodules and does not fetch
research repositories.

## Create one client per profile

```swift
import Foundation
import TeleportKit

let proxy = try TeleportProxy(url: URL(string: "https://teleport.example.com")!)
let client = TeleportClient(proxy: proxy)
let discovery = try await client.discover()
```

Share this client across tabs and nodes for one proxy/account profile.
`discovery` reports the root cluster, server version, authentication type, and
connectors. HTTPS verification stays active.

System HTTPS trust is the default. For a private HTTPS CA, supply its DER bytes:

```swift
let proxy = try TeleportProxy(
    url: URL(string: "https://teleport.example.com")!,
    httpsCACertificatesDER: [privateHTTPSCAInDER]
)
```

This keeps certificate checks active. Browser trust and iOS ATS need separate
app or device settings; see
[HTTPS requirements](docs/INTEGRATION.md#profile-and-storage).

The default identity store is memory only. For durable storage, supply your
app's `TeleportIdentityStore`:

```swift
let client = TeleportClient(proxy: proxy, identityStore: secureStore)
```

Its `replace(with:)` must atomically replace the complete identity and preserve
the old record if the write fails. Keep private keys in secure, device-only
storage, outside logs and cloud sync. See the
[storage contract](docs/INTEGRATION.md#profile-and-storage).

The examples below use account input from your app: `username`, `password`,
`oneTimeCode`, and a browser `presenter`. Do not put credentials in source code.
Each login returns a validated `TeleportIdentity` and writes it to the configured
store.

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

This needs the account password and an existing credential.
`discovery.webAuthnConfigured` is a UI hint. The login challenge decides whether
browser MFA is allowed; otherwise, the call throws
`TeleportError.unsupportedPolicy(.browserMFA)`.

## Browser SSO

Use a connector returned by discovery. For example, use an advertised GitHub
connector:

```swift
if let connector = discovery.connectors.first(where: { $0.kind == .github }) {
    let identity = try await client.login(browser: presenter, connector: connector)
}
```

OIDC and SAML use the same call with their advertised connector. SSO returns
certificates in its callback; local browser MFA returns an assertion for a later
certificate request. Required login banners and SAML HTTP-POST binding are
unsupported. Real provider tests remain pending.

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

`openURL` must present the system authentication browser and return after it
opens. Keep that browser alive until login completes or all callers cancel.
Matching callers share one login. Canceling one caller must not close another
caller's browser. The callback uses encrypted IPv4 loopback HTTP; a sandboxed Mac
app needs incoming network permission. See
[browser ownership and app settings](docs/INTEGRATION.md#browser-presentation).

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

Supply a code or a presenter, not both. Setup uses the current verified identity
and a fresh device-management approval chosen by the server.

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

Local deletion keeps the server entry and issued identity. Remove the server entry
through Teleport separately. Keep another login method for recovery: device or
biometric changes can make the key unusable, and failed setup can leave an unused
server entry.

The app supplies screens, prompts, `NSFaceIDUsageDescription`, signing settings,
and the Keychain namespace. No Associated Domains capability is needed. The RP
must equal the proxy host. There is no software-key fallback or hardware
attestation proof to Teleport. The signature counter is zero. Hardware SSH-key
and Device Trust policies remain unsupported. See
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

The Teleport account and OS login are separate. Only the root cluster is supported.
Duplicate display names return `TeleportError.ambiguousNode`; prefer the stable ID.

Pass these three inputs to your compatible SSH engine:

- The transferred nonblocking `socket`.
- `connection.sshCertificateOpenSSH` and `connection.sshPrivateKeyPEM` from that
  same connection.
- A host-check callback that calls the following before user authentication:

```swift
try connection.verifyHostCertificate(hostCertificateBytes)
```

`hostCertificateBytes` is the complete SSH wire-format host certificate. The
engine must also verify the key-exchange signature with its certified key.
A fingerprint-only check is insufficient.

Keep `connection` alive until SSH work stops. The engine owns the transferred
socket and must close it after its final SSH call. Then close the package path:

```swift
await connection.close()
```

On cancellation, closing the connection wakes pending socket work. Wait for the
engine to stop before closing its descriptor. Read the
[socket ownership contract](docs/INTEGRATION.md#socket-ownership) and
[SSH engine requirements](docs/SSH-ENGINE.md) before wiring commands, PTY, or SFTP.

## Sign out and handle failures

```swift
try await client.signOut()
```

Close dependent SSH sessions in the app. Sign-out cancels pending authentication
and clears the issued identity. It keeps the device credential and does not revoke
server certificates.

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

The pinned Teleport 18.11.4 lab passed registration/login with an injected software
test key, real password/TOTP, and issued SSH/TLS certificates. Secure Enclave,
biometric prompts, signed Keychain access, real browser MFA, physical keys,
provider SSO, and device lifecycle checks remain unverified. See the
[validation record](docs/VALIDATION.md).

The lab wrapper removes its containers, networks, credentials, and run files on
exit. After `lab.sh up`, run `lab.sh down`. SSH tests need a caller-supplied
compatible upstream libssh2 build and matching crypto libraries.

This project is independent and is not affiliated with Teleport or its publisher.
