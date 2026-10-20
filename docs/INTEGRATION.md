# App integration

## Three SSH engine inputs

1. A prepared nonblocking socket from `takeSocketDescriptor()`.
2. `sshCertificateOpenSSH` and `sshPrivateKeyPEM` from that same connection.
3. A host-check callback that calls `verifyHostCertificate` with the complete
   certificate from key exchange, before user authentication.

The SSH engine must negotiate a host certificate and verify the key exchange
signature with its certified key. A fingerprint-only host callback is not enough.
Supply a compatible external engine as described in
[SSH-ENGINE.md](SSH-ENGINE.md). The standalone product does not bundle an engine.

The connection retains the exact credentials that opened its mTLS path. A later
sign-in cannot replace the credentials of an existing connection. Keep the
connection alive through the final SSH call.

## Socket ownership

Before transfer, the package owns both socket ends. `takeSocketDescriptor()`
transfers the SSH end once. The app must use readiness events and deadlines for
libssh2 EAGAIN. Do not apply TCP options to this Unix socket.

Stop SSH work before closing the transferred descriptor. `connection.close()`
closes the package end and wakes an SSH operation that is waiting for bytes.
It never closes a transferred descriptor. This prevents a later close from
affecting an unrelated descriptor that reuses the same number.

## Profile and storage

Use one `TeleportClient` for one proxy/account profile. A server entry needs only
the profile reference, stable node ID, and OS login. It does not need another copy
of the identity. `nodes` returns a bounded page; `resolveNode` searches bounded
pages and rejects duplicate names.

Implement `TeleportIdentityStore.load` and `replace(with:)`. Replace the complete
encoded record atomically. If a write fails, preserve the previous record. Use
one secure record where possible. The package validates records on decode, and
derives validity and permitted logins from certificates. It stores no login or
expiry flag. Encoded records contain private keys; do not log or sync them.

`signOut` cancels pending login, clears the cached proxy path, and removes local
credentials. The app closes its dependent SSH sessions. Sign-out does not revoke
certificates already issued by the server.

Use system HTTPS trust for a proxy with a public certificate. With a private
HTTPS CA, iOS URLSession can reject the connection before the package's custom
trust callback runs. The app must configure the relevant domain for
[manual trust evaluation](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication)
or use a CA trusted by the system. The test app has one such setting for
`teleport.localhost`. It still requires HTTPS and verifies the configured CA,
hostname, validity, and certificate chain. It also checks that a wrong CA fails.
The package cannot change an app's ATS settings.

## Browser presentation

Implement `TeleportBrowserPresenter` to open the supplied HTTPS URL on the main
actor. The package uses the server's encrypted loopback callback protocol. It
does not substitute an app URL scheme. A sandboxed Mac app must allow the local
listener. iOS background/foreground and device behavior need the checks listed in
[COMPATIBILITY.md](COMPATIBILITY.md).

Use the same presenter for either explicit login method:

```swift
// Local account, approved with an existing passkey or security key in the browser.
let identity = try await client.login(username: username, password: password, browser: presenter)
// Or browser SSO through an advertised GitHub/OIDC/SAML connector.
let ssoIdentity = try await client.login(browser: presenter, connector: connector)
```

The presenter returns after it opens the URL. Keep it and the login task alive
until completion. Cancel the task when its last UI owner leaves, and close the
browser session when login completes or fails. One canceled waiter does not
cancel another waiter's login. Do not log browser URLs or callback data.

For local accounts, `discover().webAuthnConfigured` can show a browser MFA action.
It does not prove permission. Handle `unsupportedPolicy(.browserMFA)` if the
begin response has no browser challenge. This API still needs a password; it
does not register a credential. Password/TOTP remains a separate API.

UI, Keychain names, profile forms, navigation, and cloud sync
belong to the app. Unsupported server policies return typed errors.

## Optional biometric device credential

Use a stable app-specific Keychain service. Leave `accessGroup` unset for the app's
default group, or supply a group authorized by its entitlements and provisioning.
Do not sync or export the local credential record.

```swift
let configuration = try TeleportSecureEnclaveConfiguration(
    keychainService: "com.example.app.teleport.device-credentials"
)
let client = TeleportClient(proxy: proxy, identityStore: myAtomicSecureStore,
                            secureEnclave: configuration)

// First sign in with an existing method. Setup does not bypass account recovery.
try await client.login(username: username, password: password, otp: currentCode)
try await client.registerSecureEnclaveCredential(
    name: "This device", browser: presenter, prompt: "Set up Teleport sign-in"
)
// Or use a fresh TOTP code instead of the browser parameter for setup.

let identity = try await client.loginWithSecureEnclave(
    username: username, password: password, prompt: "Approve Teleport sign-in"
)
try await client.deleteSecureEnclaveCredential(username: username)
```

Setup takes an existing usable identity. Its browser approval is a new
device-management request. Keep the presenter/task alive and apply the same
window ownership and cancellation rules as browser login. When using TOTP, obtain
a fresh code for setup; a code already used for login can be rejected as a replay.
Prompts must be nonempty localized text, at most 1024 UTF-8 bytes, without control
characters. The library fixes the biometric protection policy; the app cannot
change it to a passcode fallback.

App settings:

- Provide `NSFaceIDUsageDescription` in the app's Info.plist for Face ID. Touch ID
  has no equivalent usage-description key. The app supplies each operation's
  localized prompt text.
- Use stable app signing and Data Protection Keychain access. Configure Xcode's
  Keychain Sharing capability when an explicit access group is needed. Match its
  signed group to the configuration; changing signing/team/group can make the
  existing record inaccessible. Do not use a shared group unless it is required.
- Keep incoming loopback permission for browser setup in a sandboxed Mac app.
  Network, TLS, and ATS requirements above still apply.
- No Associated Domains, saved Apple passkey access, PIV, or Device Trust setting
  is required or provided by this feature.

Recovery screens must keep password/TOTP and browser login available. Handle
`secureEnclaveUnavailable`, `biometricsUnavailable`, `deviceCredentialMissing`,
`deviceCredentialExists`, and `deviceCredentialStorage` without exposing system
error details. An unavailable biometric sensor, lockout, changed biometric set,
changed signing identity, or lost device can require another login method.

Explain the two deletion steps: remove the local credential with the library;
remove its server device entry in Teleport's device-management UI. Local removal
does not remove the server entry or clear an issued identity. Call `signOut`
separately if that is also intended. Failed setup can leave a server-only entry,
including after a server success followed by a storage failure. Offer recovery
instructions and a deliberate local reset, not silent replacement or automatic
server deletion.

Simulator tests do not prove Secure Enclave or biometric enforcement. A signed
real-device test must cover prompts, cancellation, lockout, persistence after
restart, biometric-set changes, missing keys, and local/server recovery. See
[validation](VALIDATION.md). Apple documents the
[device-bound encrypted key representation](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
and [biometric-set key control](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset).

## Resource rules

Control responses are capped at 1 MiB. gRPC metadata is capped at 16 KiB. Proxy
messages are capped at 256 KiB and local reads at 32 KiB. Pending socket writes
are capped at 512 KiB: enough for one maximum message plus an HTTP/2 receive
window. The next read waits for the current writes to complete. There is no
lossy byte queue, periodic idle polling, packet task, or automatic SSH byte replay.

NIO shares its process event-loop resources. Each current profile identity uses
one cached ProxySSH HTTP/2 connection; each SSH session gets a separate stream.
Control RPCs use short connections. This keeps the first implementation small;
reuse for control RPCs can be measured before adding more connection state.

Dependency ranges allow compatible versions to be shared with the consuming app.
`Package.resolved` records the exact graph used for package tests; the app keeps
its own resolved graph. Reference repositories are never dependencies.
