# App integration

The [README](../README.md) has usage examples. This guide defines the app's
responsibilities; [Authentication](AUTHENTICATION.md) explains the protocols.

## Three SSH engine inputs

1. A prepared nonblocking socket from `takeSocketDescriptor()`.
2. `sshCertificateOpenSSH` and `sshPrivateKeyPEM` from that same connection.
3. A host-check callback that calls `verifyHostCertificate` with the complete
   certificate from key exchange, before user authentication.

The engine must negotiate a host certificate and verify the key-exchange
signature with its certified key. A fingerprint-only callback is insufficient.
See [SSH engine requirements](SSH-ENGINE.md); the package does not bundle one.

Each connection keeps the credentials that opened it, even after another login.
Keep it alive through the final SSH call.

## Socket ownership

`takeSocketDescriptor()` transfers the SSH socket end once. The app must use
readiness events and deadlines for libssh2 EAGAIN. Do not apply TCP options to
this Unix socket.

Stop SSH work before closing the transferred descriptor. `connection.close()`
closes the package end and wakes pending socket work. It never closes the
transferred descriptor, which the engine must close after its final SSH call.

## Profile and storage

Use one `TeleportClient` per proxy/account profile. Each saved server entry needs
only a profile reference, stable node ID, and OS login. Share the profile identity.
`nodes` returns one bounded page; `resolveNode` searches bounded pages and rejects
duplicate names.

Implement `TeleportIdentityStore.load` and `replace(with:)`. Use one secure record
and crash-safe atomic replacement. A failed write must preserve the old record.
Bound stored input before decoding. The package validates decoded identities and
derives validity and permitted logins from certificates. Do not add login or
expiry flags. Encoded identities contain private keys; do not log or sync them.

`signOut` cancels pending authentication, clears the cached proxy path, and removes
the issued identity. It keeps the Secure Enclave credential and does not revoke
server certificates. The app must close dependent SSH sessions.

Use system HTTPS trust for a proxy with a public certificate. With a private
HTTPS CA, iOS URLSession can reject the connection before the package's custom
trust callback runs. The app must configure the relevant domain for
[manual trust evaluation](https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication)
or use a CA trusted by the system. The smoke app has a `teleport.localhost` setting
and checks that a wrong CA fails. HTTPS, hostname, validity, and chain checks stay
active. The package cannot change ATS settings or system browser trust.

## Browser presentation

Implement `TeleportBrowserPresenter` to open the supplied HTTPS URL on the main
actor and return after it opens. Use it for local browser MFA, browser SSO, and
device setup. The new device setup can open two URLs in one operation. Close the
prior system browser before opening its replacement. Ignore the prior browser's
completion; only cancellation of the current browser cancels the login.
See the [README examples](../README.md#supply-the-browser-presenter).

Keep one app-owned browser/login operation per profile:

- Retain the browser while the shared login has callers.
- Canceling one caller must not close a browser used by another caller.
- When the last owner leaves, cancel its operation, then close the browser.
- When the user cancels the browser, cancel the login operation.

Local browser MFA, management approval, and SSO use encrypted IPv4 loopback HTTP,
not an app URL scheme. A sandboxed Mac app needs incoming network permission.
The headless setup step uses the authenticated HTTPS response and has no loopback
callback. Private HTTPS roots in the library do not install browser trust. Keep
browser URLs and callback data out of logs.
Device lifecycle checks remain open; see [Compatibility](COMPATIBILITY.md).

`discover().webAuthnConfigured` is a UI hint, not browser MFA permission. Handle
`unsupportedPolicy(.browserMFA)` when the server does not offer the challenge.
Local browser MFA still needs a password and an existing passkey or security key.

## Optional biometric device credential

The [README](../README.md#device-key-sign-in) shows the high-level API. The library
owns the authentication key, WebAuthn, server requests, and certificate checks.
The app owns browser presentation, prompt text, setup/recovery UI, and signing.
Keep UI frameworks outside the library.

For a native-first local-account flow:

1. Call `loginWithSecureEnclave(username:prompt:ttl:)` when access is absent or
   expired. A successful result is a normal, stored `TeleportIdentity`.
2. On `deviceCredentialMissing`, offer
   `registerSecureEnclaveCredential(username:name:browser:prompt:ttl:)`.
   Other failures, including cancellation, must not start automatic setup.
3. Keep one owned task through browser approval, registration, and final login.
   Present sign-in before starting an SSH timeout. Cancel the task when its
   screen closes; recheck the saved account, cluster, and SSH login before use.

This flow needs no password storage. It needs `allow_headless` and
`allow_passwordless` on Teleport, plus an existing web passkey or security key.
TOTP cannot approve headless setup. A second, scoped browser approval can be
required for device management. Setup holds a 60-second identity in memory only;
show a retry action if that window expires. Store only the final identity.
There is no refresh token.

First setup keeps one local authentication context for registration and its
immediate first certificate request, then invalidates it. Later logins require
fresh local authentication. This can reduce repeated Face ID/Touch ID prompts
during setup; the exact count is not verified on hardware. Teleport's browser
login and device-management approvals remain separate. Do not treat library
authentication as an automatic grant for an app's separate lock policy.

Use a stable app-specific Keychain service. Leave `accessGroup` unset for the
default group, or supply a group allowed by the app's signing and provisioning.
Do not sync or export device records. The issued identity contains a separate
SSH/TLS private key and certificates; store it atomically in device-only storage.
Device names must be nonempty and at most 30 UTF-8 bytes. Prompt text must be
nonempty, localized, and at most 1024 UTF-8 bytes. Neither can contain control
characters. The library requires biometrics with no passcode fallback.

App settings:

- Provide `NSFaceIDUsageDescription` for Face ID. Touch ID has no equivalent
  usage-description key. Supply localized prompt text for each operation.
- Use stable app signing and Data Protection Keychain access. An explicit group
  needs Keychain Sharing and the matching signed group. Team, signing, or group
  changes can make records inaccessible.
- Keep incoming loopback permission for browser management approval in a
  sandboxed Mac app. HTTPS, browser trust, and ATS requirements still apply.
- Associated Domains is not needed. The app-owned key is not a saved Apple passkey.
  PIV and Device Trust are outside this feature.

Recovery must distinguish local and server state:

| Error | App action |
| --- | --- |
| `secureEnclaveUnavailable` or `biometricsUnavailable` | Explain the device requirement and system settings; do not bypass it |
| `deviceCredentialMissing` | Offer browser-approved setup; an old MFA-only record needs explicit removal first |
| `deviceCredentialExists` | Explain local and Teleport entry removal before new setup |
| `deviceCredentialStorage` | Explain that storage failed; use fixed text without system details |
| `unsupportedPolicy` | Explain the required server settings; do not use weaker authentication |

`deleteSecureEnclaveCredential(username:)` deletes only the local record.
The user removes the server entry in Teleport. Neither local deletion nor failed
setup clears an issued identity; call `signOut` separately when needed.
Interrupted setup or a failed local write can leave a server-only entry. Require
a deliberate reset; never silently replace a credential or delete its server entry.
If registration succeeded but final certificate issuance failed, first retry
native login with the new key.

Older password-based device MFA remains a separate API. Its records cannot be
upgraded in place: remove the local record and server entry, then use the new
setup. Apps that omit password/TOTP should direct recovery to Teleport's web UI.
Hardware changes or biometric enrollment changes can require that recovery.

Simulator and software-key tests cannot prove hardware behavior. A signed device
check must cover prompts, cancellation, lockout, restart persistence, biometric
changes, missing keys, and recovery. See [Validation](VALIDATION.md). Apple documents
[device-bound encrypted key storage](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
and [biometric key control](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset).

## Resource rules

Control responses are capped at 1 MiB, gRPC metadata at 16 KiB, proxy messages at
256 KiB, and local reads at 32 KiB. Pending socket writes are capped at 512 KiB,
enough for one maximum message plus an HTTP/2 receive window. Reads wait for
pending writes; SSH bytes are never dropped or automatically replayed.

NIO shares process event-loop resources. Each current profile identity uses one
cached ProxySSH HTTP/2 connection; each SSH session gets a separate stream.
Control RPCs use short connections. Measure a need before adding connection state.

Dependency ranges allow compatible versions to be shared with the consuming app.
`Package.resolved` records the exact graph used for package tests; the app keeps
its own resolved graph. Reference repositories are never dependencies.
