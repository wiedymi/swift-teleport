# App integration

## Three SSH engine inputs

1. A prepared nonblocking socket from `takeSocketDescriptor()`.
2. `sshCertificateOpenSSH` and `sshPrivateKeyPEM` from that same connection.
3. A host-check callback that calls `verifyHostCertificate` with the complete
   certificate from key exchange, before user authentication.

The SSH engine must negotiate a host certificate and verify the key exchange
signature with its certified key. A fingerprint-only host callback is not enough.
The existing VVTerm libssh2 1.11.1 build needs an upstream update when Teleport
integration starts. Supply a compatible external engine as described in
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

UI, Keychain names, biometric policy, profile forms, navigation, and cloud sync
belong to the app. Unsupported server policies return typed errors.

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

Dependency ranges allow compatible versions to be shared with VVTerm.
`Package.resolved` records the exact graph used for package tests; the app keeps
its own resolved graph. Reference repositories are never dependencies.
