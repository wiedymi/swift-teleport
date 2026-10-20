# Authentication contract

Share one `TeleportClient` between tabs that use the same proxy and account.
The client normalizes the HTTPS origin, applies supplied HTTPS CAs only to that
origin, and rejects native API redirects. The [README](../README.md) has usage
examples; [App integration](INTEGRATION.md) defines storage and UI responsibilities.

Matching account/method callers share one login. Password/TOTP, local browser MFA,
Secure Enclave MFA, and each SSO connector are separate methods. Different methods
cannot join a pending login. One canceled caller leaves other callers active;
canceling the last caller cancels the task. Setup and local deletion run exclusively.
Sign-out cancels and waits for pending authentication before clearing the identity.
Another client or process can still replace Teleport's pending challenge.

## Local login

The client uses these versioned public routes:

1. `GET /v1/webapi/ping` discovers the root cluster and its policy.
2. `POST /v1/webapi/mfa/login/begin` sends `user` and `pass`.
3. `POST /v1/webapi/mfa/login/finish` sends `user`, `password`, `totp_code`,
   `ssh_pub_key`, `tls_pub_key`, and `ttl`.
4. `GET /v1/webapi/auth/export?type=tls-user&format=json` and the same route
   with `type=user` obtain the public user CAs through verified HTTPS.

Public key bytes use JSON base64; the lifetime uses nanoseconds. Each login creates
one RSA 3072 private key for both SSH and TLS credentials. This limits key storage
and uses the same validated key path for all login methods. Other key algorithms
need separate checks.

TOTP is accepted only when offered by the server. This API does not open a browser.
A WebAuthn-only challenge returns `unsupportedPolicy(.hardwareKey)`; use the
browser MFA API below. Passwords and TOTP codes are not stored or logged.

## Local browser MFA

`login(username:password:browser:ttl:)` uses a local password and an existing
passkey or security key through the system browser. It is separate from
GitHub/OIDC/SAML SSO and still requires a password.

1. Discover and validate the root cluster and policy through verified HTTPS.
2. Start the authenticated loopback listener described under [Browser SSO](#browser-sso).
3. Send `user`, `pass`, and `browser_mfa_tsh_redirect_url` to
   `/v1/webapi/mfa/login/begin`.
4. Require `browser_challenge.requestId` and open the same proxy origin at
   `/web/mfa/browser/<requestId>` through `TeleportBrowserPresenter`.
5. The user signs into the matching Teleport web account and approves with an
   existing WebAuthn credential. The server checks the account, request, browser
   session, challenge, origin, and credential signature.
6. Authenticate and decrypt the loopback callback. Its
   `browser_mfa_webauthn_response` contains an assertion, **not certificates**.
7. Create the existing RSA key and send `browser_response` with the original
   `requestId` and `webauthnResponse` to `/v1/webapi/mfa/login/finish`, together
   with `user`, `password`, both public keys, an empty `totp_code`, and `ttl`.
8. Load public user CAs through verified HTTPS and validate the complete identity
   as described below. Only then atomically store it.

The server must permit browser MFA (`allow_cli_auth_via_browser`), and the account
needs a registered WebAuthn device. A missing browser challenge returns
`unsupportedPolicy(.browserMFA)` without fallback. Invalid challenges, assertions,
or certificates leave the prior identity unchanged. `discovery.webAuthnConfigured`
reports a configured RP ID, not browser MFA permission; the begin response decides.

An authenticated but invalid assertion ends the callback attempt. Assertion byte
fields use bounded base64url: credential ID 1 KiB, client data 16 KiB,
authenticator data 64 KiB, signature 16 KiB, and user handle 64 bytes. The server
verifies WebAuthn cryptography. Keys are created after approval, so disabled or
canceled MFA does not require key creation.

This API does not register devices or read saved Apple passkeys. See
[validation limits](VALIDATION.md) before making server or device support claims.

## Optional Secure Enclave MFA

Configure `TeleportSecureEnclaveConfiguration` on the client to enable three
high-level operations:

- `registerSecureEnclaveCredential(name:otp:browser:prompt:)` requires a usable,
  verified identity and fresh TOTP or browser approval when required by the server.
  Supply a code or presenter, not both. Device names have a 30 UTF-8 byte limit.
  If setup returns `oneTimeCodeRequired`, ask for a fresh authenticator code and
  retry. After a TOTP login, wait for the next code; Teleport rejects code reuse.
  If the server requires no approval, setup accepts an empty code. Browser
  approval is a separate option that needs an existing passkey or security key.
- `loginWithSecureEnclave(username:password:prompt:ttl:)` uses the local account
  password and a biometric WebAuthn assertion, then returns a complete identity.
- `deleteSecureEnclaveCredential(username:)` deletes only the local credential.
  It does not remove Teleport's device entry, sign out, or revoke issued certificates.

This is a custom, non-resident MFA credential, separate from saved Apple passkeys
and SSH/TLS keys. Library code owns key use and WebAuthn; app responsibilities are
in [App integration](INTEGRATION.md#optional-biometric-device-credential).

Registration uses the existing identity's Auth mTLS route:

1. Validate discovery policies, proxy, account, and root cluster.
2. Call `/proto.AuthService/CreateAuthenticateChallenge` with the context user,
   `MANAGE_DEVICES` scope, and no approval reuse. For browser approval, start the
   existing encrypted loopback callback and include its redirect URL. A normal
   login approval has the wrong scope and cannot authorize setup.
3. Complete the offered TOTP or browser approval, then call
   `/proto.AuthService/CreateRegisterChallenge` for WebAuthn with MFA usage.
4. Validate the challenge's account, RP, algorithm, and authenticator requirements.
   Create a device-bound P-256 key with Apple CryptoKit Secure Enclave APIs.
5. Require a biometric signature and verify it with the new public key. Send
   WebAuthn registration data to `/proto.AuthService/AddMFADeviceSync`.
6. Require the returned credential ID, RP ID, and COSE public key to match.
   Only then add the local credential record. An existing record is never replaced.

Native login uses `/v1/webapi/mfa/login/begin` and `/finish`. Challenge bytes use
Teleport's standard JSON base64; assertion bytes use base64url. The finish field
is `webauthn_challenge_response`. After biometric approval, it creates one new RSA
key for SSH/TLS, separate from the MFA key. Complete identity checks precede
atomic storage.

The key uses `privateKeyUsage` and `biometryCurrentSet`. Each signature uses a new
`LAContext` with unlock reuse disabled and no passcode fallback. Cancellation
invalidates the context. Unavailable hardware or biometrics returns a typed error;
there is no software fallback. Blocking key work runs away from the main actor.

One non-sync Data Protection Keychain item holds the credential ID, root cluster,
and opaque encrypted key representation. It is `WhenUnlockedThisDeviceOnly`.
The private key remains in the Secure Enclave. Its item account is a hash of the
normalized HTTPS origin and exact username. The RP and account are derived from
this scope, not stored twice. Sign-out keeps this credential.

Material choices and recovery limits:

- The RP must equal the proxy host. This avoids a public-suffix dependency, but
  rejects parent-domain and alternate-origin RP configurations.
- `fmt:none` attestation, a zero AAGUID, and ES256 are used. Teleport verifies
  WebAuthn, but this response does not prove Secure Enclave storage to the server.
  Other attestation requests, required resident keys, and incompatible attachment
  or algorithm requirements are rejected.
- The signature counter is always zero, as permitted by WebAuthn. This avoids
  mutable counter state, but does not provide counter-based clone detection.
- Adding/removing Touch ID fingers or changing Face ID enrollment can invalidate
  the key. Sign in another way, remove local and stale server entries, then set up
  a new credential.
- Server registration and local storage cannot commit together. Interrupted setup,
  a failed local write, or competing clients can leave an unused server entry.
  New key/blob references are dropped on failure. Remove the server entry through
  Teleport's recovery UI before repeating setup.
- A local deletion cannot erase a server registration or an opaque blob copied
  elsewhere. The library does not promise remote revocation or hardware erasure.

This MFA key cannot satisfy hardware SSH-key or Device Trust policy. See
[app settings and recovery](INTEGRATION.md) and [exact test limits](VALIDATION.md).

## Identity and storage

The immutable identity contains matching SSH/TLS credentials and trust material.
Validation checks private-key binding, account, root cluster, certificate types,
signatures, and validity. The selected TLS chain defines the usable time interval;
there are no separate login or expiry flags.

The five trust inputs have separate purposes:

| Trust input | Purpose |
| --- | --- |
| HTTPS roots | Discover the proxy, issue credentials, export public CAs |
| Host TLS CAs | Verify internal Auth and ProxySSH TLS routes |
| User TLS CAs | Verify the issued user TLS certificate |
| SSH user CAs | Verify the issued user SSH certificate |
| SSH host CAs | Verify the destination SSH host certificate |

`TeleportIdentityStore.replace(with:)` must replace the whole record atomically
and preserve the old record on failure. Persistent stores need crash-safe writes;
`MemoryIdentityStore` is memory only. See the
[storage contract](INTEGRATION.md#profile-and-storage). Passwords, keys, browser
URLs, callback secrets, and authentication responses must stay out of logs.

Operations reject stale results after profile authentication changes. Existing
connections keep the identity that opened them. On sign-out, close dependent SSH
sessions and stop their SSH work before closing transferred descriptors. Local
sign-out does not revoke issued certificates.

## Browser SSO

The presenter opens an HTTPS authorization URL. The final library callback uses a
temporary `127.0.0.1` listener, separate from the identity provider's callback to
Teleport. It does not use an app URL scheme.

The client posts to `/v1/webapi/{github|oidc|saml}/login/console`. Its final callback
has the form `http://127.0.0.1:<port>/callback?secret_key=<fresh hex key>`.
The server returns an HTTPS browser URL. A final GET or form POST supplies an
AES-256-GCM encrypted response. CryptoKit authenticates it, and identity validation
binds the credentials to the requested keys and root cluster. An unauthenticated
callback does not consume the attempt. Authenticated invalid data ends it. HTTP
limits apply, cancellation closes the listener, and it expires after 180 seconds.
This callback transport is shared with local MFA; response types and requests
remain separate. See [browser ownership and permissions](INTEGRATION.md#browser-presentation).

SAML HTTP-POST authorization binding is unsupported. It returns a typed
`browserCallback` policy error. The package does not host an HTML form page or
introduce a remote callback service.

Unit checks cover authenticated callbacks, wrong-key/tamper rejection, and
cancellation. Real provider login, physical device lifecycle, and sandboxed Mac
presentation remain unverified; see [Validation](VALIDATION.md).

## Internal Auth route

Node lookup uses `/proto.AuthService/ListResources`. Its TLS ClientHello offers
the route token `teleport-auth@<hex UTF-8 cluster>.teleport.cluster.local` and
`h2`. The Auth server negotiates `h2`. The TLS verification name is
`teleport.cluster.local`, using the host TLS CA and the issued user identity.
The route token is not the negotiated HTTP/2 protocol.

These internal routes use Teleport's private PKI. The server certificate can
exceed Apple's web certificate lifetime limit. Security validates its chain,
signatures, validity, and constraints against only the authenticated host CAs.
The client also requires the exact DNS SAN `teleport.cluster.local`, server-auth
extended key usage, and permitted signature usage. CA usage restrictions remain
enforced. There is no CN or wildcard fallback. Public discovery and login keep
Apple's HTTPS policy. A failed internal TLS check fails the connection promptly.

Node responses have a 1 MiB byte limit and a protobuf depth limit of eight.
The decoder applies the requested page count before it constructs another node
resource. SwiftProtobuf handles the wire format and unknown fields. Nested
metadata and string limits are checked after protobuf decoding; those allocations
remain bounded by the input byte and depth limits.

ProxySSH offers the `teleport-proxy-ssh-grpc` route hint first, followed by `h2`.
The server selects this internal route and negotiates `h2`. The order matters:
offering `h2` first selects the public web endpoint. Its stream carries SSH bytes
after the initial cluster response. It does not carry Auth RPCs.

## Unsupported requirements

The client rejects FIPS mode, hardware-backed SSH private-key policies, automatic
Device Trust enrollment, and required message-of-the-day banners. There is no
banner display/acknowledgment adapter, so a required banner cannot be skipped.
Passwordless, headless, per-session MFA, access requests, leaf clusters, legacy
listeners, and agent forwarding are outside the current scope. A server denial
does not cause a direct SSH fallback.
