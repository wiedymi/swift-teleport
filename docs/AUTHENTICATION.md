# Authentication contract

Share one `TeleportClient` between tabs that use the same proxy and account.
The client normalizes the HTTPS origin, applies supplied HTTPS CAs only to that
origin, and rejects native API redirects. The [README](../README.md) has usage
examples; [App integration](INTEGRATION.md) defines storage and UI responsibilities.

Matching account/method callers share one login. Password/TOTP, local browser MFA,
passwordless device login, password-based device MFA, and each SSO connector are
separate methods. Different methods cannot join a pending login. One canceled
caller leaves other callers active;
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

## Secure Enclave device credentials

Configure `TeleportSecureEnclaveConfiguration` with an app-specific Keychain
service. The library owns the key, WebAuthn, server requests, and certificate
checks. The app supplies its browser, prompts, storage settings, and recovery UI.
See [App integration](INTEGRATION.md#optional-biometric-device-credential).

### Browser-approved passwordless setup

`registerSecureEnclaveCredential(username:name:browser:prompt:ttl:)` returns a
normal identity without an app password field. It runs exclusively and does not
replace an existing device record:

1. Require a local account with `allow_headless` and `allow_passwordless` enabled.
   Create temporary SSH/TLS keys and a headless request ID bound to the SSH key.
2. Start `POST /v1/webapi/headless/login` and open the same proxy's
   `/web/headless/<id>` page. An existing web passkey or security key approves the
   request. TOTP cannot approve it.
3. Validate the HTTPS response, account, cluster, requested keys, certificate
   trust, and 60-second lifetime. Keep this setup identity in memory only. There
   is no loopback callback for this step.
4. Use the setup identity's verified Auth mTLS route to call
   `/proto.AuthService/CreateAuthenticateChallenge` with `MANAGE_DEVICES` scope
   and no approval reuse. If required, obtain a second browser approval through
   the authenticated MFA loopback callback. A normal login approval has the
   wrong scope for device management.
5. Call `/proto.AuthService/CreateRegisterChallenge` with WebAuthn usage **2**
   (passwordless). Require the requested account, exact RP, ES256, resident
   credential, and user verification. Create the device-bound P-256 key and
   require a biometric signature.
6. Send registration data to `/proto.AuthService/AddMFADeviceSync`. Check the
   returned credential ID, RP, public key, and resident status before storing the
   local record with its user handle.
7. Perform native passwordless login with the new key. Validate the complete
   normal identity, then atomically replace the configured identity store.

The setup certificate expires quickly. If approval or registration exceeds that
window, retry setup; the library does not extend it or expose it to connections.
The presenter must support repeated opens within one operation. See
[browser ownership](INTEGRATION.md#browser-presentation).

`loginWithSecureEnclave(username:prompt:ttl:)` performs later logins. It sends
`passwordless: true` to `/v1/webapi/mfa/login/begin`. The biometric assertion includes
the stored user handle and uses `/v1/webapi/mfa/login/finish`, with no password.
A new RSA 3072 key supplies both SSH and TLS credentials; it stays separate from
the P-256 authentication key. Certificate checks precede atomic storage.

A missing or unusable passwordless record returns `deviceCredentialMissing`.
An app can then offer setup. It must not treat cancellation, denied approval,
storage errors, or unsupported policy as a request to use a weaker method.

### Existing password-based MFA

The older overloads remain available:

- `registerSecureEnclaveCredential(name:otp:browser:prompt:)` uses an existing
  verified identity and fresh TOTP or browser device-management approval.
  Supply a code or presenter, not both. TOTP reuse after login can be rejected.
- `loginWithSecureEnclave(username:password:prompt:ttl:)` uses a password and a
  biometric assertion. Its non-resident credential uses MFA usage **1**.

Existing MFA records cannot become passwordless records by changing a flag.
Explicitly delete the local credential and its Teleport entry, then register
again through the new setup call.

### Key, policy, and recovery rules

`deleteSecureEnclaveCredential(username:)` removes only the local record.
It does not remove Teleport's entry, sign out, or revoke issued certificates.

The key uses `privateKeyUsage` and `biometryCurrentSet`, with device-unlock reuse
disabled and no passcode fallback. First setup shares one private `LAContext`
between key creation, the registration verification signature, and the immediate
first certificate signature. One local approval can cover these steps. The
context is invalidated on completion, failure, or cancellation. Later logins use
fresh contexts. Both server browser approvals remain separate and cannot be
reused across MFA scopes.

This reduces repeated local prompts within one setup action. It does not remove
either signature or weaken later login verification. The exact Face ID/Touch ID
prompt count still needs a real-device check. Unavailable hardware or biometrics
returns a typed error; there is no software fallback. Blocking key work runs away
from the main actor.

One non-sync Data Protection Keychain item holds the credential ID, root cluster,
optional passwordless user handle, and opaque encrypted key representation.
It is `WhenUnlockedThisDeviceOnly`; the private key stays in the Secure Enclave.
The item account is a hash of the normalized HTTPS origin and exact username.
Sign-out keeps this credential. It is app-owned and cannot be used as a saved
Apple passkey by the system browser.

Material choices and recovery limits:

- The RP must equal the proxy host. This avoids a public-suffix dependency and
  rejects parent-domain or alternate-origin RP configurations.
- `fmt:none`, a zero AAGUID, ES256, and a zero signature counter are used. Teleport
  verifies WebAuthn, but receives no proof of Secure Enclave storage and cannot
  use the counter to detect clones. Other attestation or incompatible
  authenticator requirements are rejected.
- Biometric enrollment changes can invalidate the key. Use Teleport's web recovery
  to remove the stale entry, remove the local record, then set up again.
- Server registration and local storage cannot commit together. Interrupted setup
  or a failed local write can leave a server-only entry. No existing record is
  silently replaced or removed. A completed registration survives a later
  certificate-request failure; retry native login before resetting it.
- The bootstrap identity never reaches persistent identity storage. A failed final
  identity write preserves the previous record. Temporary key/blob references
  are dropped after failed setup where they are no longer needed.
- Local deletion cannot remove a server entry or an opaque blob copied elsewhere.
  The library does not promise remote revocation or hardware erasure.

Neither device mode satisfies hardware SSH-key or Device Trust policy.
[Validation](VALIDATION.md) separates software protocol checks from real browser,
Secure Enclave, biometric, and device evidence.

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
Passwordless support is limited to app-owned device credentials. Headless login
is internal to short-lived device setup; there is no general CLI headless API.
Native saved Apple passkeys, per-session MFA, access requests, leaf clusters,
legacy listeners, and agent forwarding remain outside the scope. A server denial
does not cause a direct SSH fallback.
