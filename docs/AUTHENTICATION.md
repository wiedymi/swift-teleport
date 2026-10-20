# Authentication contract

Share one `TeleportClient` between tabs that use the same proxy and account.
The client normalizes the HTTPS origin. A supplied HTTPS CA applies only to
that origin. HTTP redirects are not followed by the native API client.

## Local login

The client uses these versioned public routes:

1. `GET /v1/webapi/ping` discovers the root cluster and its policy.
2. `POST /v1/webapi/mfa/login/begin` sends `user` and `pass`.
3. `POST /v1/webapi/mfa/login/finish` sends `user`, `password`, `totp_code`,
   `ssh_pub_key`, `tls_pub_key`, and `ttl`.
4. `GET /v1/webapi/auth/export?type=tls-user&format=json` and the same route
   with `type=user` obtain the public user CAs through verified HTTPS.

Public key bytes use JSON base64. The requested lifetime uses nanoseconds.
The client uses one RSA 3072 private key for the issued SSH and TLS credentials.
This reduces key storage and lets all authentication paths use one key. Other client key algorithms need separate checks.

The client accepts TOTP only when the server offers it. This password/TOTP API
does not open a browser. A WebAuthn-only challenge returns the typed `hardwareKey`
error. Use the separate browser MFA API below for that approval. Passwords and
TOTP codes are not stored or logged.

Concurrent callers for the same account and authentication method share one login.
Password/TOTP, local browser MFA, and each SSO connector are separate enum cases;
one method cannot join another pending method. Canceling one caller leaves the login active
for other callers. When no caller remains, the client cancels the login.

## Local browser MFA

`login(username:password:browser:ttl:)` uses a local account password and an
**existing** passkey or security key through the system browser. This is separate
from GitHub/OIDC/SAML SSO and is not passwordless login.

1. Discover and validate the root cluster and policy through verified HTTPS.
2. Start the same authenticated loopback listener used by SSO.
3. Send `user`, `pass`, and `browser_mfa_tsh_redirect_url` to
   `/v1/webapi/mfa/login/begin`.
4. Require `browser_challenge.requestId` and open the same proxy origin at
   `/web/mfa/browser/<requestId>` through `TeleportBrowserPresenter`.
5. The user signs into the matching Teleport web account and approves with an
   existing WebAuthn credential. The server authenticates the account, request,
   browser session, challenge, origin, and credential signature.
6. Authenticate and decrypt the loopback callback. Its
   `browser_mfa_webauthn_response` contains an assertion, **not certificates**.
7. Create the existing RSA key and send `browser_response` with the original
   `requestId` and `webauthnResponse` to `/v1/webapi/mfa/login/finish`, together
   with `user`, `password`, both public keys, an empty `totp_code`, and `ttl`.
8. Load public user CAs through verified HTTPS and apply the existing account,
   root cluster, private key, SSH/TLS certificate, signature, and validity checks.
   Only then can the shared login operation atomically store the identity.

The server must permit browser MFA (`allow_cli_auth_via_browser`) and the account
must have an existing WebAuthn device. An absent browser challenge returns
`unsupportedPolicy(.browserMFA)` without a fallback. Malformed challenges,
assertions, and certificate responses fail without replacing an identity.
`discovery.webAuthnConfigured` only reports a configured RP ID. It is a UI hint;
discovery does not report browser MFA permission. The begin response is authoritative.

The shared listener enforces its existing one-attempt AES-GCM protocol, HTTP
limits, cancellation, and 180-second timeout. An invalid unauthenticated callback
does not consume the attempt. An authenticated but invalid assertion ends it.
Assertion byte fields use bounded URL-safe base64: credential ID 1 KiB, client
data 16 KiB, authenticator data 64 KiB, signature 16 KiB, and user handle 64 bytes.
These are client resource limits; the server verifies WebAuthn cryptography.
Keys are created after approval to avoid key work for disabled or canceled MFA.
No password, key, callback secret, or authentication response is logged.

Device registration, native Apple passkeys, custom Secure Enclave credentials,
PIV signing, Device Trust, headless login, and access requests are outside this API.
See [validation limits](VALIDATION.md) before making a real-server or device claim.

## Identity and storage

The immutable identity record contains both matching credentials and their
trust material. Validation checks the private key, account, root cluster,
certificate signatures, certificate types, and validity times. The client uses
the selected TLS chain to derive the usable time interval. It does not store
parallel login or expiry flags.

The five trust inputs have separate purposes:

| Trust input | Purpose |
| --- | --- |
| HTTPS roots | Discover the proxy, issue credentials, export public CAs |
| Host TLS CAs | Verify internal Auth and ProxySSH TLS routes |
| User TLS CAs | Verify the issued user TLS certificate |
| SSH user CAs | Verify the issued user SSH certificate |
| SSH host CAs | Verify the destination SSH host certificate |

`TeleportIdentityStore.replace(with:)` must replace the entire record atomically.
A failed write must preserve the prior record. A persistent app adapter must
also provide crash-safe writes. `MemoryIdentityStore` is only an in-memory store.
Encoded identity data contains a private key. The app must protect it, bound
stored input before decoding it, and keep it out of sync services and logs.

New operations reject stale results when login or sign-out changes the profile
while an asynchronous operation waits. Existing connection objects retain the
exact identity that opened them. On sign-out, the app must close its dependent
SSH sessions and connection objects. It must then stop all SSH operations before
it closes transferred descriptors. Local sign-out does not revoke certificates
on other clients.

## Browser SSO

The presenter opens an HTTPS authorization URL. It returns after the browser
opens. The library receives the final response on a temporary listener bound to
`127.0.0.1`. This is separate from the identity provider's callback to Teleport.
An arbitrary app URL scheme is not part of this contract.

The client posts to `/v1/webapi/{github|oidc|saml}/login/console`. Its final callback
has the form `http://127.0.0.1:<port>/callback?secret_key=<fresh hex key>`.
The server returns an HTTPS browser URL. A final GET or form POST supplies an
AES-256-GCM encrypted response. The library verifies it with CryptoKit and binds
the issued credentials to the requested keys and root cluster. An invalid local
request gets an error response and does not consume the login attempt. The
attempt expires after 180 seconds.

The app needs permission for incoming loopback connections. It must keep the
login active when the browser opens. A native custom HTTPS trust adapter does
not install browser trust. A test browser must trust the test HTTPS CA separately.

SAML HTTP-POST authorization binding is unsupported. It returns a typed
`browserCallback` policy error. The package does not host an HTML form page or
introduce a remote callback service.

The unit suite proves authenticated native loopback callbacks, wrong-key and
modified-data rejection, and cancellation. It does not prove a real provider
login, physical iPhone/iPad lifecycle, or sandboxed Mac presentation. Those
results must be recorded separately before claiming support.

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

The client rejects FIPS mode, hardware-backed SSH private-key policies, automatic Device Trust
enrollment, and a required message-of-the-day banner. The library has no banner
display and acknowledgement adapter. It must not silently skip this requirement.
Passwordless, headless, per-session MFA, access requests, leaf clusters, legacy
listeners, and agent forwarding are outside the current scope. A server denial
does not cause a direct SSH fallback.
