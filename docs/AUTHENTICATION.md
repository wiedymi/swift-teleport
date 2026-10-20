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
This reduces key storage and lets both authentication paths use one key. Other client key algorithms need separate checks.

The client accepts TOTP only when the server offers it. A hardware key challenge
returns a typed unsupported-policy error. Passwords and TOTP codes are not
stored or logged.

Concurrent callers share one login. Canceling one caller leaves the login active
for other callers. When no caller remains, the client cancels the login.

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

## Browser login

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

The client rejects FIPS mode, hardware-key policies, automatic Device Trust
enrollment, and a required message-of-the-day banner. The library has no banner
display and acknowledgement adapter. It must not silently skip this requirement.
Passwordless, headless, per-session MFA, access requests, leaf clusters, legacy
listeners, and agent forwarding are outside the current scope. A server denial
does not cause a direct SSH fallback.
