# Compatibility and verification

The initial test server is Teleport Community **18.11.4**, pinned by image digest.
Other server majors are rejected. Other v18 patches need separate checks before
a compatibility claim. See the image/source records in
`IntegrationTests/Docker/versions.lock.json`.

The first scope is one root cluster, TLS routing, local password/TOTP login,
browser sign-in, stable SSH node IDs, and shared short-lived identities. Client
keys are RSA 3072. Host certificate validation handles Ed25519, ECDSA
P-256/P-384/P-521, and RSA SHA-2 signatures.

The package rejects leaf access, legacy listeners, FIPS mode, hardware-key
policies, and automatic Device Trust enrollment. It does not implement
passwordless/headless flows, per-session MFA, access requests, or agent
forwarding. No direct SSH fallback exists.
Required message-of-the-day banners and SAML HTTP-POST authorization binding
are also unsupported. See [AUTHENTICATION.md](AUTHENTICATION.md).

The browser implementation uses a temporary IPv4 loopback listener and the
Teleport AES-GCM response protocol. A successful local callback test does not
establish compatibility with every identity provider or Apple app sandbox.
Real provider login, physical iPhone/iPad background/foreground, and sandboxed
Mac presentation remain release checks until their results are recorded.

The package has no Secure Enclave or passkey feature. It does not add Mosh,
Eternal Terminal, forwarding, databases, Kubernetes, desktop, or session joining.

Verification results and their exact limits are recorded in
[VALIDATION.md](VALIDATION.md). Local OpenSSH engine results are separate from
Teleport results.
