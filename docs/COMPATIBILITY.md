# Compatibility and verification

The initial test server is Teleport Community **18.11.4**, pinned by image digest.
Other server majors are rejected. Other v18 patches need separate checks before
a compatibility claim. See the image/source records in
`IntegrationTests/Docker/versions.lock.json`.

The scope is one root cluster, TLS routing, local password/TOTP login, local
browser MFA, optional Secure Enclave MFA, browser SSO, stable SSH node IDs, and shared short-lived identities. Client
keys are RSA 3072. Host certificate validation handles Ed25519, ECDSA
P-256/P-384/P-521, and RSA SHA-2 signatures.

The package rejects leaf access, legacy listeners, FIPS mode, hardware-backed SSH
private-key policies, and automatic Device Trust enrollment. It does not implement
passwordless/headless flows, per-session MFA, access requests, or agent
forwarding. No direct SSH fallback exists.
Required message-of-the-day banners and SAML HTTP-POST authorization binding
are also unsupported. See [AUTHENTICATION.md](AUTHENTICATION.md).

The browser implementation uses a temporary IPv4 loopback listener and the
Teleport AES-GCM response protocol. A successful local callback test does not
establish compatibility with every identity provider or Apple app sandbox.
Real provider login, physical iPhone/iPad background/foreground, and sandboxed
Mac presentation remain release checks until their results are recorded.

Local browser MFA uses an existing passkey or security key in the browser and
then requests SSH/TLS certificates. The protocol was checked against source pin
`1283425b60ec5f60d509ba4c791183d452923ff7`. The current browser MFA change has
mock-server certificate tests and native loopback tests. Its real Teleport
18.11.4 test is pending: the pinned Chromium fixture build exceeded its download
time limit. Auth startup and user enrollment did not run for that attempt.
Physical keys and passkeys, browser UI, and device lifecycle are not verified by
these tests. Existing historical password/TOTP server results remain separate.

Optional Secure Enclave MFA supports custom non-resident P-256 credential
registration and local password login. The pinned 18.11.4 server accepted the
registration and login wire flow with an injected software test key. This proves
server interoperability only. Real Secure Enclave, Face ID/Touch ID, signed
Keychain storage, and physical-device behavior remain unverified. Fresh browser
management approval has loopback/mock coverage; its real browser UI is unverified.
Only an exact proxy-host RP ID is supported. Parent RP domains, resident or
passwordless credentials, direct hardware attestation, and incompatible
authenticator requirements are rejected. The new key does not satisfy hardware
SSH-key or Device Trust policy. See [AUTHENTICATION.md](AUTHENTICATION.md).

There is no native saved Apple passkey or PIV signing API. The package does not add Mosh,
Eternal Terminal, forwarding, databases, Kubernetes, desktop, or session joining.

Verification results and their exact limits are recorded in
[VALIDATION.md](VALIDATION.md). Local OpenSSH engine results are separate from
Teleport results.
