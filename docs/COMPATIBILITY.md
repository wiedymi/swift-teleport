# Compatibility and verification

The lab pins Teleport Community **18.11.4** by image digest in
[versions.lock.json](../IntegrationTests/Docker/versions.lock.json). Other server
majors are rejected. Other v18 patches need separate validation.

Support is limited to one root cluster with TLS routing and stable SSH node IDs.
Each login creates an RSA 3072 key for SSH/TLS certificates. Optional biometric
MFA uses a separate P-256 key. Host certificate checks support Ed25519,
ECDSA P-256/P-384/P-521, and RSA SHA-2 signatures.

| Authentication method | Test evidence | Remaining limits |
| --- | --- | --- |
| Password/TOTP | Real pinned-server login and issued identity checks | Other server versions need validation |
| Local browser MFA | Mock certificate endpoint and authenticated loopback tests | Real browser approval, physical keys/passkeys, and Apple app lifecycle remain unverified |
| Optional Secure Enclave MFA | Real registration/login protocol with a software test key; mock browser management approval | Real Secure Enclave, biometrics, signed Keychain, recovery, and browser management UI remain unverified |
| GitHub/OIDC/SAML browser SSO | Local encrypted callback and identity checks | Real provider login and sandboxed/device presentation remain unverified |

Browser flows use an IPv4 loopback listener and Teleport's authenticated AES-GCM
callback. Local callback tests do not prove provider or platform compatibility.
Secure Enclave credentials are non-resident MFA credentials; the RP must exactly
match the proxy host. They cannot satisfy hardware SSH-key or Device Trust policy.
See [Authentication](AUTHENTICATION.md) for protocol and security choices.

Unsupported:

- Leaf clusters, legacy listeners, FIPS, hardware SSH-key policies, and automatic
  Device Trust enrollment.
- Passwordless/headless login, native saved Apple passkeys, PIV, per-session MFA,
  access requests, and agent forwarding.
- Parent-domain RP configurations, required resident credentials, direct hardware
  attestation, and incompatible authenticator requirements.
- Required login banners and SAML HTTP-POST authorization binding.
- Mosh, Eternal Terminal, other forwarding, databases, Kubernetes, desktop, and
  session joining. There is no direct SSH fallback.

The [validation record](VALIDATION.md) separates passed, skipped, historical, and
unverified checks. Historical SSH engine results do not validate the selected
upstream engine; see [SSH engine requirements](SSH-ENGINE.md).
