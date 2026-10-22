# Compatibility and verification

The lab pins Teleport Community **18.11.4** by image digest in
[versions.lock.json](../IntegrationTests/Docker/versions.lock.json). Other server
majors are rejected. Other v18 patches need separate validation.

Support is limited to one root cluster with TLS routing and stable SSH node IDs.
Each login creates an RSA 3072 key for SSH/TLS certificates. Device authentication
uses a separate P-256 key. Host certificate checks support Ed25519,
ECDSA P-256/P-384/P-521, and RSA SHA-2 signatures.

| Authentication method | Test evidence | Remaining limits |
| --- | --- | --- |
| Password/TOTP | Real pinned-server login and issued identity checks | Other server versions need validation |
| Local browser MFA | Mock certificate endpoint and authenticated loopback tests | Real browser approval, physical keys/passkeys, and Apple app lifecycle remain unverified |
| Passwordless device key | Real headless approval, setup-identity registration, and passwordless login with a software test key; focused binding and policy tests | Real browser approval, Secure Enclave, biometrics, signed Keychain, and recovery remain unverified |
| Password-based device MFA | Real registration/login protocol with a software test key; mock browser management approval | Real Secure Enclave, biometrics, signed Keychain, recovery, and browser management UI remain unverified |
| GitHub/OIDC/SAML browser SSO | Local encrypted callback and identity checks | Real provider login and sandboxed/device presentation remain unverified |

Passwordless setup is for local accounts with `allow_headless` and
`allow_passwordless` enabled. It needs an existing web passkey or security key;
TOTP cannot approve the headless request. The 60-second setup identity stays in
memory. A second browser approval can be required for device management.
The flow uses short-lived certificates and has no refresh token.

Local browser MFA, device-management approval, and SSO use Teleport's
authenticated AES-GCM loopback callback. Headless setup instead uses its verified
HTTPS response. Callback tests do not prove browser or platform compatibility.
The new device credential is resident in app-owned protected storage; it is not
a saved Apple passkey. Older MFA-only records need explicit local and server
removal before registration for passwordless use. The RP must exactly match the
proxy host. Neither device mode satisfies hardware SSH-key or Device Trust policy.
See [Authentication](AUTHENTICATION.md) for protocol and security choices.

Unsupported:

- Leaf clusters, legacy listeners, FIPS, hardware SSH-key policies, and automatic
  Device Trust enrollment.
- General headless login, native saved Apple passkeys, PIV, per-session MFA,
  access requests, and agent forwarding. Headless is internal to device setup.
- Parent-domain RP configurations, direct hardware attestation, and incompatible
  authenticator requirements.
- Required login banners and SAML HTTP-POST authorization binding.
- Mosh, Eternal Terminal, other forwarding, databases, Kubernetes, desktop, and
  session joining. There is no direct SSH fallback.

The [validation record](VALIDATION.md) separates passed, skipped, historical, and
unverified checks. Software-key results do not prove Secure Enclave behavior.
Historical SSH engine results do not validate the selected upstream engine; see
[SSH engine requirements](SSH-ENGINE.md).
