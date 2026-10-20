# SSH engine adapter

`TeleportKit` does not include an SSH engine. The optional package in
`IntegrationTests/SSH` uses VVTerm's libssh2 archives to test the public socket
API. The C adapter accepts a connected descriptor. It does not run `tsh` or
implement Teleport HTTP, TLS, or protobuf rules.

## Required host-certificate patch

The checked VVTerm archives report libssh2 **1.11.1** and OpenSSL **3.2.0**.
The existing VVTerm patch adds exit-status presence detection. All nine archive
hashes match VVTerm's native artifact manifest. See
[the recorded results](ssh-engine-results.json) for exact hashes.

Stock 1.11.1 supports user certificates. Its RSA and ECDSA host-certificate
entries have no import or signature-verification function. Its Ed25519
certificate entry uses the plain-key importer, which rejects a certificate.
Thus, a certificate name in the archive does not establish host-certificate
support. The local test reproduces this failure with the actual macOS archive.
These facts follow the pinned [host-key source](https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/src/hostkey.c)
and [key-exchange selection](https://github.com/libssh2/libssh2/blob/libssh2-1.11.1/src/kex.c).

`patches/libssh2/host-certificates.patch` adds bounded certificate import for
Ed25519, ECDSA P-256/P-384/P-521, and RSA. It imports the certified public key
into the existing cryptographic backend for key-exchange signature checks.
It preserves the complete certificate returned by `libssh2_session_hostkey`.
User authentication still sends the issued user certificate.

`failed-kex-cleanup.patch` releases the imported host-key context when initial
key exchange fails before NEWKEYS. Its regression check confirms that upstream
code omits the destructor and the patched code calls it once.

The patch does **not** decide CA trust, time validity, principals, or critical
options. The caller must validate the complete host certificate after key
exchange and before user authentication. The public package supplies this check
through `TeleportConnection.verifyHostCertificate`. The C adapter requires a
host verifier callback. Its local fixture CLI uses exact signed-certificate
comparison only. The patch and copied libssh2 notice use BSD-3-Clause terms.

## Run the local proof

Requirements: macOS arm64, a C compiler, `make`, `curl`, Python 3, system
`ssh-keygen` and `sshd`, OpenSSL 3 headers, and the VVTerm vendor archives.
Set `VVTERM_ROOT` if VVTerm is not in the usual sibling repository path.
Set `OPENSSL_INCLUDE_DIR` if headers are not at the default Homebrew path.

```sh
IntegrationTests/SSH/run-engine-proof.sh
```

The script verifies the upstream archive SHA-256, applies all three patches, builds
one test archive, starts a loopback-only OpenSSH fixture, and runs the tests.
Temporary source, keys, server files, and executables are removed on exit.
The script does not change the VVTerm checkout or install a server service.

To build the optional Swift harness, first create one reusable test archive:

```sh
IntegrationTests/SSH/build-engine.sh /tmp/teleport-test-engine > /tmp/teleport-test-engine.env
source /tmp/teleport-test-engine.env
swift build --package-path IntegrationTests/SSH --configuration release
```

Remove the chosen output directory and environment file after use. The build
script removes its own downloaded source. The root package has no libssh2 or
OpenSSL dependency. Archive selection exists only in the test manifest.
SwiftPM uses its default build cache.

For macOS, iOS, and simulator archives with original OpenSSL 3.2.0 headers, use
`build-apple-engines.sh OUTPUT_DIRECTORY`. It creates the headers without
compiling OpenSSL, then links each build against the corresponding VVTerm
crypto archive. It removes downloaded source after all three builds finish.

## Socket and operation ownership

Keep the public `TeleportConnection` alive. Transfer its descriptor once to
`teleport_ssh_run_command`. This C call owns and closes that descriptor on every
return. It finishes native SSH cleanup before closing. The package owns the
other socket end. Closing the package connection wakes blocked test I/O.
The host verifier callback returns **0 to accept**, and nonzero to reject.

Call this test-only synchronous adapter on a dedicated queue. Setup uses
nonblocking libssh2 calls, `poll` readiness, and one deadline. Native teardown
has a separate short limit. There is no timer-based retry loop.

The operation enum selects command execution, PTY allocation plus resize, or a
small SFTP round trip. PTY starts at 80 columns by 24 rows. A running remote
probe checks that size, installs a WINCH trap, and reports readiness. The adapter
then requests 121 columns by 43 rows. The trap reports the new size. There is no
fixed delay or server-side resize command. The SFTP test creates a new file with exclusive-create,
checks the returned bytes, and removes the file. A failed connection can leave
the remote test file; the disposable fixture also removes its test directory.
Output has an explicit capacity supplied by the caller.

## Recorded checks: 20 October 2026

The local proof passed **34 checks** on macOS 27.2 arm64 with Apple clang 21
and OpenSSH 10.5p1. It proves SSH engine behavior, not Teleport routing or login.
Eight additional input tests verify bounds and descriptor cleanup. A native
cleanup regression verifies release of a host key after failed initial KEX.

| Check | Result |
| --- | --- |
| Exact stock archive, user certificates over a pinned plain host key | Ed25519, ECDSA P-256, RSA passed |
| Exact stock archive, certificate-only host negotiation | All five host key types failed |
| Patched archive, host and user certificates | All 15 pairs below passed |
| Full host-certificate byte retrieval | Passed for all five host key types |
| Truncated certificate at every byte offset, extra trailing byte, user certificate as host | Rejected for all five types |
| Changed key-exchange signature | Rejected |
| Expired user certificate, denied OS login | Rejected |
| Host-verifier rejection before user authentication | Rejected |
| Live PTY WINCH probe after resize | Returned `43 121` |
| SFTP write, read, compare, remove | Passed |

| Certified host key | User Ed25519 | User ECDSA P-256 | User RSA |
| --- | --- | --- | --- |
| Ed25519 | Passed | Passed | Passed |
| ECDSA P-256 | Passed | Passed | Passed |
| ECDSA P-384 | Passed | Passed | Passed |
| ECDSA P-521 | Passed | Passed | Passed |
| RSA with SHA-512 | Passed | Passed | Passed |

These fixtures use Ed25519 CA keys. RSA SHA-256 host negotiation, other CA key
types, FIPS, and Apple device execution are not established by this matrix.
iOS and simulator archives were also built for arm64 with a 16.1 deployment
target. The macOS target remains 13.3. This local matrix executes only macOS.

The final patched builds use original OpenSSL **3.2.0 headers** and each
platform's exact VVTerm OpenSSL **3.2.0 archive**. All downloaded source was
removed. No patched binary is shipped in this repository.
