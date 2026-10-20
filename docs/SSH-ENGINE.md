# SSH engine adapter

`TeleportKit` does not include an SSH engine. The app supplies one. The optional
test package in `IntegrationTests/SSH` checks that engine through the public
socket API. Its C adapter does not implement Teleport HTTP, TLS, or protobuf.
This repository does not download, build, or modify libssh2.

## Engine contract

The engine must:

1. Negotiate the issued user certificate and an OpenSSH host certificate.
2. Verify the key-exchange signature with the certified host key.
3. Return the complete host certificate to the caller before user authentication.
4. Expose whether the server sent an exit status, including status zero.
5. Release imported host keys after failed key exchange.

The host callback calls `TeleportConnection.verifyHostCertificate`. The package
checks the CA, signature, dates, host principal, and critical options. A key
fingerprint alone is not sufficient.

A libssh2 build must include the required host-certificate support. The
checked upstream commit
[`3209951`](https://github.com/libssh2/libssh2/commit/3209951db4e47ef902db047d12f9f464f835c27e)
includes host certificates, failed-key-exchange cleanup, and exit-status presence
detection. These changes are not yet in a release. Pin the selected upstream
commit in the consuming app and run the checks below before use. The existing
reports do not validate that build.

## Check an external build

Supply a macOS arm64 static library and its matching headers. The library must
use a compatible OpenSSL build. With an `include/` and `lib/` directory:

```sh
export TELEPORT_LIBSSH2_ROOT=/path/to/upstream-libssh2
export TELEPORT_LIBCRYPTO_LIBRARY=/path/to/matching-openssl/lib/libcrypto.a
IntegrationTests/SSH/run-engine-proof.sh
swift build --package-path IntegrationTests/SSH --configuration release
```

Alternatively, set `TELEPORT_LIBSSH2_INCLUDE` to the header directory and
`TELEPORT_LIBSSH2_LIBRARY` to the static archive. Set both overrides together.
Set `TELEPORT_LIBCRYPTO_LIBRARY` to the matching static OpenSSL archive.
No path is inferred from another project or a system installation.
These are test inputs only; the root package has no libssh2 or OpenSSL dependency.

The local proof needs macOS arm64, a C compiler, Python 3, and system `ssh-keygen`
and `sshd`. It starts a loopback-only OpenSSH fixture and checks the supplied
engine. It removes temporary keys, server files, and executables on exit. It
does not modify the external engine or install a server service. The caller owns
and removes the external engine build. Use `--report /path/to/report.json` to save the result.
The current proof has 24 engine checks and eight adapter bounds/descriptor checks.
SwiftPM uses its default build cache.

For the iOS test app, supply platform archives through `SSH_ENGINE_ROOT`. See
[the Apple test app instructions](../Examples/AppleSmoke/README.md).

## Socket and operation ownership

Keep the public `TeleportConnection` alive. Transfer its descriptor once to
`teleport_ssh_run_command`. This synchronous C call owns and closes that descriptor
on every return, after native SSH cleanup. The package owns the other socket end.
Closing the package connection wakes blocked test I/O. The host callback returns
**0 to accept**, and nonzero to reject.

Run the adapter on a dedicated queue. It uses nonblocking libssh2 calls, `poll`
readiness, and one deadline. Native teardown has a separate short limit.

The adapter supports commands, PTY allocation and resize, and an SFTP round trip.
The PTY probe reports its initial size, waits for a window change, and reports
the new size. The SFTP check creates a file with exclusive-create, compares the
returned bytes, and removes the file. A failed session can leave that file in
the disposable fixture. The caller supplies an explicit output capacity.

## Test limits

Earlier engine checks used a modified libssh2 1.11.1 build. That build and its
changes are removed. Those results do not validate the selected upstream engine;
rerun the proof and live tests with matching headers and crypto libraries.
A platform build alone does not prove a device session. See
[Validation](VALIDATION.md). No SSH engine binary is distributed by this repository.
