# Protocol and source inputs

This is an independent implementation. The reference package was not imported
as source or as a dependency. No reference checkout is needed to build or test.
Teleport `lib/` files were read for wire facts only. They use AGPL terms; no code
from them was copied or translated. Source inspection is not test evidence.

| Input | Pin | Use |
| --- | --- | --- |
| Teleport Apache API | `1283425b60ec5f60d509ba4c791183d452923ff7` | Transport schema, auth resource schema, ALPN/name constants, protocol contract |
| cad0p/swift-teleport | `77a6bec824f079ce48468ac9a3cad3dda038d3d7` | Design and interoperability review only; no code copied |
| Historical libssh2 test engine | `1.11.1`, archive SHA-256 in `docs/ssh-engine-results.json` | Recorded test results only; source changes and build scripts removed |
| Runtime dependencies | exact versions and commits in `Package.resolved` | NIO, HTTP/2, Apple network transport, protobuf |

`Protos/transport_service.proto` is copied from the Apache-2.0
[upstream API schema](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/proto/teleport/transport/v1/transport_service.proto).
It is unchanged. `Protos/node_resources.proto` is a small adapted schema containing
the field numbers needed for node pages. It omits unrelated resources and uses
an internal package name. SwiftProtobuf 1.39.0 produces the checked-in Swift
messages. No build plugin or schema download runs in a consumer build.

`Protos/device_auth.proto` is an Apache-2.0 wire-compatible subset for the three
native device-registration RPCs and WebAuthn messages. It keeps original field
numbers/types and oneof selection, omits unrelated fields and service stubs, and
uses an internal package name. Its source files are listed in the schema header.
SwiftProtobuf 1.39.0 produced `device_auth.pb.swift`; it is checked in with its
notices. No schema/compiler tool is fetched by a consuming app.

The native credential contract was checked before implementation against the
pinned [Auth schema](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/proto/teleport/legacy/client/proto/authservice.proto),
[WebAuthn schema](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/proto/teleport/legacy/types/webauthn/webauthn.proto),
and [MFA scope schema](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/proto/teleport/mfa/v1/mfa.proto).
The independently written CBOR and WebAuthn responses follow those public wire
types and the standard ES256 signature format. Apple Security, CryptoKit, and
LocalAuthentication provide hardware operations. Real native registration/login was checked against
the separately pinned 18.11.4 image with a software test authenticator; this is not
a Secure Enclave or biometric result.

Discovery, local MFA, public CA export, and browser sign-in follow the HTTP wire
contract and real-server observations. The fixture pin is separate from the API
snapshot.

Local browser MFA was checked before implementation against the same source pin:

| Source | Wire fact checked |
| --- | --- |
| [Local login requests](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/client/weblogin.go) | Begin redirect field, finish assertion, public keys, and lifetime |
| [MFA types](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/client/mfatypes/mfatypes.go) | Browser challenge and response fields |
| [Browser approval](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/auth/browser_mfa.go) | One-use request, account, browser session, and WebAuthn checks |
| [Callback format](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/auth/internal/browsermfa/browser_mfa.go) | AES-GCM callback contains a WebAuthn assertion |
| [WebAuthn wire types](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/auth/webauthntypes/webauthn.go) | Credential, extension, and response byte fields |

The public v18.11.1 source has matching relevant fields; that source
check does not validate a browser approval on the pinned 18.11.4 server. Real
browser approval remains pending; native credential wire results are separate.

The internal route checks also used these files at the same source pin:

| Source | Wire fact checked |
| --- | --- |
| [Apache proxy client](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/client/proxy/client.go) | The SSH gRPC route uses a client certificate and the `teleport-proxy-ssh-grpc` hint |
| [ALPN route selection](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/srv/alpnproxy/proxy.go#L591-L611) | The first matching protocol in the client's offered order selects the route |
| [Server route setup](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/service/service.go#L6455-L6462) | The SSH gRPC route passes TLS to its internal mTLS server |

The pinned real server confirmed that the SSH route hint must precede `h2`;
that route then negotiates `h2`.

Trust contexts are separate: public HTTPS roots, host TLS roots for internal
routes, user TLS roots for issued credentials, SSH user CAs, and SSH host CAs.
They are never merged into a broad accept list.

The optional source pins in `refs/pins.json` are research aids only. No submodule,
recursive checkout, research tree, or reference code is a package input.

SSH integration tests now require a caller-supplied compatible upstream engine.
No engine is downloaded or built by this repository. See
[the engine contract](SSH-ENGINE.md) before selecting a build.

Third-party terms are recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
No Teleport executable or image is redistributed by the library. The lab operator
must use server artifacts under their applicable terms; a source license and an
image license are separate records.
