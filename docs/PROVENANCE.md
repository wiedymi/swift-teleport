# Protocol and source inputs

This is an independent implementation. The reference package was not imported
as source or as a dependency. No reference checkout is needed to build or test.

| Input | Pin | Use |
| --- | --- | --- |
| Teleport Apache API | `1283425b60ec5f60d509ba4c791183d452923ff7` | Transport schema, auth resource schema, ALPN/name constants, protocol contract |
| cad0p/swift-teleport | `77a6bec824f079ce48468ac9a3cad3dda038d3d7` | Design and interoperability review only; no code copied |
| libssh2 | `1.11.1`, archive SHA-256 in `docs/ssh-engine-results.json` | Test-only engine patch and proof |
| Runtime dependencies | exact versions and commits in `Package.resolved` | NIO, HTTP/2, Apple network transport, protobuf |

`Protos/transport_service.proto` is copied from the Apache-2.0
[upstream API schema](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/proto/teleport/transport/v1/transport_service.proto).
It is unchanged. `Protos/node_resources.proto` is a small adapted schema containing
the field numbers needed for node pages. It omits unrelated resources and uses
an internal package name. SwiftProtobuf 1.39.0 produces the checked-in Swift
messages. No build plugin or schema download runs in a consumer build.

Discovery, local MFA, public CA export, and browser sign-in are independently
implemented from the HTTP wire contract and real-server observations. Relevant
upstream implementation files under `lib/` use AGPL terms; none were copied or
translated into this package. Source inspection alone does not establish a
release test result. The real fixture is pinned separately from the API snapshot.

The internal route checks also used these files at the same source pin:

| Source | Wire fact checked |
| --- | --- |
| [Apache proxy client](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/api/client/proxy/client.go) | The SSH gRPC route uses a client certificate and the `teleport-proxy-ssh-grpc` hint |
| [ALPN route selection](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/srv/alpnproxy/proxy.go#L591-L611) | The first matching protocol in the client's offered order selects the route |
| [Server route setup](https://github.com/gravitational/teleport/blob/1283425b60ec5f60d509ba4c791183d452923ff7/lib/service/service.go#L6455-L6462) | The SSH gRPC route passes TLS to its internal mTLS server |

The two `lib/` files were read for wire facts only. No implementation was copied.
The pinned real server confirmed that the SSH route hint must precede `h2`;
that route then negotiates `h2`.

Trust contexts are separate: public HTTPS roots, host TLS roots for internal
routes, user TLS roots for issued credentials, SSH user CAs, and SSH host CAs.
They are never merged into a broad accept list.

The optional source pins in `refs/pins.json` are research aids only. No submodule,
recursive checkout, research tree, or reference code is a package input.

Third-party terms are recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
No Teleport executable or image is redistributed by the library. The lab operator
must use server artifacts under their applicable terms; a source license and an
image license are separate records.
