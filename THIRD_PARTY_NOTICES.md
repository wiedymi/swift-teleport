# Third-party notices

The package's original Swift code uses the MIT license in `LICENSE`.

The Teleport API schemas and their SwiftProtobuf output retain Gravitational's
Apache-2.0 notice. See `Protos/`, `docs/PROVENANCE.md`, and
`licenses/Apache-2.0.txt`. The source pin is separate from the test image pin.

The runtime graph is locked in `Package.resolved` and listed in
`docs/dependencies.spdx.json`:

| Package | Version | License |
| --- | --- | --- |
| swift-nio | 2.104.0 | Apache-2.0, with component notices |
| swift-nio-http2 | 1.46.0 | Apache-2.0, with component notices |
| swift-nio-transport-services | 1.28.0 | Apache-2.0 |
| swift-protobuf | 1.39.0 | Apache-2.0 with Swift runtime library exception |
| swift-atomics | 1.3.1 | Apache-2.0 with Swift runtime library exception |
| swift-collections | 1.7.3 | Apache-2.0 with Swift runtime library exception |
| swift-system | 1.8.1 | Apache-2.0 with Swift runtime library exception |

Retain the dependency license and notice files when distributing compiled code.
The copied NIO and HTTP/2 notices are under `licenses/`. NIO includes llhttp
under MIT terms and other components listed in its notice. SwiftProtobuf's
bundled compiler sources are build-tool inputs, not part of this library's
runtime target.

The original test-only C SSH code uses the BSD-3-Clause terms in
[licenses/BSD-3-Clause.txt](licenses/BSD-3-Clause.txt), as stated in its source
files. It is not linked into the public library product. Tests link caller-supplied
libssh2 and OpenSSL archives under those libraries' own terms.
This repository distributes no libssh2 source, source changes, or engine binary.

The test server image, Debian base, Chromium, Playwright, Node, and their system
packages are test tools only. The library does not ship them. The Docker lab
does not grant a server distribution or Enterprise license. Its operator must
use the selected artifacts under their own terms.

The Teleport name identifies protocol compatibility only. This project has no
affiliation with Teleport or its publisher.
