# TeleportKit

A native Swift package for SSH access through a Teleport proxy. The package
handles sign-in, short-lived credentials, node lookup, and the proxy byte path.
Your SSH engine handles commands, terminals, PTY, and SFTP.

Requires Swift 6.2 or later with the checked-in dependency lock, and
iOS/iPadOS 16.1 or later or macOS 13.3 or later.
There is one public product: `TeleportKit`. No Go runtime, `tsh`, server binary,
UI framework, or SSH engine is part of the product.

```swift
import Foundation
import TeleportKit

let proxy = try TeleportProxy(url: URL(string: "https://teleport.example.com")!)
let client = TeleportClient(proxy: proxy, identityStore: myAtomicSecureStore)

try await client.login(username: username, password: password, otp: oneTimeCode)
let node = try await client.resolveNode(stableNodeID)
let connection = try await client.connect(to: node, login: "alice")
let socket = try connection.takeSocketDescriptor()
```

Pass that socket and the connection's issued SSH certificate and private key to
your SSH engine. After key exchange, call `connection.verifyHostCertificate`
with the complete host certificate **before** user authentication. Keep the
connection alive until the engine stops. The engine owns the transferred socket
and must close it after all SSH calls stop.

Share one client per proxy/account profile across tabs and nodes. The default
store is memory only. The app supplies durable, atomic secure storage and browser
presentation. Credentials must not enter cloud configuration sync.

Local users can approve a password login with an existing passkey or security key
in the system browser:

```swift
try await client.login(username: username, password: password, browser: myBrowserPresenter)
```

This is separate from browser SSO. The server must permit browser MFA.
Real-server browser MFA and physical-key validation are pending; see
[the authentication contract](docs/AUTHENTICATION.md) and test limits below.

Optional Secure Enclave MFA adds device credential setup, biometric local-password
login, and local deletion. The library owns the key and WebAuthn protocol. Apps
supply screens, prompt text, browser presentation, Keychain configuration, and
signing settings. See [setup and recovery](docs/INTEGRATION.md#optional-biometric-device-credential).
Native registration/login passed against the pinned server with a software test
key. Real Secure Enclave and biometric behavior still need signed-device checks.

Read [the integration contract](docs/INTEGRATION.md),
[the tested scope](docs/COMPATIBILITY.md), and
[the SSH engine requirements](docs/SSH-ENGINE.md).

SSH integration tests require a caller-supplied compatible upstream libssh2
build with matching crypto libraries. This repository does not download or build
an SSH engine.

## Checks

```sh
swift test
swift build -c release
```

The [real-server test lab](IntegrationTests/README.md) uses pinned server images,
two allowed nodes, one denied node, and verified TLS. Its separate test package
uses the same public API an app uses. It does not use `tsh` to implement the Swift
client. The test wrapper removes its containers, networks, credentials, and run
files on exit. A lab started with `lab.sh up` needs an explicit `lab.sh down`.

The source/protocol inputs are recorded in [provenance](docs/PROVENANCE.md).
This project is independent and is not affiliated with Teleport or its publisher.

See [the authentication contract](docs/AUTHENTICATION.md) for app storage,
browser callbacks, and unsupported policy requirements. Required login banners
and SAML HTTP-POST authorization binding are unsupported.
