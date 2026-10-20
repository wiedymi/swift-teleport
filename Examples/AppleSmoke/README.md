# Apple test app

This app uses the local package and the test-only C SSH adapter. It runs native
HTTPS discovery, two callers sharing one password/TOTP login, certificate
validation, node permissions, ProxySSH, commands, PTY resize, SFTP, and sign-out.
It displays a redacted report and writes `Documents/smoke-report.txt`.

Create the ignored `SmokeConfig.json` from a disposable lab fixture. The example
file shows its format. `httpsCA` is the base64 DER HTTPS CA. Use a proxy hostname
that the Simulator can resolve and reach, with that name in the HTTPS certificate.
The app installs no browser trust and does not run browser SSO.

The test app has one ATS exception for `teleport.localhost`. Apple's
[manual trust documentation](https://developer.apple.com/documentation/Foundation/performing-manual-server-trust-authentication)
requires this to let URLSession evaluate a private CA. The
[domain exception](https://developer.apple.com/documentation/BundleResources/Information-Property-List/NSExceptionAllowsInsecureHTTPLoads)
does not change the TLS or forward secrecy requirements. The package still
requires HTTPS and verifies the exact anchor, hostname, and dates. There is no
global or subdomain exception. A public CA proxy needs no such setting.
The live app test also requires discovery with the wrong HTTPS CA to fail.

Prepare the private config from an enrolled fixture:

```sh
python3 IntegrationTests/Scripts/prepare-apple-smoke.py /path/to/client/fixture.json
```

Supply a compatible upstream libssh2 build for each SDK. Pass `SSH_ENGINE_ROOT`
to Xcode. It must contain `include/`, `ios/lib/libssh2.a`, and
`ios-simulator/lib/libssh2.a`. Pass `SSH_CRYPTO_ROOT` for the matching OpenSSL
archives under `ios/lib/libcrypto.a` and `ios-simulator/lib/libcrypto.a`.
The engine must use matching OpenSSL headers and archives.
See [the engine contract](../../docs/SSH-ENGINE.md). This repository does not
download or build the engine.
Secure storage and the SSH engine remain the consuming app's responsibility.

The default is an arm64 iOS Simulator build with the default Xcode build cache:

```sh
xcodebuild -project Examples/AppleSmoke/TeleportSmoke.xcodeproj \
  -scheme TeleportSmoke -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  SSH_ENGINE_ROOT=/path/to/upstream-engine SSH_CRYPTO_ROOT=/path/to/matching-crypto \
  CODE_SIGNING_ALLOWED=NO build
```

Open the project in Xcode, select an arm64 iOS Simulator, and run the app.
The sample has no signing team. Device signing needs an explicit
`DEVELOPMENT_TEAM` build setting.

Press **Run test**
after a fresh TOTP interval if another client used this test user's current code.
For automation, launch the app with `--run-smoke` to start the same checks.
Remove the test app, ignored config, and disposable lab files after the checks.
Do not archive or distribute an app that contains the test credentials.

On 20 October 2026, the app passed all listed checks on the arm64 iPhone Duo
Simulator with iOS 27.1, using Teleport 18.11.4 on OrbStack 2.2.4 and a temporary
libssh2 1.11.1 test build with local changes. The wrong
HTTPS CA was rejected. Commands checked stdout and stderr on separate leases,
with exact output and exit status. The PTY check confirmed a live size change
from 24 by 80 to 43 by 121. SFTP compared 256 KiB exactly and removed its remote
file. Physical devices and browser SSO were not run. This result does not
validate a new upstream engine. The earlier local source changes are removed.
