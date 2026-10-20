#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VVTERM_ROOT="${VVTERM_ROOT:-$(cd "$REPO_ROOT/../../vivy-company/vvterm" && pwd)}"
OPENSSL_INCLUDE_DIR="${OPENSSL_INCLUDE_DIR:-/opt/homebrew/opt/openssl@3/include}"
OPENSSL_PREFIX="${OPENSSL_INCLUDE_DIR%/include}"

if [[ $# != 1 ]]; then
    echo "usage: build-engine.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi
if [[ ! -f "$OPENSSL_INCLUDE_DIR/openssl/opensslv.h" ]]; then
    echo "Set OPENSSL_INCLUDE_DIR to installed OpenSSL 3 headers." >&2
    exit 2
fi
for artifact in libssh2 libssl libcrypto; do
    test -f "$VVTERM_ROOT/Vendor/libssh2/macos/lib/$artifact.a"
done
mkdir -p "$1"
OUTPUT_DIR="$(cd "$1" && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/teleport-ssh-build.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

curl --fail --location --silent --show-error \
    https://www.libssh2.org/download/libssh2-1.11.1.tar.gz \
    --output "$WORK_DIR/source.tar.gz"
echo "d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7  $WORK_DIR/source.tar.gz" |
    shasum -a 256 --check --status
tar -xzf "$WORK_DIR/source.tar.gz" -C "$WORK_DIR"
SOURCE="$WORK_DIR/libssh2-1.11.1"
patch --batch --fuzz=0 -p1 -d "$SOURCE" < "$REPO_ROOT/patches/libssh2/exit-status-presence.patch" >&2
patch --batch --fuzz=0 -p1 -d "$SOURCE" < "$REPO_ROOT/patches/libssh2/host-certificates.patch" >&2

if ! (cd "$SOURCE" &&
    CC="cc -arch arm64 -mmacosx-version-min=13.3" \
    ./configure --disable-shared --enable-static --disable-examples-build \
        --with-crypto=openssl --with-libssl-prefix="$OPENSSL_PREFIX" &&
    make -C src -j4) > "$WORK_DIR/build.log" 2>&1; then
    tail -n 60 "$WORK_DIR/build.log" >&2
    exit 1
fi

# First establish the upstream failure, then test the narrow cleanup change.
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG -DHAVE_CONFIG_H \
    -I "$SOURCE/src" -I "$SOURCE/include" -I "$OPENSSL_INCLUDE_DIR" \
    "$SCRIPT_DIR/failed-setup-cleanup-test.c" "$SOURCE/src/.libs/libssh2.a" \
    "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libcrypto.a" -lz \
    -o "$WORK_DIR/cleanup-before"
"$WORK_DIR/cleanup-before" 0 >&2
patch --batch --fuzz=0 -p1 -d "$SOURCE" < "$REPO_ROOT/patches/libssh2/failed-kex-cleanup.patch" >&2
rm -f "$SOURCE/src/session.lo" "$SOURCE/src/session.o" "$SOURCE/src/.libs/session.o"
rm -f "$SOURCE/src/libssh2.la" "$SOURCE/src/.libs/libssh2.a"
if ! make -C "$SOURCE/src" -j4 > "$WORK_DIR/cleanup-build.log" 2>&1; then
    tail -n 60 "$WORK_DIR/cleanup-build.log" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR/include" "$OUTPUT_DIR/lib"
cp "$SOURCE/src/.libs/libssh2.a" "$OUTPUT_DIR/lib/libssh2.a"
cp "$SOURCE/include/libssh2.h" "$SOURCE/include/libssh2_sftp.h" \
    "$SOURCE/include/libssh2_publickey.h" "$OUTPUT_DIR/include/"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG -DHAVE_CONFIG_H \
    -I "$SOURCE/src" -I "$SOURCE/include" -I "$OPENSSL_INCLUDE_DIR" \
    "$SCRIPT_DIR/host-import-tests.c" "$OUTPUT_DIR/lib/libssh2.a" \
    "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libcrypto.a" -lz \
    -o "$OUTPUT_DIR/host-import-tests"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG -DHAVE_CONFIG_H \
    -I "$SOURCE/src" -I "$SOURCE/include" -I "$OPENSSL_INCLUDE_DIR" \
    "$SCRIPT_DIR/failed-setup-cleanup-test.c" "$OUTPUT_DIR/lib/libssh2.a" \
    "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libcrypto.a" -lz \
    -o "$WORK_DIR/cleanup-after"
if ! "$WORK_DIR/cleanup-after" 1 >&2; then
    sed -n '942,970p' "$SOURCE/src/session.c" >&2
    cat "$WORK_DIR/cleanup-build.log" >&2
    exit 1
fi
python3 - "$VVTERM_ROOT" "$REPO_ROOT" "$OUTPUT_DIR" <<'PY'
import hashlib, json, pathlib, sys
vendor = pathlib.Path(sys.argv[1]) / 'Vendor/libssh2'
repo = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])
paths = [vendor / platform / 'lib' / name
         for platform in ['ios', 'ios-simulator', 'macos']
         for name in ['libssh2.a', 'libcrypto.a', 'libssl.a']]
paths += [repo / 'patches/libssh2/host-certificates.patch',
          repo / 'patches/libssh2/exit-status-presence.patch',
          repo / 'patches/libssh2/failed-kex-cleanup.patch',
          output / 'lib/libssh2.a']
inventory = {
    'source_version': '1.11.1',
    'source_sha256': 'd9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7',
    'artifacts': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
}
(output / 'artifacts.json').write_text(json.dumps(inventory, indent=2) + '\n')
PY

printf 'export TELEPORT_LIBSSH2_INCLUDE=%q\n' "$OUTPUT_DIR/include"
printf 'export TELEPORT_LIBSSH2_LIBRARY=%q\n' "$OUTPUT_DIR/lib/libssh2.a"
printf 'export TELEPORT_LIBCRYPTO_LIBRARY=%q\n' "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libcrypto.a"
printf 'export TELEPORT_LIBSSL_LIBRARY=%q\n' "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libssl.a"
