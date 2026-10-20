#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VVTERM_ROOT="${VVTERM_ROOT:-$(cd "$REPO_ROOT/../../vivy-company/vvterm" && pwd)}"
if [[ $# != 1 ]]; then
    echo "usage: build-apple-engines.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi
mkdir -p "$1"
OUTPUT_DIR="$(cd "$1" && pwd)"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/teleport-apple-ssh.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

curl --fail --silent --show-error --location --retry 3 --retry-all-errors --retry-delay 1 \
    https://www.libssh2.org/download/libssh2-1.11.1.tar.gz \
    --output "$WORK_DIR/libssh2.tar.gz"
echo "d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7  $WORK_DIR/libssh2.tar.gz" |
    shasum -a 256 --check --status
curl --fail --silent --show-error --location --retry 3 --retry-all-errors --retry-delay 1 \
    https://www.openssl.org/source/old/3.2/openssl-3.2.0.tar.gz \
    --output "$WORK_DIR/openssl.tar.gz"
echo "14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e  $WORK_DIR/openssl.tar.gz" |
    shasum -a 256 --check --status
tar -xzf "$WORK_DIR/libssh2.tar.gz" -C "$WORK_DIR"
tar -xzf "$WORK_DIR/openssl.tar.gz" -C "$WORK_DIR"
SOURCE="$WORK_DIR/libssh2-1.11.1"
OPENSSL_SOURCE="$WORK_DIR/openssl-3.2.0"
for name in exit-status-presence host-certificates failed-kex-cleanup; do
    patch --batch --fuzz=0 -p1 -d "$SOURCE" < "$REPO_ROOT/patches/libssh2/$name.patch" >&2
done

for platform in macos ios ios-simulator; do
    case "$platform" in
        macos)
            sdk=macosx
            target=arm64-apple-macos13.3
            openssl_target=darwin64-arm64-cc
            openssl_options=(no-shared no-tests)
            host_option=(--host=aarch64-apple-darwin)
            ;;
        ios)
            sdk=iphoneos
            target=arm64-apple-ios16.1
            openssl_target=ios64-xcrun
            openssl_options=(no-shared no-tests no-apps)
            host_option=(--host=arm-apple-darwin)
            ;;
        ios-simulator)
            sdk=iphonesimulator
            target=arm64-apple-ios16.1-simulator
            openssl_target=iossimulator-xcrun
            openssl_options=(no-shared no-tests no-apps)
            host_option=(--host=arm-apple-darwin)
            ;;
    esac
    sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"
    compiler="$(xcrun --sdk "$sdk" -f clang) -target $target -isysroot $sdk_path"
    prefix="$WORK_DIR/openssl-$platform"
    build="$WORK_DIR/build-$platform"
    mkdir -p "$prefix/lib" "$build" "$OUTPUT_DIR/$platform/lib"
    # Configure only headers. The original VVTerm crypto archive is the linked
    # backend; this script does not compile a second OpenSSL implementation.
    if ! (cd "$OPENSSL_SOURCE" &&
        ./Configure "$openssl_target" "${openssl_options[@]}" &&
        make build_generated) > "$WORK_DIR/openssl-$platform.log" 2>&1; then
        tail -n 60 "$WORK_DIR/openssl-$platform.log" >&2
        exit 1
    fi
    cp -R "$OPENSSL_SOURCE/include" "$prefix/include"
    ln -s "$VVTERM_ROOT/Vendor/libssh2/$platform/lib/libcrypto.a" "$prefix/lib/libcrypto.a"
    ln -s "$VVTERM_ROOT/Vendor/libssh2/$platform/lib/libssl.a" "$prefix/lib/libssl.a"
    if ! (cd "$build" && CC="$compiler" \
        "$SOURCE/configure" "${host_option[@]}" \
            --disable-shared --enable-static --disable-examples-build \
            --with-crypto=openssl --with-libssl-prefix="$prefix" &&
        make -C src -j4) > "$WORK_DIR/libssh2-$platform.log" 2>&1; then
        tail -n 80 "$WORK_DIR/libssh2-$platform.log" >&2
        exit 1
    fi
    cp "$build/src/.libs/libssh2.a" "$OUTPUT_DIR/$platform/lib/libssh2.a"
    if [[ "$platform" == macos ]]; then
        mkdir -p "$OUTPUT_DIR/include" "$OUTPUT_DIR/lib"
        cp "$build/src/.libs/libssh2.a" "$OUTPUT_DIR/lib/libssh2.a"
        cp "$SOURCE/include/libssh2.h" "$SOURCE/include/libssh2_sftp.h" \
            "$SOURCE/include/libssh2_publickey.h" "$OUTPUT_DIR/include/"
        for test_name in host-import-tests failed-setup-cleanup-test; do
            cc -std=c11 -Wall -Wextra -Werror -UNDEBUG -DHAVE_CONFIG_H \
                -I "$build/src" -I "$SOURCE/src" -I "$SOURCE/include" -I "$prefix/include" \
                "$SCRIPT_DIR/$test_name.c" "$OUTPUT_DIR/lib/libssh2.a" \
                "$prefix/lib/libcrypto.a" -lz -o "$OUTPUT_DIR/$test_name"
        done
        "$OUTPUT_DIR/failed-setup-cleanup-test" 1 >&2
        rm "$OUTPUT_DIR/failed-setup-cleanup-test"
    fi
    python3 - "$OUTPUT_DIR" "$VVTERM_ROOT" "$platform" "$target" "$sdk_path" <<'PY'
import hashlib,json,pathlib,sys
output=pathlib.Path(sys.argv[1]); vendor=pathlib.Path(sys.argv[2])/'Vendor/libssh2'
platform,target,sdk=sys.argv[3:]
paths={'libssh2':output/platform/'lib/libssh2.a',
       'libcrypto':vendor/platform/'lib/libcrypto.a',
       'libssl':vendor/platform/'lib/libssl.a'}
data={'libssh2_version':'1.11.1','openssl_header_version':'3.2.0',
      'openssl_archive_version':'3.2.0','target':target,'sdk':pathlib.Path(sdk).name,
      'sha256':{name:hashlib.sha256(p.read_bytes()).hexdigest() for name,p in paths.items()}}
(output/platform/'artifacts.json').write_text(json.dumps(data,indent=2)+'\n')
PY
    echo "Built $platform with OpenSSL 3.2.0 headers and original crypto archive." >&2
done
python3 - "$OUTPUT_DIR" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
data={'libssh2_source_sha256':'d9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7',
      'openssl_source_sha256':'14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e',
      'platforms':{name:json.loads((root/name/'artifacts.json').read_text())
                   for name in ['macos','ios','ios-simulator']}}
(root/'artifacts.json').write_text(json.dumps(data,indent=2)+'\n')
PY
printf 'export TELEPORT_LIBSSH2_INCLUDE=%q\n' "$OUTPUT_DIR/include"
printf 'export TELEPORT_LIBSSH2_LIBRARY=%q\n' "$OUTPUT_DIR/lib/libssh2.a"
printf 'export TELEPORT_LIBCRYPTO_LIBRARY=%q\n' "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libcrypto.a"
printf 'export TELEPORT_LIBSSL_LIBRARY=%q\n' "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libssl.a"
