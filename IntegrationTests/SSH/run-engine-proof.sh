#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VVTERM_ROOT="${VVTERM_ROOT:-$REPO_ROOT/../../vivy-company/vvterm}"

if [[ -z "${TELEPORT_LIBSSH2_ROOT:-}" ]] &&
   { [[ -z "${TELEPORT_LIBSSH2_INCLUDE:-}" ]] || [[ -z "${TELEPORT_LIBSSH2_LIBRARY:-}" ]]; }; then
    echo "Set TELEPORT_LIBSSH2_ROOT to an upstream-compatible libssh2 install prefix," >&2
    echo "or set both TELEPORT_LIBSSH2_INCLUDE and TELEPORT_LIBSSH2_LIBRARY." >&2
    exit 2
fi
SSH_INCLUDE="${TELEPORT_LIBSSH2_INCLUDE:-${TELEPORT_LIBSSH2_ROOT:-}/include}"
SSH_LIBRARY="${TELEPORT_LIBSSH2_LIBRARY:-${TELEPORT_LIBSSH2_ROOT:-}/lib/libssh2.a}"
CRYPTO_LIBRARY="${TELEPORT_LIBCRYPTO_LIBRARY:-$VVTERM_ROOT/Vendor/libssh2/macos/lib/libcrypto.a}"
for artifact in "$SSH_INCLUDE/libssh2.h" "$SSH_INCLUDE/libssh2_sftp.h" \
                "$SSH_LIBRARY" "$CRYPTO_LIBRARY"; do
    if [[ ! -f "$artifact" ]]; then
        echo "Missing SSH test input: $artifact" >&2
        exit 2
    fi
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/teleport-engine-proof.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
for check in engine-proof adapter-input-tests; do
    if ! cc -std=c11 -Wall -Wextra -Werror -UNDEBUG -I "$SCRIPT_DIR/include" \
        -I "$SSH_INCLUDE" "$SCRIPT_DIR/TeleportSSHEngine.c" "$SCRIPT_DIR/$check.c" \
        "$SSH_LIBRARY" "$CRYPTO_LIBRARY" -lz -o "$WORK_DIR/$check"; then
        echo "Use an upstream libssh2 build with host certificates and exit-status detection." >&2
        exit 2
    fi
done
"$WORK_DIR/adapter-input-tests"
python3 "$SCRIPT_DIR/engine-tests.py" --engine "$WORK_DIR/engine-proof" "$@"
