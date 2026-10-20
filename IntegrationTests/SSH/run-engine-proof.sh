#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VVTERM_ROOT="${VVTERM_ROOT:-$(cd "$REPO_ROOT/../../vivy-company/vvterm" && pwd)}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/teleport-engine-proof.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

"$SCRIPT_DIR/build-engine.sh" "$WORK_DIR/engine" > "$WORK_DIR/engine.env"
source "$WORK_DIR/engine.env"
cc -std=c11 -Wall -Wextra -Werror -I "$SCRIPT_DIR/include" \
    -I "$VVTERM_ROOT/Vendor/libssh2/include" \
    "$SCRIPT_DIR/TeleportSSHEngine.c" "$SCRIPT_DIR/engine-proof.c" \
    "$VVTERM_ROOT/Vendor/libssh2/macos/lib/libssh2.a" \
    "$TELEPORT_LIBCRYPTO_LIBRARY" -lz -o "$WORK_DIR/stock-proof"
cc -std=c11 -Wall -Wextra -Werror -I "$SCRIPT_DIR/include" \
    -I "$TELEPORT_LIBSSH2_INCLUDE" \
    "$SCRIPT_DIR/TeleportSSHEngine.c" "$SCRIPT_DIR/engine-proof.c" \
    "$TELEPORT_LIBSSH2_LIBRARY" "$TELEPORT_LIBCRYPTO_LIBRARY" -lz \
    -o "$WORK_DIR/patched-proof"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG -I "$SCRIPT_DIR/include" \
    -I "$TELEPORT_LIBSSH2_INCLUDE" \
    "$SCRIPT_DIR/TeleportSSHEngine.c" "$SCRIPT_DIR/adapter-input-tests.c" \
    "$TELEPORT_LIBSSH2_LIBRARY" "$TELEPORT_LIBCRYPTO_LIBRARY" -lz \
    -o "$WORK_DIR/adapter-input-tests"
"$WORK_DIR/adapter-input-tests"
python3 "$SCRIPT_DIR/engine-tests.py" --stock "$WORK_DIR/stock-proof" \
    --patched "$WORK_DIR/patched-proof" \
    --import-test "$WORK_DIR/engine/host-import-tests" "$@"
