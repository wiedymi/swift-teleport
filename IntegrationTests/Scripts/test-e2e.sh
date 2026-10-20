#!/bin/sh
set -eu
SCRIPTS=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
suite=full
if [ "${1:-}" = --suite ]; then
  [ "$#" -ge 2 ] || { echo 'Missing suite.' >&2; exit 2; }
  suite=$2
  shift 2
fi
[ "${1:-}" != -- ] || shift
case "$suite" in
  infrastructure|transport|login|full|browser-mfa) ;;
  *) echo 'Suite must be infrastructure, transport, login, full, or browser-mfa.' >&2; exit 2 ;;
esac
if [ "$suite" != infrastructure ] && [ "$#" -eq 0 ]; then
  echo 'A native harness command is required after --. No native test was run.' >&2
  exit 2
fi
run_id=
cleanup() {
  if [ -n "$run_id" ]; then
    "$SCRIPTS/lab.sh" down --run-id "$run_id"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$suite" = transport ]; then
  fixture=$("$SCRIPTS/lab.sh" up --without-enrollment)
elif [ "$suite" = browser-mfa ]; then
  fixture=$("$SCRIPTS/lab.sh" up --browser-mfa)
else
  fixture=$("$SCRIPTS/lab.sh" up)
fi
run_dir=$(dirname -- "$(dirname -- "$fixture")")
run_id=$(basename -- "$run_dir")
if [ "$suite" = infrastructure ]; then
  cat "$run_dir/report.json"
elif [ "$suite" = browser-mfa ]; then
  TELEPORT_BROWSER_MFA_FIXTURE=$fixture "$@"
else
  TELEPORT_E2E_FIXTURE=$fixture TELEPORT_E2E_SUITE=$suite "$@"
fi
