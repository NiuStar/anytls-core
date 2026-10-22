#!/bin/bash
# Short prebuilt installer entry; the legacy helper URL remains supported.
set -euo pipefail
umask 077
[[ "$EUID" != 0 ]] || { printf '%s\n' 'Run as your normal user, never sudo/root.' >&2; exit 1; }
work="$(mktemp -d "${TMPDIR:-$HOME}/anytls-entry.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 \
  https://raw.githubusercontent.com/NiuStar/anytls-core/main/install-control-helper.sh -o "$work/install.sh"
bash "$work/install.sh" "$@"
