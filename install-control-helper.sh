#!/bin/bash
# Prebuilt macOS installer. Password is handled only by native sudo.
set -euo pipefail
umask 077
[[ "$EUID" != 0 ]] || { printf '%s\n' 'Run as your normal user, never sudo/root.' >&2; exit 1; }
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { printf '%s\n' 'Requires macOS Apple Silicon.' >&2; exit 1; }
command -v python3 >/dev/null || { printf '%s\n' 'Python 3 required: https://www.python.org/downloads/macos/' >&2; exit 1; }
command -v curl >/dev/null || { printf '%s\n' 'curl is required.' >&2; exit 1; }
app="$HOME/.anytls"
[[ ! -L "$app" ]] || { printf '%s\n' 'Refusing symlink app directory.' >&2; exit 1; }
mkdir -p "$app"
work="$(mktemp -d "$app/binary-bootstrap.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 https://raw.githubusercontent.com/NiuStar/anytls-core/main/scripts/install.py -o "$work/install.py"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 https://raw.githubusercontent.com/NiuStar/anytls-core/main/scripts/install-binary.py -o "$work/install-binary.py"
PYTHONDONTWRITEBYTECODE=1 python3 -I "$work/install-binary.py" "$@"
