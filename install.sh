#!/bin/bash
# Official source-only bootstrap. Never stops services or writes system paths.
set -euo pipefail
umask 077
[[ "$EUID" != 0 ]] || { printf '%s\n' 'Run installer as your normal user, never root/sudo.' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Python 3 required. Install from https://www.python.org/downloads/macos/ then rerun. No system packages installed.' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { printf '%s\n' 'curl is required.' >&2; exit 1; }
VERSION="${VERSION:-}"
args=(--install-toolchain "$@")
explicit_version=false
for ((j=0; j<${#args[@]}; j++)); do
  if [[ "${args[j]}" == --version ]]; then
    (( j+1 < ${#args[@]} )) || { printf '%s\n' '--version requires a value' >&2; exit 1; }
    [[ "$explicit_version" == false ]] || { printf '%s\n' 'duplicate --version' >&2; exit 1; }
    explicit_version=true
    VERSION="${args[j+1]}"
  fi
done
# Bootstrap stays on main: older tags may not contain an installer at all.
ref=main
if [[ -n "$VERSION" ]]; then
  python3 -I -c 'import datetime,re,sys; v=sys.argv[1]; d=re.fullmatch(r"v([0-9]{4}-[0-9]{2}-[0-9]{2})-[0-9]{2}",v); valid=bool(d or re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",v)); assert valid,"Invalid stable version (not a URL)"; datetime.date.fromisoformat(d[1]) if d else None' "$VERSION"
  [[ "$explicit_version" == true ]] || args+=(--version "$VERSION")
fi
app="$HOME/.anytls"
[[ ! -L "$app" ]] || { printf '%s\n' 'App directory must not be a symlink' >&2; exit 1; }
mkdir -p "$app"
work="$(mktemp -d "$app/install-bootstrap.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
base="https://raw.githubusercontent.com/NiuStar/anytls-core/$ref/scripts"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 "$base/install.py" -o "$work/install.py"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 "$base/go-patched.py" -o "$work/go-patched.py"
# Running the official installer explicitly permits a private, checksum-verified
# Go 1.26.8 download if no exact toolchain is already installed.
PYTHONDONTWRITEBYTECODE=1 python3 -I "$work/install.py" --wrapper "$work/go-patched.py" "${args[@]}"
