#!/bin/bash
# Short prebuilt installer entry; the legacy helper URL remains supported.
set -euo pipefail
umask 077
[[ "$EUID" != 0 ]] || { printf '%s\n' 'Run as your normal user, never sudo/root.' >&2; exit 1; }
work="$(mktemp -d "${TMPDIR:-$HOME}/anytls-entry.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
if ! curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 \
  https://raw.githubusercontent.com/NiuStar/anytls-core/main/install-control-helper.sh -o "$work/install.sh"; then
  printf '%s\n' '[AnyTLS] raw 下载失败，改用官方 GitHub API…' >&2
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 \
    -H 'Accept: application/vnd.github.raw+json' \
    'https://api.github.com/repos/NiuStar/anytls-core/contents/install-control-helper.sh?ref=main' -o "$work/install.sh"
fi
IFS= read -r first_line < "$work/install.sh" && [[ "$first_line" == '#!/bin/bash' ]] || {
  printf '%s\n' 'Invalid installer response (expected Bash script).' >&2; exit 1;
}
bash "$work/install.sh" "$@"
