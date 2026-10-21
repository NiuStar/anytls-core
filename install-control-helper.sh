#!/bin/bash
# Prebuilt macOS installer. Password is handled only by native sudo.
set -euo pipefail
umask 077
[[ "$EUID" != 0 ]] || { printf '%s\n' 'Run as your normal user, never sudo/root.' >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || { printf '%s\n' 'Requires macOS arm64 or Intel x86_64.' >&2; exit 1; }
# Python selects native Apple Silicon even when invoked under Rosetta.
case "$(uname -m)" in
  arm64|x86_64|amd64) ;;
  *) printf '%s\n' 'Requires macOS arm64 or Intel x86_64.' >&2; exit 1 ;;
esac
command -v python3 >/dev/null || { printf '%s\n' 'Python 3 required: https://www.python.org/downloads/macos/' >&2; exit 1; }
command -v curl >/dev/null || { printf '%s\n' 'curl is required.' >&2; exit 1; }
app="$HOME/.anytls"
[[ ! -L "$app" ]] || { printf '%s\n' 'Refusing symlink app directory.' >&2; exit 1; }
mkdir -p "$app"
work="$(mktemp -d "$app/binary-bootstrap.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
printf '%s\n' '[AnyTLS] 正在下载安装组件（1/2）；网络无响应将超时报错，不会停止 VPN。' >&2
curl --fail --progress-bar --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 https://raw.githubusercontent.com/NiuStar/anytls-core/main/scripts/install.py -o "$work/install.py"
printf '%s\n' '[AnyTLS] 正在下载安装组件（2/2）…' >&2
curl --fail --progress-bar --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 180 https://raw.githubusercontent.com/NiuStar/anytls-core/main/scripts/install-binary.py -o "$work/install-binary.py"
printf '%s\n' '[AnyTLS] 安装组件已下载，开始校验和安装。' >&2
PYTHONDONTWRITEBYTECODE=1 python3 -I "$work/install-binary.py" "$@"
