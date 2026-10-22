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
# Python.org builds can lack their default CA bundle although macOS curl works.
# Use the existing system PEM only when Python has no loaded default CA at all;
# preserve an explicitly configured SSL_CERT_FILE/SSL_CERT_DIR, including errors.
if [[ -z "${SSL_CERT_FILE+x}" && -z "${SSL_CERT_DIR+x}" && -r /etc/ssl/cert.pem ]] &&
  python3 -I -c 'import ssl,sys; default=ssl.create_default_context(); system=ssl.create_default_context(cafile="/etc/ssl/cert.pem"); sys.exit(0 if default.cert_store_stats()["x509_ca"] == 0 and system.cert_store_stats()["x509_ca"] > 0 else 1)' 2>/dev/null; then
  export SSL_CERT_FILE=/etc/ssl/cert.pem
  printf '%s\n' '[AnyTLS] Python 默认 CA 缺失，本次安装使用 macOS CA 文件（保持证书校验，不修改系统配置）。' >&2
fi
printf '%s\n' '[AnyTLS] 安装组件已下载，开始校验和安装。' >&2
PYTHONDONTWRITEBYTECODE=1 python3 -I "$work/install-binary.py" "$@"
