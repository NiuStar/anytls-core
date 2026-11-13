#!/bin/bash
# Build only; no launch, production installation, or network access.
set -euo pipefail
[ "$#" -le 2 ] || { printf 'Usage: build-menubar.sh [arm64|amd64] [out]\n' >&2; exit 2; }
ARCH="${1-arm64}"
case "$ARCH" in
  arm64) MACHINE=arm64 ;;
  amd64) MACHINE=x86_64 ;;
  *) printf 'Unsupported architecture: %s\n' "$ARCH" >&2; exit 2 ;;
esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${2:-$ROOT/macos/build}"
[ "$(uname -s)" = Darwin ] || { printf 'macOS required\n' >&2; exit 1; }
[ "$(uname -m)" = "$MACHINE" ] || { printf 'Native %s host required\n' "$MACHINE" >&2; exit 2; }
: "${CORE:?Set CORE to an explicit qualified local native core image; no download fallback}"
[ -f "$CORE" ] || exit 2
/usr/bin/lipo "$CORE" -verify_arch "$MACHINE"
[ "$(/usr/bin/lipo -archs "$CORE")" = "$MACHINE" ] || { printf 'Core must be %s only\n' "$MACHINE" >&2; exit 2; }
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
APP="$OUT/AnyTLSMenuBar.app"
[ ! -e "$APP" ] || { printf 'Refusing to overwrite existing app\n' >&2; exit 2; }
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/runtime" "$OUT/test"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
SHARED=("$ROOT/macos/Model.swift" "$ROOT/macos/Connectivity.swift" "$ROOT/macos/Client.swift" "$ROOT/macos/QuitCoordinator.swift")
UI=("${SHARED[@]}" "$ROOT/macos/DesktopMigration.swift" "$ROOT/macos/DesktopRuntime.swift" "$ROOT/macos/main.swift")
xcrun swiftc -swift-version 5 -parse-as-library -O -sdk "$SDK" -target "$MACHINE-apple-macosx13.0" "${UI[@]}" -framework AppKit -framework Security -o "$APP/Contents/MacOS/AnyTLSMenuBar"
[ "$(/usr/bin/lipo -archs "$APP/Contents/MacOS/AnyTLSMenuBar")" = "$MACHINE" ] || { printf 'UI must be %s only\n' "$MACHINE" >&2; exit 2; }
cp "$CORE" "$APP/Contents/Resources/runtime/anytls-macos"
chmod 755 "$APP/Contents/Resources/runtime/anytls-macos"
/usr/bin/codesign --force --sign - "$APP/Contents/Resources/runtime/anytls-macos"
CORE_VERSION="$($APP/Contents/Resources/runtime/anytls-macos -version)"
# Pure -version only; no desktop prepare/inspect or service commands during build.
python3 -c 'import hashlib,json,pathlib,plistlib,sys
app=pathlib.Path(sys.argv[1]); runtime=app/"Contents/Resources/runtime"
# Go prints its version with the standard prefix; metadata uses currentVersion().
v=sys.argv[2].strip().removeprefix("anytls-macos ").removeprefix("AnyTLS ")
(runtime/"manifest.json").write_text(json.dumps(dict(schema=1,binary="anytls-macos",arch=sys.argv[3],version=v,sha256=hashlib.sha256((runtime/"anytls-macos").read_bytes()).hexdigest()),sort_keys=True)+"\n")
p=dict(CFBundleIdentifier="org.anytls.menubar.candidate",CFBundleName="AnyTLSMenuBar",CFBundleDisplayName="AnyTLS 菜单栏",CFBundleExecutable="AnyTLSMenuBar",CFBundlePackageType="APPL",CFBundleShortVersionString="0.5.5",CFBundleVersion="0.5.5.20261112.1",AnyTLSCoreVersion=v,LSMinimumSystemVersion="13.0",LSUIElement=True,NSHighResolutionCapable=True,NSAppTransportSecurity={"NSAllowsLocalNetworking":True})
with (app/"Contents/Info.plist").open("wb") as f: plistlib.dump(p,f)' "$APP" "$CORE_VERSION" "$ARCH"
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --strict --deep "$APP"
xcrun swiftc -swift-version 5 -O -sdk "$SDK" -target "$MACHINE-apple-macosx13.0" "${SHARED[@]}" "$ROOT/macos/Tests.swift" "$ROOT/macos/KnownFailureTests.swift" -o "$OUT/test/AnyTLSMenuBarTests"
xcrun swiftc -swift-version 5 -O -sdk "$SDK" -target "$MACHINE-apple-macosx13.0" "${SHARED[@]}" "$ROOT/macos/QuitTests.swift" -o "$OUT/test/QuitTests"
xcrun swiftc -swift-version 5 -O -sdk "$SDK" -target "$MACHINE-apple-macosx13.0" "$ROOT/macos/Connectivity.swift" "$ROOT/macos/ConnectivityTests.swift" -o "$OUT/test/ConnectivityTests"
for spec in 'FOCUS_TESTS FocusTests' 'DESKTOP_TESTS DesktopRuntimeTests'; do
  flag="${spec%% *}"; name="${spec#* }"
  xcrun swiftc -swift-version 5 -O -D "$flag" -parse-as-library -sdk "$SDK" -target "$MACHINE-apple-macosx13.0" "${UI[@]}" "$ROOT/macos/$name.swift" -framework AppKit -framework Security -o "$OUT/test/$name"
done
printf 'Built %s (%s only), core %s\n' "$APP" "$MACHINE" "$CORE_VERSION"
