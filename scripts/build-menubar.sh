#!/bin/bash
# Build only; no launch, production installation, or network access.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${1:-arm64}"
OUT="${2:-$ROOT/macos/build}"
[ "$ARCH" = arm64 ] || { printf 'Unified app is ARM64 ONLY\n' >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || { printf 'macOS required\n' >&2; exit 1; }
: "${CORE:?Set CORE to an explicit qualified local arm64 core image; no download fallback}"
[ -f "$CORE" ] || exit 2
/usr/bin/lipo "$CORE" -verify_arch arm64
[ "$(/usr/bin/lipo -archs "$CORE")" = arm64 ] || { printf 'Core must be arm64 only\n' >&2; exit 2; }
VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
APP="$OUT/AnyTLSMenuBar.app"
[ ! -e "$APP" ] || { printf 'Refusing to overwrite existing app\n' >&2; exit 2; }
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/runtime" "$OUT/test"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
SHARED=("$ROOT/macos/Model.swift" "$ROOT/macos/Connectivity.swift" "$ROOT/macos/Client.swift" "$ROOT/macos/QuitCoordinator.swift")
UI=("${SHARED[@]}" "$ROOT/macos/DesktopMigration.swift" "$ROOT/macos/DesktopRuntime.swift" "$ROOT/macos/main.swift")
xcrun swiftc -swift-version 5 -parse-as-library -O -sdk "$SDK" -target arm64-apple-macosx13.0 "${UI[@]}" -framework AppKit -framework Security -o "$APP/Contents/MacOS/AnyTLSMenuBar"
cp "$CORE" "$APP/Contents/Resources/runtime/anytls-macos"
chmod 755 "$APP/Contents/Resources/runtime/anytls-macos"
/usr/bin/codesign --force --sign - "$APP/Contents/Resources/runtime/anytls-macos"
CORE_VERSION="$($APP/Contents/Resources/runtime/anytls-macos -version)"
# Pure -version only; no desktop prepare/inspect or service commands during build.
python3 - "$APP" "$CORE_VERSION" <<'PY'
import hashlib,json,pathlib,plistlib,sys
app=pathlib.Path(sys.argv[1]); runtime=app/'Contents/Resources/runtime'
# Go prints its version with the standard prefix; metadata uses currentVersion().
v=sys.argv[2].strip().removeprefix('anytls-macos ').removeprefix('AnyTLS ')
(runtime/'manifest.json').write_text(json.dumps(dict(schema=1,binary='anytls-macos',arch='arm64',version=v,sha256=hashlib.sha256((runtime/'anytls-macos').read_bytes()).hexdigest()),sort_keys=True)+'\n')
p=dict(CFBundleIdentifier='org.anytls.menubar.candidate',CFBundleName='AnyTLSMenuBar',CFBundleDisplayName='AnyTLS 菜单栏',CFBundleExecutable='AnyTLSMenuBar',CFBundlePackageType='APPL',CFBundleShortVersionString='0.4.0',CFBundleVersion='0.4.0.20261107.2',AnyTLSCoreVersion=v,LSMinimumSystemVersion='13.0',LSUIElement=True,NSHighResolutionCapable=True,NSAppTransportSecurity={'NSAllowsLocalNetworking':True})
with (app/'Contents/Info.plist').open('wb') as f: plistlib.dump(p,f)
PY
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --strict --deep "$APP"
xcrun swiftc -swift-version 5 -O -sdk "$SDK" "${SHARED[@]}" "$ROOT/macos/Tests.swift" -o "$OUT/test/AnyTLSMenuBarTests"
xcrun swiftc -swift-version 5 -O -sdk "$SDK" "${SHARED[@]}" "$ROOT/macos/QuitTests.swift" -o "$OUT/test/QuitTests"
xcrun swiftc -swift-version 5 -O -sdk "$SDK" "$ROOT/macos/Connectivity.swift" "$ROOT/macos/ConnectivityTests.swift" -o "$OUT/test/ConnectivityTests"
for spec in 'FOCUS_TESTS FocusTests' 'DESKTOP_TESTS DesktopRuntimeTests'; do
  read -r flag name <<< "$spec"
  xcrun swiftc -swift-version 5 -O -D "$flag" -parse-as-library -sdk "$SDK" "${UI[@]}" "$ROOT/macos/$name.swift" -framework AppKit -framework Security -o "$OUT/test/$name"
done
printf 'Built %s (arm64 only), core %s\n' "$APP" "$CORE_VERSION"
