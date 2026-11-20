#!/bin/bash
# Check the embedded libswift_Concurrency.dylib of an IPA.
# 1. Is it even loaded? (rpath order of the main binary)
# 2. Does it match, code signature removed, a copy shipped in any installed Xcode?
# 3. Heuristics: linked libraries, suspicious imports, URLs.
# Usage: verify_dylib.sh path/to.ipa
set -u
W=$(mktemp -d)
unzip -q "$1" -d "$W/ipa"
APP=$(ls -d "$W"/ipa/Payload/*.app)
BIN="$APP/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Info.plist")"
DY="$APP/Frameworks/libswift_Concurrency.dylib"

echo "== Main binary LC_RPATH order (first match wins):"
otool -l "$BIN" | grep -A2 LC_RPATH | grep path
echo "== Main binary minimum tvOS:"
otool -l "$BIN" | grep -A4 LC_BUILD_VERSION | grep minos

echo "== Embedded dylib: archs, sha256, id, linked libraries"
lipo -archs "$DY"
shasum -a 256 "$DY"
otool -D "$DY" | tail -1
otool -L "$DY" | tail -n +2

echo "== Imports outside the Swift runtime / libSystem / Foundation basics:"
nm -um "$DY" | grep -v -E "from libSystem|from libswiftCore|from libobjc|from libc\+\+|from CoreFoundation|from Foundation|from libswift_" || echo "(none)"
echo "== Network or dynamic-loading symbols:"
nm -um "$DY" | grep -i -E "socket|connect|CFNetwork|NSURL|dlopen|dlsym|getaddrinfo|posix_spawn|system\b" || echo "(none)"
echo "== URLs / hosts in strings:"
strings -a "$DY" | grep -E -i "https?://|\.(com|net|org|io|ru|cn)\b" || echo "(none)"

echo "== Compare with copies shipped in installed Xcodes (signature removed, arm64 thin)"
cp "$DY" "$W/app.dylib"
codesign --remove-signature "$W/app.dylib" 2>/dev/null
lipo "$W/app.dylib" -thin arm64 -output "$W/app.thin" 2>/dev/null || cp "$W/app.dylib" "$W/app.thin"
APP_HASH=$(shasum -a 256 "$W/app.thin" | cut -d' ' -f1)
echo "app (unsigned, thin): $APP_HASH  size $(stat -f%z "$W/app.thin")"
MATCH=0
for ref in $(find /Applications/Xcode*.app -path '*appletvos*' -name libswift_Concurrency.dylib 2>/dev/null); do
  cp "$ref" "$W/ref.dylib"
  codesign --remove-signature "$W/ref.dylib" 2>/dev/null
  lipo "$W/ref.dylib" -thin arm64 -output "$W/ref.thin" 2>/dev/null || cp "$W/ref.dylib" "$W/ref.thin"
  H=$(shasum -a 256 "$W/ref.thin" | cut -d' ' -f1)
  [ "$H" = "$APP_HASH" ] && { echo "MATCH: $ref"; MATCH=1; } || echo "differs: $ref (size $(stat -f%z "$W/ref.thin"))"
done
[ $MATCH = 1 ] && echo "RESULT: dylib identical to an Apple Xcode copy" || echo "RESULT: no identical Xcode copy found"
