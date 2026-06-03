#!/bin/bash
set -e
CDM="${1:-/workspace/mem_layout_agent/libwidevinecdm.so}"
VERSION="${3:-4.10.2710.0}"          # just the on-disk dir name + manifest string
URL="${2:-about:blank}"              # e.g. http://localhost:8080/index.html?auto=full&...
FIREFOX=/usr/bin/firefox
PROFILE="/tmp/ff-cdm-$(basename "$CDM" .so)"

rm -rf "$PROFILE"; mkdir -p "$PROFILE/gmp-widevinecdm/$VERSION"
cp "$CDM" "$PROFILE/gmp-widevinecdm/$VERSION/libwidevinecdm.so"
cat > "$PROFILE/gmp-widevinecdm/$VERSION/manifest.json" <<EOF
{"name":"WidevineCdm","description":"Widevine CDM","version":"$VERSION",
 "x-cdm-module-versions":"4","x-cdm-interface-versions":"10",
 "x-cdm-host-versions":"10","x-cdm-codecs":"vp8,vp09,avc1"}
EOF
cat > "$PROFILE/prefs.js" <<'EOF'
user_pref("media.eme.enabled", true);
user_pref("media.gmp-widevinecdm.enabled", true);
user_pref("media.gmp-widevinecdm.visible", true);
user_pref("media.gmp-widevinecdm.abi", "x86_64-gcc3");
// --- the bits that make Firefox use the LOCAL .so instead of downloading ---
user_pref("media.gmp-widevinecdm.forceInstalled", true);
user_pref("media.gmp-widevinecdm.hasLocalCDM", true);
user_pref("media.gmp-widevinecdm.autoupdate", false);
user_pref("media.gmp-manager.updateEnabled", false);
user_pref("media.gmp-manager.checkContentSignature", false);
user_pref("media.gmp-manager.cert.requireBuiltIn", false);
EOF
# the version pref must match the dir name above
echo "user_pref(\"media.gmp-widevinecdm.version\", \"$VERSION\");" >> "$PROFILE/prefs.js"

echo "[launch] firefox=$FIREFOX"
echo "[launch] CDM=$CDM  (version dir $VERSION)"
echo "[launch] profile=$PROFILE  url=$URL"
exec "$FIREFOX" -profile "$PROFILE" -no-remote -new-instance "$URL"
