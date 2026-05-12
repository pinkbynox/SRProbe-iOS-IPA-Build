#!/bin/zsh
set -euo pipefail

# Usage:
#   ./build_and_export_ipa.sh TEAMID com.your.bundle.SRProbe
# Example:
#   ./build_and_export_ipa.sh ABCD123456 com.greenbynox.SRProbe

TEAM_ID="${1:-}"
BUNDLE_ID="${2:-com.greenbynox.SRProbe}"

if [[ -z "$TEAM_ID" ]]; then
  echo "Usage: $0 TEAM_ID BUNDLE_ID"
  exit 1
fi

/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" SRProbe/Info.plist 2>/dev/null || true

xcodebuild \
  -project SRProbe.xcodeproj \
  -scheme SRProbe \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -archivePath build/SRProbe.xcarchive \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  PRODUCT_BUNDLE_IDENTIFIER="$BUNDLE_ID" \
  CODE_SIGN_STYLE=Automatic \
  clean archive

cat > build/ExportOptions.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key>
  <string>development</string>
  <key>signingStyle</key>
  <string>automatic</string>
  <key>teamID</key>
  <string>$TEAM_ID</string>
  <key>compileBitcode</key>
  <false/>
  <key>stripSwiftSymbols</key>
  <true/>
</dict>
</plist>
PLIST

xcodebuild \
  -exportArchive \
  -archivePath build/SRProbe.xcarchive \
  -exportPath build/export \
  -exportOptionsPlist build/ExportOptions.plist

find build/export -name '*.ipa' -maxdepth 2 -print
