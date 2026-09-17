#!/usr/bin/env bash
#
# Full iOS build pipeline: Rust static libs → gomobile XCFramework → xcodegen →
# xcodebuild. This is the top-level script a developer runs on macOS to produce
# a runnable .app or .ipa.
#
# Prerequisites (macOS only):
#   - Xcode with iOS SDK
#   - Rust toolchain (rustup)
#   - gomobile + gobind (go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init)
#   - xcodegen (brew install xcodegen)
#
# Usage:
#   cd ios && bash build-app.sh [--device | --simulator]
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

target="simulator"  # default
if [ "${1:-}" = "--device" ]; then
  target="device"
elif [ "${1:-}" = "--simulator" ]; then
  target="simulator"
fi

echo "=== Molepipe iOS build (target: $target) ==="

# Step 1: Rust static libraries
echo ""
echo "--- step 1/4: torhost static libraries ---"
bash "$script_dir/build-torhost.sh"

# Step 2: gomobile XCFramework
echo ""
echo "--- step 2/4: gomobile XCFramework ---"
bash "$script_dir/build-xcframework.sh"

# Step 3: xcodegen
echo ""
echo "--- step 3/4: xcodegen ---"
if ! command -v xcodegen >/dev/null 2>&1; then
  echo "error: xcodegen not found. Install with: brew install xcodegen" >&2
  exit 1
fi
cd "$script_dir"
xcodegen generate

# Step 4: xcodebuild
echo ""
echo "--- step 4/4: xcodebuild ---"
if [ "$target" = "simulator" ]; then
  # Find the first available iOS Simulator destination
  DESTINATION="$(xcodebuild -project Molepipe.xcodeproj -scheme Molepipe -showdestinations 2>/dev/null \
    | grep 'platform:iOS Simulator' | head -1 | sed 's/.*destination:"\(.*\)".*/\1/')"
  if [ -z "$DESTINATION" ]; then
    DESTINATION="platform=iOS Simulator,name=iPhone 16,OS=latest"
  fi
  echo "Destination: $DESTINATION"
  xcodebuild -project Molepipe.xcodeproj -scheme Molepipe \
    -destination "$DESTINATION" \
    -configuration Debug build 2>&1 | tail -20
else
  echo "For device builds, open Molepipe.xcodeproj in Xcode and run from there."
  echo "(xcodebuild for device requires code signing configuration.)"
fi

echo ""
echo "=== done ==="
