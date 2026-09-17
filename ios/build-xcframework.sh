#!/usr/bin/env bash
#
# Build the Molepipe.xcframework that the iOS app consumes. This wraps the Go
# backend (backend/mobile) into an XCFramework via gomobile bind.
#
# Prerequisites (macOS only):
#   - The Rust static libraries must already be built (run ios/build-torhost.sh)
#   - gomobile + gobind installed and initialised:
#       go install golang.org/x/mobile/cmd/gomobile@latest
#       go install golang.org/x/mobile/cmd/gobind@latest
#       gomobile init
#
# Output: ios/Molepipe.xcframework
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
output="$repo_root/ios/Molepipe.xcframework"

export PATH="$(go env GOPATH)/bin:$PATH"

# Verify gomobile is available.
if ! command -v gomobile >/dev/null 2>&1; then
  echo "error: gomobile not found. Install with:" >&2
  echo "  go install golang.org/x/mobile/cmd/gomobile@latest" >&2
  echo "  go install golang.org/x/mobile/cmd/gobind@latest" >&2
  echo "  gomobile init" >&2
  exit 1
fi

# Verify the Rust static libraries exist.
for lib in "$repo_root/backend/internal/tor/artihost/lib/ios-arm64/libtorhost.a" \
           "$repo_root/backend/internal/tor/artihost/lib/iossim-arm64/libtorhost.a"; do
  if [ ! -f "$lib" ]; then
    echo "error: missing $lib" >&2
    echo "Run ios/build-torhost.sh first." >&2
    exit 1
  fi
done

echo "== gomobile bind (iOS + iOS Simulator) =="

# VERSION defaults to the git tag; override by exporting VERSION=…
VERSION="${VERSION:-$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || echo dev)}"
GIT_COMMIT="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
verpkg="github.com/molepipe/molepipe/backend/internal/version"

cd "$repo_root/backend"
gomobile bind \
  -target=ios,iossimulator \
  -iosversion 16.0 \
  -ldflags="-X ${verpkg}.Version=${VERSION} -X ${verpkg}.GitCommit=${GIT_COMMIT}" \
  -o "$output" \
  ./mobile

echo "wrote $output"
