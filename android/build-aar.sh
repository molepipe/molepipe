#!/usr/bin/env bash
#
# Build the gomobile .aar that the Android app consumes. Two stages:
#
#   1. cargo-ndk cross-compiles the torhost Rust shim (arti-client: onion-service
#      HOSTING + dialing) to a static library per ABI, copied where cgo links it
#      (backend/internal/tor/artihost/lib/<abi>/libtorhost.a).
#   2. gomobile bind compiles the Go backend — whose android build links those
#      .a files via cgo (see backend/internal/tor/artihost) — into app/libs/mobile.aar.
#
# One-time toolchain setup (Phase 7 §1):
#   - rustup + the Android std targets:
#       rustup target add aarch64-linux-android x86_64-linux-android
#   - cargo-ndk:  cargo install cargo-ndk
#   - gomobile + gobind, initialised once:
#       go install golang.org/x/mobile/cmd/gomobile@latest
#       go install golang.org/x/mobile/cmd/gobind@latest
#       gomobile init
#   - An NDK (API 21..36) via Android Studio > SDK Manager > NDK (Side by side).
#   - A JDK — Android Studio's bundled JBR is used automatically if none is on PATH.
#
# The preflight below fills in ANDROID_HOME / ANDROID_NDK_HOME / javac when they
# are unset, so a plain `./android/build-aar.sh` works; export any of them to
# override. Output: android/app/libs/mobile.aar.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
artihost_lib="$repo_root/backend/internal/tor/artihost/lib"
aar_out="$repo_root/android/app/libs/mobile.aar"

export PATH="$(go env GOPATH)/bin:$PATH"

# --- toolchain preflight ---------------------------------------------------
: "${ANDROID_HOME:=$HOME/Android/Sdk}"
export ANDROID_HOME

# Pick the highest-versioned side-by-side NDK if ANDROID_NDK_HOME is unset.
# `command ls` bypasses any `ls` shell alias (e.g. eza), whose decorated output
# would otherwise poison the path.
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ANDROID_NDK_HOME="$(command ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | sort -V | tail -1)"
  ANDROID_NDK_HOME="${ANDROID_NDK_HOME%/}"
  export ANDROID_NDK_HOME
fi
if [ ! -d "${ANDROID_NDK_HOME:-/nonexistent}" ]; then
  echo "error: no NDK found under $ANDROID_HOME/ndk. Install one via Android Studio >" >&2
  echo "       SDK Manager > SDK Tools > NDK (Side by side), or set ANDROID_NDK_HOME." >&2
  exit 1
fi

# gomobile needs javac. Fall back to Android Studio's bundled JBR if no JDK is
# on PATH.
if ! command -v javac >/dev/null 2>&1; then
  for jbr in "$HOME/android-studio/jbr" /opt/android-studio/jbr /usr/local/android-studio/jbr; do
    if [ -x "$jbr/bin/javac" ]; then
      export JAVA_HOME="$jbr"
      export PATH="$jbr/bin:$PATH"
      break
    fi
  done
fi
if ! command -v javac >/dev/null 2>&1; then
  echo "error: javac not found. Install a JDK, or ensure Android Studio's JBR exists." >&2
  exit 1
fi

echo "ANDROID_NDK_HOME=$ANDROID_NDK_HOME"
echo "javac=$(command -v javac)"

# Go ABI  ->  cargo-ndk ABI  ->  Rust target triple. Keep in step with the
# gomobile -target list below and the per-ABI ldflags_*.go files in artihost.
abis=("arm64:arm64-v8a:aarch64-linux-android" "amd64:x86_64:x86_64-linux-android")

echo "== stage 1: cargo-ndk build torhost per ABI =="
cd "$repo_root/torhost"
for entry in "${abis[@]}"; do
  IFS=':' read -r goabi ndkabi triple <<<"$entry"
  echo "-- $ndkabi ($triple)"
  cargo ndk -t "$ndkabi" build --release --lib
  dest="$artihost_lib/$goabi"
  mkdir -p "$dest"
  cp "target/$triple/release/libtorhost.a" "$dest/libtorhost.a"
done

echo "== stage 2: gomobile bind =="
mkdir -p "$(dirname "$aar_out")"
cd "$repo_root/backend"

# Stamp the same version identity into the AAR that build-release.sh stamps into
# the desktop binaries, so /api/version reports the real build on Android too
# (otherwise it links as "dev"/"unknown", which the update path can't compare).
# VERSION defaults to the git tag; override by exporting VERSION=…
VERSION="${VERSION:-$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || echo dev)}"
GIT_COMMIT="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
verpkg="github.com/molepipe/molepipe/backend/internal/version"
gomobile bind \
  -target=android/arm64,android/amd64 \
  -androidapi 24 \
  -ldflags="-X ${verpkg}.Version=${VERSION} -X ${verpkg}.GitCommit=${GIT_COMMIT}" \
  -o "$aar_out" \
  ./mobile

echo "wrote $aar_out"
