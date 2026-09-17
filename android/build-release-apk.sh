#!/usr/bin/env bash
# Build the signed release APK: the hand-to-a-tester Android build, the mobile
# counterpart of tools/build-release.sh (which does desktop).
#
# Two stages:
#   1. build-aar.sh — (re)builds mobile.aar with the version stamped in, so the
#      backend's /api/version reports this build (not "dev").
#   2. gradle assembleRelease — links the AAR into an APK, signed with the
#      release key IF an untracked keystore.properties exists at the repo root.
#
# Signing: no signing secret is committed. When keystore.properties is absent the
# APK still builds — unsigned — and Android will refuse to install it; the script
# says so. Generate a key once (keep the keystore + passwords OUT of git):
#
#   keytool -genkeypair -v -keystore ~/molepipe-release.jks \
#       -alias onionchat -keyalg RSA -keysize 4096 -validity 10000
#
# then write repo-root keystore.properties (git-ignored) with:
#   storeFile=/home/you/molepipe-release.jks
#   storePassword=…
#   keyAlias=molepipe
#   keyPassword=…
#
# The SAME key must sign every release: Android only installs an update over an
# existing app when both are signed by the same key. That same-key rule is the
# update path's integrity guarantee — a differently-signed APK cannot replace an
# installed build, so a tester can go N -> N+1 by installing a newer APK without
# the developer touching the device.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

# Version identity, shared with the AAR stamp and the desktop release:
#   versionName — human string from the git tag (e.g. v1.2.3, v1.2.3-5-gabcdef).
#   versionCode — MUST strictly increase per release; Android compares only this
#     to decide "is this build newer". Total commit count is monotonic across
#     releases and needs no tag discipline. Override either via env.
VERSION="${VERSION:-$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION_CODE="${VERSION_CODE:-$(git -C "$repo_root" rev-list --count HEAD 2>/dev/null || echo 1)}"
export VERSION  # build-aar.sh reads it for the ldflags stamp

echo "== stage 1: build AAR (version ${VERSION}) =="
VERSION="$VERSION" "$repo_root/android/build-aar.sh"

echo "== stage 2: gradle assembleRelease (versionCode ${VERSION_CODE}, versionName ${VERSION}) =="
# gradle needs a JDK. Fall back to Android Studio's bundled JBR like build-aar.sh.
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/javac" ]; then
  for jbr in "$HOME/android-studio/jbr" /opt/android-studio/jbr /usr/local/android-studio/jbr; do
    if [ -x "$jbr/bin/javac" ]; then export JAVA_HOME="$jbr"; break; fi
  done
fi

cd "$repo_root/android"
./gradlew :app:assembleRelease --console=plain \
  -PonionVersionCode="$VERSION_CODE" \
  -PonionVersionName="$VERSION"

apk_dir="$repo_root/android/app/build/outputs/apk/release"
signed_apk="$apk_dir/app-release.apk"
unsigned_apk="$apk_dir/app-release-unsigned.apk"

echo
if [ -f "$signed_apk" ]; then
  echo "wrote SIGNED release APK: $signed_apk"
  echo "  versionCode=$VERSION_CODE versionName=$VERSION"
elif [ -f "$unsigned_apk" ]; then
  echo "wrote UNSIGNED release APK: $unsigned_apk" >&2
  echo "  No keystore.properties at repo root, so the APK is unsigned and will" >&2
  echo "  NOT install. See the header of this script to generate a signing key." >&2
  exit 2
else
  echo "error: no release APK produced under $apk_dir" >&2
  exit 1
fi
