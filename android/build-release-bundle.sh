#!/usr/bin/env bash
# Build the signed release BUNDLE (.aab) — the artifact Google Play takes.
# Sibling of build-release-apk.sh, which builds the APK you hand straight to a
# tester. The difference matters:
#
#   APK    one file containing every ABI, installable by anyone with adb.
#   AAB    not installable. Play splits it per device, so a phone downloads one
#          ABI instead of both — which for this app is the difference between a
#          ~145 MB download and roughly half that, because almost all the weight
#          is libgojni.so (the Go backend plus Arti) built for arm64 and x86_64.
#
# Two stages, same as the APK script:
#   1. build-aar.sh — (re)builds mobile.aar with the version stamped in, so the
#      backend's /api/version reports this build and not "dev".
#   2. gradle bundleRelease — links the AAR, runs R8, signs with the release key.
#
# VERSION / VERSION_CODE must be set explicitly unless the tree is clean AND
# tagged. A store listing shows versionName to users and keys every future
# update off versionCode, so neither is allowed to come out of a dirty working
# tree by accident:
#
#   VERSION=1.0.0 VERSION_CODE=1 ./android/build-release-bundle.sh
#
# versionCode MUST strictly increase for every upload Play ever accepts, and a
# number can never be reused — not even after deleting a draft release. Keep it
# simple and monotonic.
#
# Signing: no secret is committed. An unsigned bundle is useless (Play rejects
# it), so this script fails rather than writing one. See the header of
# build-release-apk.sh for generating a key and writing keystore.properties.
#
# The same key must sign every upload. If this is the first upload, enrol in
# Play App Signing — then this key is only the UPLOAD key, and Google can reset
# it for you if it is ever lost, which is not true of the app signing key.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

described="$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || echo dev)"
if [ -z "${VERSION:-}" ] || [ -z "${VERSION_CODE:-}" ]; then
  case "$described" in
    *-dirty|*dev)
      echo "error: refusing to guess the version of a store build." >&2
      echo "       git describe says '$described', which would put that string in" >&2
      echo "       front of users as the app's version." >&2
      echo >&2
      echo "       Set both explicitly:" >&2
      echo "         VERSION=1.0.0 VERSION_CODE=1 $0" >&2
      exit 1
      ;;
  esac
fi
VERSION="${VERSION:-$described}"
VERSION_CODE="${VERSION_CODE:-$(git -C "$repo_root" rev-list --count HEAD)}"
export VERSION  # build-aar.sh reads it for the ldflags stamp

if [ ! -f "$repo_root/keystore.properties" ]; then
  echo "error: no keystore.properties at the repo root, so the bundle would be" >&2
  echo "       unsigned — and Play refuses an unsigned bundle at upload, not at" >&2
  echo "       install, so there would be nothing useful to do with it." >&2
  echo "       See the header of android/build-release-apk.sh to generate a key." >&2
  exit 1
fi

echo "== stage 1: build AAR (version ${VERSION}) =="
VERSION="$VERSION" "$repo_root/android/build-aar.sh"

echo "== stage 2: gradle bundleRelease (versionCode ${VERSION_CODE}, versionName ${VERSION}) =="
# gradle needs a JDK. Fall back to Android Studio's bundled JBR like build-aar.sh.
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "${JAVA_HOME}/bin/javac" ]; then
  for jbr in "$HOME/android-studio/jbr" /opt/android-studio/jbr /usr/local/android-studio/jbr; do
    if [ -x "$jbr/bin/javac" ]; then export JAVA_HOME="$jbr"; break; fi
  done
fi

cd "$repo_root/android"
aab="$repo_root/android/app/build/outputs/bundle/release/app-release.aab"
# Delete the previous bundle before building. signReleaseBundle has been seen to
# go UP-TO-DATE against an output that was already there, which leaves the old
# file in place and reports success — so the only way to be sure the file below
# came out of THIS run is for there to have been no file before it.
rm -f "$aab"

./gradlew :app:bundleRelease --console=plain \
  -PonionVersionCode="$VERSION_CODE" \
  -PonionVersionName="$VERSION"

if [ ! -f "$aab" ]; then
  echo "error: no bundle produced at $aab" >&2
  exit 1
fi

# The failure mode of this script is a bundle that builds perfectly and is
# quietly UNSIGNED. It has happened here for three unrelated reasons — a
# configuration-cache entry that predated keystore.properties, the stale
# UP-TO-DATE output above, and a signingConfig whose path never resolved — and
# in every case gradle printed BUILD SUCCESSFUL. Play only rejects it at the end
# of an upload, so the signature is checked here instead of trusted.
#
# Checked by OUTPUT TEXT, not exit status: `jarsigner -verify` exits 0 for an
# unsigned archive too (it just prints "jar is unsigned."), so an `if ! jarsigner`
# guard would silently pass exactly the case it was written to catch.
if [ -x "${JAVA_HOME:-/nonexistent}/bin/jarsigner" ]; then
  if "$JAVA_HOME/bin/jarsigner" -verify "$aab" 2>&1 | grep -q "jar verified"; then
    echo "signature verified (jarsigner)"
  else
    echo "error: the bundle built but is NOT validly signed, so Play would reject" >&2
    echo "       it at upload. Check that the release signingConfig resolved:" >&2
    echo "         ./gradlew :app:signingReport   # wants Config: release, not none" >&2
    echo "       and if it looks right, clear the configuration cache and retry:" >&2
    echo "         rm -rf android/.gradle/configuration-cache" >&2
    exit 1
  fi
else
  echo "warning: no jarsigner in JAVA_HOME, so the signature was NOT verified." >&2
  echo "         Check it before uploading: jarsigner -verify '$aab'" >&2
fi

# Confirm the bundle really carries the version asked for, so a build that came
# out of some stale state cannot be uploaded as a new one. Only versionName is
# checked: the bundle's manifest is protobuf, where versionName survives as a
# plain string but versionCode is a varint with no readable form (aapt2 cannot
# open an .aab at all — "could not identify format of APK"). In practice that is
# enough, because the two always move together here: both come from the same
# pair of -P properties on one gradle invocation. If you ever ship a versionCode
# bump with an unchanged versionName, this check goes blind and you should read
# the upload summary in the Play Console instead.
if ! unzip -p "$aab" base/manifest/AndroidManifest.xml | grep -aq "$VERSION"; then
  echo "error: the bundle does not report versionName $VERSION, so it is not the" >&2
  echo "       build you just asked for. Clear the build state and retry:" >&2
  echo "         rm -rf android/app/build/outputs android/.gradle/configuration-cache" >&2
  exit 1
fi
echo "version verified (bundle reports $VERSION)"

echo
echo "wrote $aab"
echo "  versionCode=$VERSION_CODE versionName=$VERSION  ($(du -h "$aab" | cut -f1))"
echo
# R8 renames classes, so a crash report from Play is unreadable without this.
# AGP puts a copy inside the bundle's BUNDLE-METADATA for Play to pick up
# automatically; the standalone copy is the one to keep with the release.
mapping="$repo_root/android/app/build/outputs/mapping/release/mapping.txt"
if [ -f "$mapping" ]; then
  echo "keep the R8 mapping with this release (Play reads its own copy from the"
  echo "bundle, but keep yours too, matched to this versionCode):"
  echo "  $mapping"
fi

# ---------------------------------------------------------------------------
# Smoke-testing the release build before upload
#
# The release build is signed with a different key than the debug build, so it
# cannot be installed over one — and uninstalling the debug build would destroy
# the account on that device. Use a throwaway AVD instead. This SDK has no
# cmdline-tools, so there is no `avdmanager`; an AVD is just a directory and a
# .ini, and copying an existing one works:
#
#   A=~/.android/avd
#   mkdir -p $A/mp_release_check.avd
#   cp $A/Medium_Phone.avd/config.ini $A/mp_release_check.avd/config.ini
#   sed -i 's/^AvdId=.*/AvdId=mp_release_check/' $A/mp_release_check.avd/config.ini
#   printf 'avd.ini.encoding=UTF-8\npath=%s/mp_release_check.avd\ntarget=android-36\n' \
#     "$A" > $A/mp_release_check.ini
#   $ANDROID_HOME/emulator/emulator -avd mp_release_check -port 5558 \
#     -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect &
#
# Pick a port no running emulator is using (5554/5556 are the usual two), then
# install the APK from build-release-apk.sh and look for three things in
# `adb -s emulator-5558 logcat`:
#
#   nativeloader: Load .../libgojni.so ... ok      R8 left the JNI bridge intact
#   MolepipeService: bound to default network      the backend came up
#   no FATAL / UnsatisfiedLinkError / NoClassDefFoundError
#
# then screencap: the onboarding screen rendering at all means the Go backend is
# serving the embedded UI over loopback through a minified, resource-shrunk
# build. Delete the AVD directory afterwards. What this cannot test is a real
# onion publish — that needs a real network and a peer.
# ---------------------------------------------------------------------------
