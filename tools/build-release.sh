#!/usr/bin/env bash
# Build the hand-to-a-friend release: a versioned tarball containing the app,
# the Arti binary it needs, a launcher and a desktop entry.
#
# Arti is shipped alongside rather than embedded in the Go binary. Embedding
# would mean owning an extract-to-temp path, its cleanup, and the question of
# what two concurrent launches do to it — for no user-visible gain over a
# directory with two files in it. Shipping it as a visibly separate binary also
# keeps its licensing and provenance obvious.
set -euo pipefail

VERSION="${VERSION:-$(git -C "$(dirname "$0")/.." describe --tags --always --dirty 2>/dev/null || echo dev)}"
GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"
ARTI_BIN="${ARTI_BIN:-$(command -v arti || true)}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="tormsg-${VERSION}-${GOOS}-${GOARCH}"
OUT="${ROOT}/dist"
STAGE="${OUT}/${NAME}"

# Shared version stamp. VersionCode is the DESKTOP source of truth for the update
# check (internal/version.Code) — a monotonic integer from the commit count, so a
# newer build always compares higher. Override with VERSION_CODE=… for a tag-based
# scheme.
GITCOMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"
VERSION_CODE="${VERSION_CODE:-$(git -C "${ROOT}" rev-list --count HEAD 2>/dev/null || echo 0)}"
VPKG="github.com/molepipe/molepipe/backend/internal/version"
PINPKG="github.com/molepipe/molepipe/backend/internal/updatepin"
VER_LDFLAGS="-X ${VPKG}.Version=${VERSION} -X ${VPKG}.GitCommit=${GITCOMMIT} -X ${VPKG}.VersionCode=${VERSION_CODE}"

# Optional notify-only update pins. EMPTY by default → the update check reports
# "disabled" and never dials. Set ALL THREE to arm it for a release:
#   RELEASE_ONION   56-char v3 onion of the release service (no ".onion" suffix)
#   MANIFEST_PUBKEY hex-encoded 32-byte Ed25519 manifest public key (from
#                   `update-manifest -genkey`)
#   UPDATE_CHANNEL  "direct" | "fdroid"
if [ -n "${RELEASE_ONION:-}" ] && [ -n "${MANIFEST_PUBKEY:-}" ] && [ -n "${UPDATE_CHANNEL:-}" ]; then
  echo "  update check ENABLED (channel ${UPDATE_CHANNEL})"
  VER_LDFLAGS="${VER_LDFLAGS} -X ${PINPKG}.ReleaseOnion=${RELEASE_ONION} -X ${PINPKG}.ManifestPubKeyHex=${MANIFEST_PUBKEY} -X ${PINPKG}.Channel=${UPDATE_CHANNEL}"
fi

if [ -z "${ARTI_BIN}" ] || [ ! -x "${ARTI_BIN}" ]; then
  echo "error: no arti binary found. Install arti, or set ARTI_BIN=/path/to/arti." >&2
  echo "       The release has to ship it: the recipient will not have it." >&2
  exit 1
fi

rm -rf "${STAGE}"
mkdir -p "${STAGE}"

echo "building ${NAME}"
( cd "${ROOT}/backend" && CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -trimpath -ldflags="-s -w ${VER_LDFLAGS}" -o "${STAGE}/tormsg" ./cmd/server )
( cd "${ROOT}/backend" && CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -trimpath -ldflags="-s -w ${VER_LDFLAGS}" -o "${STAGE}/tormsg-cli" ./cmd/tormsg )

# The desktop build (window + tray) is a different kind of binary from the two
# above, and the differences are not cosmetic:
#
#   * It needs cgo, so it cannot be built CGO_ENABLED=0 and cannot be
#     cross-compiled here — it is built only for the machine running this.
#   * It links against libwebkit2gtk-4.1 and libgtk-3 at runtime, so unlike
#     tormsg it is NOT self-contained. A recipient without those packages gets
#     a binary that will not start.
#
# That is why tormsg stays in the tarball rather than being replaced: it is the
# fallback that runs anywhere, and the launcher below picks between them. The
# desktop binary is skipped (with a warning, not an error) when its build
# dependencies are missing, so this script still produces a release on a
# machine without the GTK development headers.
DESKTOP="${DESKTOP:-1}"
WEBKIT_TAG=""
if [ "${DESKTOP}" = "1" ] && [ "${GOOS}" = "linux" ] \
   && [ "${GOOS}" = "$(go env GOHOSTOS)" ] && [ "${GOARCH}" = "$(go env GOHOSTARCH)" ]; then
  # The desktop build needs cgo (CGO_ENABLED=1) and a C compiler.
  if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    WEBKIT_TAG="missing"
  # Wails v2 defaults its pkg-config to webkit2gtk-4.0; anything current ships
  # 4.1 and needs the tag. Pick whichever this machine actually has.
  elif pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
    WEBKIT_TAG="webkit2_41"
  elif ! pkg-config --exists webkit2gtk-4.0 2>/dev/null; then
    WEBKIT_TAG="missing"
  fi
fi
if [ "${DESKTOP}" != "1" ]; then
  echo "  skipping the desktop build (DESKTOP=0)"
elif [ "${GOOS}" != "linux" ] || [ "${GOOS}" != "$(go env GOHOSTOS)" ] || [ "${GOARCH}" != "$(go env GOHOSTARCH)" ]; then
  echo "  skipping the desktop build: it needs cgo and cannot be cross-compiled" >&2
elif [ "${WEBKIT_TAG}" = "missing" ]; then
  echo "  skipping the desktop build: no webkit2gtk-4.1 or -4.0 development package" >&2
  echo "  (install webkit2gtk-4.1 and gtk3 dev packages to include the window/tray build)" >&2
else
  echo "  building the desktop window/tray binary (tags: desktop production ${WEBKIT_TAG})"
  ( cd "${ROOT}/backend" && CGO_ENABLED=1 \
      go build -trimpath -ldflags="-s -w ${VER_LDFLAGS}" -tags "desktop production ${WEBKIT_TAG}" \
        -o "${STAGE}/tormsg-desktop" ./cmd/desktop )
  chmod +x "${STAGE}/tormsg-desktop"
fi

# The app looks for "arti" next to itself before falling back to PATH, so this
# copy is what makes the tarball self-contained.
cp "${ARTI_BIN}" "${STAGE}/arti"
chmod +x "${STAGE}/arti" "${STAGE}/tormsg" "${STAGE}/tormsg-cli"

# Record the Arti binary hash for integrity verification. Users can verify
# the binary matches what was shipped by comparing this hash.
ARTI_HASH=$(sha256sum "${STAGE}/arti" | cut -d' ' -f1)
echo "arti sha256: ${ARTI_HASH}" > "${STAGE}/arti-sha256.txt"

cat > "${STAGE}/start-molepipe.sh" <<'LAUNCHER'
#!/usr/bin/env bash
# Launcher: runs the app from wherever this folder was unpacked.
#
# It prefers the desktop build (its own window, a tray icon, and it keeps
# running when you close the window) and falls back to the browser build, which
# is self-contained and runs anywhere. The fallback is not hypothetical: the
# desktop build needs libwebkit2gtk-4.1 and libgtk-3 on the machine, and a
# recipient without them would otherwise just see nothing happen.
cd "$(dirname "$(readlink -f "$0")")"
if [ -x ./tormsg-desktop ] && ldd ./tormsg-desktop >/dev/null 2>&1; then
  exec ./tormsg-desktop "$@"
fi
if [ -x ./tormsg-desktop ]; then
  echo "The desktop build needs libwebkit2gtk-4.1 and libgtk-3, which are not installed here." >&2
  echo "Opening in your browser instead. Missing libraries:" >&2
  ldd ./tormsg-desktop 2>&1 | grep "not found" >&2 || true
  echo >&2
fi
exec ./tormsg "$@"
LAUNCHER
chmod +x "${STAGE}/start-molepipe.sh"

cat > "${STAGE}/molepipe.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Molepipe
Comment=Private messaging over Tor
Exec=sh -c '"$(dirname "%k")/start-molepipe.sh"'
Terminal=false
Categories=Network;InstantMessaging;
DESKTOP

cat > "${STAGE}/README.txt" <<READMETXT
Molepipe ${VERSION}

To run
------
  ./start-molepipe.sh

Everything runs on your own machine — there is no server to sign up to, and
nothing about your account leaves this folder except the messages you send.

Two builds are included and the launcher picks for you:

  tormsg-desktop   its own window and a system tray icon. Closing the window
                   does NOT quit — the app keeps running so messages can still
                   reach you, and the tray icon reopens it. Use Quit in the tray
                   menu to stop it completely. It needs libwebkit2gtk-4.1 and
                   libgtk-3 installed (most desktop Linux systems have both).
  tormsg           opens in your browser instead. No extra libraries needed.
                   The launcher falls back to this automatically.

Both are the same application with the same data; you can switch between them,
but not run both at once on the same folder.

First run
---------
Creating an account gives you a 24-word recovery phrase. Write it down. It is
the ONLY way back into your account: nobody, including whoever gave you this,
can reset your password or recover it for you.

After you unlock, it takes roughly 30 seconds before other people can reach
you — that is Tor publishing your address. The "You" tab shows when it is
ready.

What is in this folder
----------------------
  tormsg-desktop  the application, in its own window with a tray icon
  tormsg          the application, in your browser (works everywhere)
  tormsg-cli      optional command-line tool (create/unlock/recover)
  arti            the Tor client the app runs; it is not a system install and
                  does not touch the rest of your machine

Start at login
--------------
The desktop build can start itself when you log in — it is off until you turn
it on, under "You". Turning it on writes one file to
~/.config/autostart/molepipe.desktop, and nothing else on your system is
touched. Removing your account from the app deletes that file too. If you move
this folder somewhere else, turn the setting off and on again so it points at
the new location.

Where your data lives
---------------------
  \$TORMSG_DATA_DIR, or ~/.config/molepipe by default.
  Your identity, messages and contacts are encrypted there with your password.
  tormsg.log in that folder records what the app did — send it along if you
  report a problem.

Running a second account on this machine
----------------------------------------
  ./tormsg -data-dir ~/some-other-folder
  Each account needs its own folder; the app refuses to share one.
READMETXT

mkdir -p "${OUT}"
tar -C "${OUT}" -czf "${OUT}/${NAME}.tar.gz" "${NAME}"
rm -rf "${STAGE}"

echo
echo "built ${OUT}/${NAME}.tar.gz"
ls -lh "${OUT}/${NAME}.tar.gz" | awk '{print "  size:", $5}'
