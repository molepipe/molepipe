# Play Console upload notes

Working notes for getting Molepipe onto Google Play. Everything here is either
copied out of the build or quoted verbatim from the manifest — where the Console
asks a question that must agree with what Play reads out of the bundle, paste
the text from here rather than rewriting it, because a mismatch between the two
is a review-rejection cause.

**No secrets in this file.** It is tracked in git. The upload keystore password
lives only in the untracked `keystore.properties`; see "Signing" below.

## The artifact

| | |
|---|---|
| Upload | `android/app/build/outputs/bundle/release/app-release.aab` |
| Build it with | `VERSION=1.0.0 VERSION_CODE=1 ./android/build-release-bundle.sh` |
| applicationId | `org.molepipe.app` |
| versionName / versionCode | `1.0.0` / `1` |
| minSdk / targetSdk | 24 / 37 |
| ABIs | `arm64-v8a`, `x86_64` only — see "Device support" |

`versionCode` must strictly increase on every upload and can never be reused,
even for a build that was rejected. The script refuses to guess it from a dirty
tree for that reason.

Keep `android/app/build/outputs/mapping/release/mapping.txt` with each release,
matched to its versionCode: R8 renames classes, so a crash report from Play is
unreadable without it. Play also reads its own copy out of the bundle
automatically, so this is a backup rather than a required upload step.

## Signing

The bundle is signed with an upload key held **outside the repo**:

- keystore `~/molepipe-upload.jks` (PKCS12, RSA 4096, alias `molepipe-upload`)
- credentials `keystore.properties` at the repo root — untracked, git-ignored
- certificate `CN=Molepipe, O=Molepipe, C=NZ`, valid to 2054

Upload certificate fingerprints, for the Console's app-signing page:

```
SHA-256  14:4B:AB:8C:6D:E5:EF:05:C2:7E:3C:3C:D9:33:14:B1:2D:0B:F5:B5:2B:F3:5D:36:FF:4A:30:79:13:4F:E1:22
SHA-1    3A:3C:A9:69:7C:6B:8C:B6:A8:5C:08:65:19:89:30:8E:7B:F2:83:89
```

**Enrol in Play App Signing.** It makes the key above merely the *upload* key,
which Google can reset if it is ever lost, instead of the key that owns the
app's identity forever. Neither the keystore nor its password is backed up
anywhere right now, so without enrolment, losing the laptop means losing the
ability to ever update the app.

The release APK is signed with the v2 scheme only (v1 and v3 absent). That is
correct at `minSdk 24` — v1 is only needed below API 24 — and not something to
fix.

## Device support

The bundle declares `arm64-v8a` and `x86_64` and nothing else. This is
deliberate and should not be "fixed" by widening it: the Go backend and Arti are
cross-compiled for exactly those two, so `libgojni.so` does not exist for
32-bit ABIs. Play reads a bundle's lib directories as the list of devices the
app supports, so the filter is what stops Play offering the app to a
32-bit-only phone and handing it a split with no backend in it — which would
die in `System.loadLibrary` on first launch. Excluding those devices from the
listing is the honest answer; there is no 32-bit build to give them.

Estimated per-device download: **~25 MB on arm64** (24.3 MB of ABI-specific
native code plus ~1.0 MB shared). The all-ABI APK is 132 MB; almost all of the
weight either way is `libgojni.so`. The figure is computed from compressed sizes
inside the bundle, not measured with `bundletool`.

## Declarations the Console will ask for

### Foreground service: `FOREGROUND_SERVICE_SPECIAL_USE`

Play requires a justification for `specialUse`, and it must match the
`PROPERTY_SPECIAL_USE_FGS_SUBTYPE` value in the manifest. Paste this exactly:

> Runs an embedded Tor peer so the user can send and receive end-to-end encrypted messages while the app window is closed.

Supporting detail if the reviewer asks why a standard type does not fit: an
always-on peer-to-peer Tor node has no time-capped equivalent among the standard
FGS types, and `dataSync` is throttled on API 35+ — the OS would stop the
service, which is the exact failure the app exists to avoid.

### `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`

Play treats this as a sensitive permission needing a declaration. The honest
description: the app asks the user (it does not force the exemption) so an
aggressive OEM power manager does not defer the always-on Tor node's network in
deep idle. The app is functional without it; the prompt is dismissible and the
answer is remembered.

### Other permissions, and why each is here

| Permission | Why |
|---|---|
| `INTERNET` | Reach the Tor network. |
| `FOREGROUND_SERVICE` | Keep receiving messages with the window closed. |
| `ACCESS_NETWORK_STATE` | `bindProcessToNetwork`, so Tor survives Doze. |
| `POST_NOTIFICATIONS` | Show an incoming message on Android 13+. |
| `WAKE_LOCK` | The FGS exempts network but not CPU suspension; Arti's onion-service maintenance needs the CPU while the screen is off. |
| `CAMERA` | Scan a contact's QR code. Optional — `uses-feature required="false"`, and the app works fully by pasting an account instead. |

### Data safety

The app collects nothing and has no server to send it to: there is no account
system, no analytics, no crash reporting SDK, and no phone number or email. All
message content is end-to-end encrypted and stored only on the device.
`allowBackup="false"` and `fullBackupContent="false"`, so nothing is copied off
the device by Android's own backup either. Answer the Data Safety form as "no
data collected, no data shared", and expect to be asked to justify it — the
Tor-related permissions above are what usually prompts the question.

## Before the first upload

- [ ] Enrol in Play App Signing (see "Signing").
- [ ] Back up `~/molepipe-upload.jks` and `keystore.properties` somewhere other
      than this laptop.
- [ ] Confirm Play accepts `targetSdk 37`. AGP resolves it as `release(37)` and
      would have required a `preview =` spelling for a preview API, so it is a
      stable SDK — but whether Play's current target-API window accepts it can
      only be checked in the Console.
- [ ] Push to the **internal testing track first** and open the app on a real
      phone. The release build has been run on an emulator, but no release build
      has ever published a real onion service on a real network — that is the
      one part of this app an emulator cannot exercise.
