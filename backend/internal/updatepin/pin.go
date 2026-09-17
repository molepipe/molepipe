// Package updatepin holds the compiled-in release-channel pins for the
// notify-only update check (see docs/UPDATE_CHANNEL.md). All values are injected
// at build time via -ldflags and are EMPTY by default, which DISABLES the update
// check entirely:
//
//   - dev / test builds carry no pins, so the check reports "disabled";
//   - the direct and F-Droid flavors stamp the release onion, the manifest
//     verification key, and their channel name;
//   - the Play flavor MUST NOT stamp them — Play policy forbids an in-app updater
//     — so it too reports "disabled" and the whole path stays inert.
//
// The pinned key is the MANIFEST key: a standalone Ed25519 key that authenticates
// update-notice content. It is NOT the APK signing key and NOT any account
// identity key. See UPDATE_CHANNEL.md.
package updatepin

import (
	"crypto/ed25519"
	"encoding/hex"
)

// Injected via, e.g.:
//
//	go build -ldflags "\
//	  -X github.com/molepipe/molepipe/backend/internal/updatepin.ReleaseOnion=<56-char-onion> \
//	  -X github.com/molepipe/molepipe/backend/internal/updatepin.ManifestPubKeyHex=<64-hex> \
//	  -X github.com/molepipe/molepipe/backend/internal/updatepin.Channel=direct"
var (
	// ReleaseOnion is the 56-char v3 onion address of the release service,
	// WITHOUT the ".onion" suffix.
	ReleaseOnion = ""
	// ManifestPubKeyHex is the hex-encoded 32-byte Ed25519 manifest public key.
	ManifestPubKeyHex = ""
	// Channel is the update channel this build follows: "direct" | "fdroid". It
	// both selects the manifest path and is checked against the manifest's own
	// channel field.
	Channel = ""
)

// Enabled reports whether a usable pin set is compiled in. When false the update
// check is disabled (dev/test builds and the Play flavor).
func Enabled() bool {
	return ReleaseOnion != "" && Channel != "" && len(PubKey()) == ed25519.PublicKeySize
}

// PubKey returns the pinned manifest verification key, or nil if unset/malformed.
func PubKey() ed25519.PublicKey {
	b, err := hex.DecodeString(ManifestPubKeyHex)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(b)
}
