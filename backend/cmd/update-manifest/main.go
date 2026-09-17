// Command update-manifest signs a release manifest for the notify-only update
// channel (docs/UPDATE_CHANNEL.md). It runs OFFLINE on the release machine with
// the manifest signing key — a standalone Ed25519 key, NOT the APK signing key
// and NOT any account identity key. The signed JSON it emits is published at the
// release onion as <channel>.json; every client verifies it against the pinned
// public half compiled into the app (updatepin.ManifestPubKeyHex).
//
// Generate a key once:
//
//	update-manifest -genkey manifest-key.hex
//	# prints the PUBLIC key hex — stamp it as updatepin.ManifestPubKeyHex.
//
// Sign a release:
//
//	update-manifest -key manifest-key.hex \
//	  -channel direct -version-code 43 -version-name 1.3.0 \
//	  -notes "Fixes reconnect loop." -min-code 40 \
//	  -apk-url http://<release-onion>.onion/onion-chat-1.3.0.apk \
//	  -apk-file ./onion-chat-1.3.0.apk \
//	  -out direct.json
//
// The signing key never leaves this machine; the tool reads it, signs, and
// exits. It does not fabricate or store any secret of its own.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/molepipe/molepipe/backend/internal/updatecheck"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "update-manifest:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		genKey      = flag.String("genkey", "", "generate a new Ed25519 manifest key, write the private half (hex) to this path (0600), print the public half to stdout, and exit")
		keyPath     = flag.String("key", "", "path to the manifest signing key (hex: a 32-byte seed or a 64-byte private key)")
		channel     = flag.String("channel", "direct", `update channel: "direct" | "fdroid"`)
		versionCode = flag.Int("version-code", 0, "latest build's integer version code (must exceed the running build to notify)")
		versionName = flag.String("version-name", "", "latest build's human version, e.g. 1.3.0")
		notes       = flag.String("notes", "", "release notes shown to the user")
		apkURL      = flag.String("apk-url", "", "URL of the APK on the release onion (http://<onion>.onion/...)")
		apkFile     = flag.String("apk-file", "", "path to the APK; its SHA-256 is computed and embedded")
		apkSHA      = flag.String("apk-sha256", "", "APK SHA-256 (hex); alternative to -apk-file")
		minCode     = flag.Int("min-code", 0, "minimum supported version code; builds below this are told the update is mandatory")
		published   = flag.String("published", "", "RFC3339 publish time (default: now, UTC)")
		out         = flag.String("out", "", "write the signed manifest here (default: stdout)")
	)
	flag.Parse()

	if *genKey != "" {
		return generateKey(*genKey)
	}

	priv, err := loadKey(*keyPath)
	if err != nil {
		return err
	}

	sha, err := resolveSHA(*apkFile, *apkSHA)
	if err != nil {
		return err
	}

	pubAt := *published
	if pubAt == "" {
		pubAt = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, pubAt); err != nil {
		return fmt.Errorf("-published is not RFC3339: %w", err)
	}

	if *versionCode <= 0 {
		return fmt.Errorf("-version-code must be a positive integer")
	}
	if *versionName == "" || *apkURL == "" {
		return fmt.Errorf("-version-name and -apk-url are required")
	}

	m := updatecheck.Manifest{
		Ver:     1,
		Channel: *channel,
		Latest: updatecheck.Release{
			VersionCode: *versionCode,
			VersionName: *versionName,
			Notes:       *notes,
			APKURL:      *apkURL,
			APKSHA256:   sha,
			PublishedAt: pubAt,
		},
		MinSupportedCode: *minCode,
	}
	m.Sig = updatecheck.Sign(m, priv)

	// Self-check: verify what we just signed with the derived public key, so a
	// malformed field or key can never ship as a manifest no client will accept.
	if err := updatecheck.Verify(m, priv.Public().(ed25519.PublicKey)); err != nil {
		return fmt.Errorf("self-verify after signing failed: %w", err)
	}

	enc, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	enc = append(enc, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(enc)
		return err
	}
	return os.WriteFile(*out, enc, 0o644)
}

// generateKey creates a fresh Ed25519 key, writes the 64-byte private half as hex
// to path (0600), and prints the 32-byte public half as hex to stdout.
func generateKey(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote private key to %s (keep it offline and secret)\n", path)
	fmt.Fprintf(os.Stderr, "public key (stamp as updatepin.ManifestPubKeyHex):\n")
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

// loadKey reads a hex-encoded Ed25519 key file: a 32-byte seed (expanded to a
// full key) or a 64-byte private key.
func loadKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("-key is required (or use -genkey to create one)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("key file is not valid hex: %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("key must be %d (seed) or %d (private) bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
	}
}

// resolveSHA returns the APK SHA-256 hex, computing it from apkFile when given,
// otherwise validating the supplied hex.
func resolveSHA(apkFile, apkSHA string) (string, error) {
	if apkFile != "" {
		data, err := os.ReadFile(apkFile)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	}
	if apkSHA == "" {
		return "", fmt.Errorf("provide -apk-file or -apk-sha256")
	}
	b, err := hex.DecodeString(strings.TrimSpace(apkSHA))
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("-apk-sha256 must be 64 hex chars")
	}
	return hex.EncodeToString(b), nil
}
