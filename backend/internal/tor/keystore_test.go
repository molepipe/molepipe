package tor

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// Arti's key reader is strict about the OpenSSH 70-column base64 width; Go's
// encoding/pem wraps at 64, which Arti silently rejects. pem.Decode (used in the
// round-trip test) is width-lenient and would not catch a regression, so assert
// the raw line width directly.
func TestMarshalKeystoreKeyLineWidth(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveOnionKey(id.Keys.Signing.Private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	out, err := key.MarshalKeystoreKey()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----" || lines[len(lines)-1] != "-----END OPENSSH PRIVATE KEY-----" {
		t.Fatal("missing OpenSSH PEM header/footer")
	}
	body := lines[1 : len(lines)-1]
	for i, ln := range body {
		if i < len(body)-1 && len(ln) != 70 {
			t.Fatalf("base64 line %d width = %d, want 70 (Arti rejects other widths)", i, len(ln))
		}
		if len(ln) > 70 {
			t.Fatalf("base64 line %d exceeds 70: %d", i, len(ln))
		}
	}
}

// sshReader parses SSH length-prefixed strings from a buffer.
type sshReader struct {
	b []byte
	o int
}

func (r *sshReader) str(t *testing.T) []byte {
	t.Helper()
	if r.o+4 > len(r.b) {
		t.Fatal("truncated ssh string length")
	}
	n := int(binary.BigEndian.Uint32(r.b[r.o:]))
	r.o += 4
	if r.o+n > len(r.b) {
		t.Fatal("truncated ssh string body")
	}
	s := r.b[r.o : r.o+n]
	r.o += n
	return s
}

func (r *sshReader) u32(t *testing.T) uint32 {
	t.Helper()
	v := binary.BigEndian.Uint32(r.b[r.o:])
	r.o += 4
	return v
}

// Re-parse our encoded keystore file and confirm every field matches the key,
// so the format is byte-shaped exactly like Arti's (Arti acceptance is proven
// separately in the integration spike).
func TestMarshalKeystoreKeyRoundTrip(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveOnionKey(id.Keys.Signing.Private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := key.MarshalKeystoreKey()
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		t.Fatal("not a valid OPENSSH PRIVATE KEY PEM block")
	}
	blob := block.Bytes
	if !bytes.HasPrefix(blob, []byte("openssh-key-v1\x00")) {
		t.Fatal("missing openssh-key-v1 magic")
	}

	r := &sshReader{b: blob, o: 15}
	if got := string(r.str(t)); got != "none" {
		t.Errorf("cipher = %q, want none", got)
	}
	if got := string(r.str(t)); got != "none" {
		t.Errorf("kdf = %q, want none", got)
	}
	r.str(t) // kdfopts
	if n := r.u32(t); n != 1 {
		t.Fatalf("nkeys = %d, want 1", n)
	}

	// Public section.
	pubSec := &sshReader{b: r.str(t)}
	if got := string(pubSec.str(t)); got != expandedKeyType {
		t.Errorf("pub keytype = %q", got)
	}
	if got := pubSec.str(t); !bytes.Equal(got, key.Public[:]) {
		t.Error("public key bytes do not match")
	}

	// Private section.
	privSec := &sshReader{b: r.str(t)}
	c1, c2 := privSec.u32(t), privSec.u32(t)
	if c1 != c2 {
		t.Error("check1 != check2")
	}
	if got := string(privSec.str(t)); got != expandedKeyType {
		t.Errorf("priv keytype = %q", got)
	}
	if got := privSec.str(t); !bytes.Equal(got, key.Public[:]) {
		t.Error("priv public key bytes do not match")
	}
	if got := privSec.str(t); !bytes.Equal(got, key.ExpandedSecret[:]) {
		t.Error("expanded secret bytes do not match")
	}
	if got := privSec.str(t); len(got) != 0 {
		t.Errorf("comment = %q, want empty", got)
	}
}
