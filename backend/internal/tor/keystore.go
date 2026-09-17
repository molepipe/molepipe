package tor

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// opensshLineWidth is the base64 line width OpenSSH uses for private keys. Arti's
// key reader is strict about it, so we must match it exactly (Go's encoding/pem
// wraps at 64, which Arti rejects).
const opensshLineWidth = 70

// expandedKeyType is Tor's OpenSSH key-type name for an expanded Ed25519 onion
// identity key.
const expandedKeyType = "ed25519-expanded@spec.torproject.org"

// KeystoreFileName is the file name Arti expects for the HS identity key inside
// <state>/keystore/hss/<nickname>/.
const KeystoreFileName = "ks_hs_id.ed25519_expanded_private"

// MarshalKeystoreKey encodes the onion key as an OpenSSH-format
// ed25519-expanded private key, byte-compatible with Arti's HS keystore. Arti
// reads the public key from this file to determine the .onion address, so
// writing our key here makes Arti publish under our account number.
func (k OnionKey) MarshalKeystoreKey() ([]byte, error) {
	// Public key section.
	var pub bytes.Buffer
	pub.Write(sshString([]byte(expandedKeyType)))
	pub.Write(sshString(k.Public[:]))

	// Private key section, prefixed with a repeated random check value.
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, fmt.Errorf("read check bytes: %w", err)
	}
	var priv bytes.Buffer
	priv.Write(check[:])
	priv.Write(check[:])
	priv.Write(sshString([]byte(expandedKeyType)))
	priv.Write(sshString(k.Public[:]))
	priv.Write(sshString(k.ExpandedSecret[:]))
	priv.Write(sshString(nil)) // empty comment
	// Pad to a multiple of the cipher block size (8 for "none") with 1,2,3,…
	for i := 1; priv.Len()%8 != 0; i++ {
		priv.WriteByte(byte(i))
	}

	var blob bytes.Buffer
	blob.WriteString("openssh-key-v1")
	blob.WriteByte(0)
	blob.Write(sshString([]byte("none")))                // cipher
	blob.Write(sshString([]byte("none")))                // kdf
	blob.Write(sshString(nil))                           // kdf options
	_ = binary.Write(&blob, binary.BigEndian, uint32(1)) // number of keys
	blob.Write(sshString(pub.Bytes()))
	blob.Write(sshString(priv.Bytes()))

	der := blob.Bytes()
	result := encodeOpenSSHPEM(der)
	// Zero intermediate buffers containing the expanded secret before returning.
	crypto.Zero(priv.Bytes())
	crypto.Zero(blob.Bytes())
	crypto.Zero(der)
	return result, nil
}

// encodeOpenSSHPEM wraps the DER blob as an OpenSSH PRIVATE KEY PEM with the
// 70-column line width OpenSSH (and Arti) expect.
func encodeOpenSSHPEM(der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var out bytes.Buffer
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for i := 0; i < len(b64); i += opensshLineWidth {
		end := i + opensshLineWidth
		if end > len(b64) {
			end = len(b64)
		}
		out.WriteString(b64[i:end])
		out.WriteByte('\n')
	}
	out.WriteString("-----END OPENSSH PRIVATE KEY-----\n")
	return out.Bytes()
}

// sshString length-prefixes b with a big-endian uint32, the SSH wire encoding.
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}
