package chatstore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// AvatarStore holds profile-picture bytes encrypted at rest, each in its own file
// under <dir>/avatars/<sha256hex>.enc. It is CONTENT-ADDRESSED by the sha256 of
// the image bytes — the same hash that rides in the signed profile card — so a
// contact who reads the hash from the card can fetch the exact bytes from the
// ungated AvatarPath and verify them against it (a relay can't swap a face).
// Unlike AttachmentStore (32-hex random ids for message images), the key here IS
// the content hash, which lets any device dedupe and verify without coordination.
// Encrypted with the same identity store key as chatstore.Store, so an avatar is
// exactly as readable as the messages that reference it — only while unlocked.
type AvatarStore struct {
	dir string // <dataDir>/avatars
	key []byte // 32-byte AES key (identity.StoreKey), same as chatstore.Store
}

// avatarDirName is a sibling of messages.enc; wipeAccountFiles clears it by this
// name, so keep it in step there.
const avatarDirName = "avatars"

// maxAvatarStoreBytes bounds total on-disk avatar storage. Each avatar is capped
// at 64 KiB on the wire, so this holds my own avatar plus a few thousand cached
// contact avatars. A Put past the cap is refused; to stop an old, now-unreferenced
// avatar hash from walling off new ones, sweepOrphanAvatarsLocked (in the api
// package) reclaims any on-disk avatar no live profile/contact references, run on
// the same authoritative paths as the attachment sweep.
const maxAvatarStoreBytes = 32 << 20 // 32 MiB

// maxAvatarBytes is the store-side per-avatar byte guard (mirrors the wire cap
// protocol.MaxAvatarBytes; the two packages are siblings and each owns its own
// limit, as attachments do). Avatars are single-digit KB after the client's
// square crop+downscale; 64 KiB is generous headroom.
const maxAvatarBytes = 64 << 10 // 64 KiB

// NewAvatarStore returns a store rooted at <dir>/avatars, encrypting under key.
// The directory is created lazily on first Put.
func NewAvatarStore(dir string, key []byte) *AvatarStore {
	return &AvatarStore{dir: filepath.Join(dir, avatarDirName), key: key}
}

// AvatarHashBytes returns the lowercase-hex sha256 of data — the content address
// used as an avatar's id and advertised in the signed profile card.
func AvatarHashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// validAvatarHash guards against path traversal: a hash is used directly as a
// filename, so it must be exactly the sha256 hex shape (64 lowercase hex).
func validAvatarHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (a *AvatarStore) path(hash string) string { return filepath.Join(a.dir, hash+".enc") }

// Put seals data under a FRESH random nonce (crypto.Seal generates it) bound to
// the hash via AAD, and writes it atomically. It VERIFIES that sha256(data) ==
// hash before storing, so a store is always self-consistent: whatever Get later
// returns for a hash actually hashes to that hash (a corrupt or spoofed push
// can't poison the content-addressed cache). Refuses a write past the store cap.
func (a *AvatarStore) Put(hash string, data []byte) error {
	if !validAvatarHash(hash) {
		return fmt.Errorf("invalid avatar hash")
	}
	if len(data) == 0 || len(data) > maxAvatarBytes {
		return fmt.Errorf("avatar size out of range")
	}
	if AvatarHashBytes(data) != hash {
		return fmt.Errorf("avatar bytes do not match hash")
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return fmt.Errorf("create avatar dir: %w", err)
	}
	if a.Has(hash) {
		return nil // content-addressed: identical bytes, nothing to do
	}
	total, err := a.totalBytes()
	if err != nil {
		return err
	}
	if total+int64(len(data)) > maxAvatarStoreBytes {
		return fmt.Errorf("avatar storage full")
	}
	nonce, ct, err := crypto.Seal(a.key, data, avatarAAD(hash))
	if err != nil {
		return err
	}
	// File layout: [4-byte BE nonce length][nonce][ciphertext].
	buf := make([]byte, 0, 4+len(nonce)+len(ct))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(nonce)))
	buf = append(buf, l[:]...)
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return atomicWrite(a.path(hash), buf, 0o600)
}

// Get decrypts and returns an avatar's bytes. A missing file returns an error the
// caller treats as "not on this device yet".
func (a *AvatarStore) Get(hash string) ([]byte, error) {
	if !validAvatarHash(hash) {
		return nil, fmt.Errorf("invalid avatar hash")
	}
	raw, err := os.ReadFile(a.path(hash))
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("corrupt avatar")
	}
	nl := binary.BigEndian.Uint32(raw[:4])
	if int(nl) > len(raw)-4 {
		return nil, fmt.Errorf("corrupt avatar")
	}
	nonce := raw[4 : 4+nl]
	ct := raw[4+nl:]
	return crypto.Open(a.key, nonce, ct, avatarAAD(hash))
}

// List returns the hashes of every avatar currently on disk. Used by the orphan
// sweep to reclaim avatars no longer referenced by our own profile or any contact
// (a content-addressed store never evicts on its own, so a contact who rotates
// their picture would otherwise leave the old bytes behind forever, eventually
// walling off the cap). Skips any file whose name isn't a valid hash.
func (a *AvatarStore) List() ([]string, error) {
	entries, err := os.ReadDir(a.dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".enc" {
			continue
		}
		hash := name[:len(name)-len(".enc")]
		if validAvatarHash(hash) {
			hashes = append(hashes, hash)
		}
	}
	return hashes, nil
}

// Delete removes an avatar's bytes from disk. A missing file is not an error (the
// sweep may race a concurrent reclaim). Invalid hashes are ignored, so the
// content-addressed filename can never be steered outside the store dir.
func (a *AvatarStore) Delete(hash string) {
	if !validAvatarHash(hash) {
		return
	}
	// Non-fatal on error: a leftover file just occupies cap until the next sweep
	// retries. A missing file is the expected no-op when a sweep races a reclaim.
	_ = os.Remove(a.path(hash))
}

// Has reports whether an avatar's bytes are present on this device.
func (a *AvatarStore) Has(hash string) bool {
	if !validAvatarHash(hash) {
		return false
	}
	_, err := os.Stat(a.path(hash))
	return err == nil
}

// totalBytes sums the on-disk size of every stored avatar.
func (a *AvatarStore) totalBytes() (int64, error) {
	entries, err := os.ReadDir(a.dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total, nil
}

func avatarAAD(hash string) []byte { return []byte("onion-chat/v1 avatar " + hash) }
