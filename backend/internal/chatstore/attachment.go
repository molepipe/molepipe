package chatstore

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// AttachmentStore holds image (and future binary) attachments encrypted at rest,
// each in its own file under <dir>/attachments/<id>.enc. It is SEPARATE from the
// message log on purpose: a 1–2 MB image inlined into messages.enc would bloat
// the whole store and every /api/messages poll, so the log keeps only metadata
// (Message.Kind/AttachID/Mime/Size) and the bytes are fetched from here on
// demand. Encrypted with the same identity store key (AES-256-GCM), so an
// attachment is exactly as readable as the messages that reference it — only
// while unlocked.
type AttachmentStore struct {
	dir string // <dataDir>/attachments
	key []byte // 32-byte AES key (identity.StoreKey), same as chatstore.Store
}

// attachDirName is a sibling of messages.enc; the wipe paths clear it by this
// name, so keep it in step with wipeAccountFiles.
const attachDirName = "attachments"

// maxAttachStoreBytes bounds total on-disk attachment storage, so inbound images
// (each already capped on the wire) can't fill the disk over time. A Put that
// would exceed it is refused rather than silently evicting, so nothing the user
// believes is stored disappears without them acting.
const maxAttachStoreBytes = 256 << 20 // 256 MiB

// maxSingleAttachBytes bounds the size of a single attachment. Prevents a
// malicious or buggy caller from storing an arbitrarily large file up to the
// total store cap.
const maxSingleAttachBytes = 10 << 20 // 10 MiB

// NewAttachmentStore returns a store rooted at <dir>/attachments, encrypting
// under key. The directory is created lazily on first Put.
func NewAttachmentStore(dir string, key []byte) *AttachmentStore {
	return &AttachmentStore{dir: filepath.Join(dir, attachDirName), key: key}
}

// validAttachID guards against path traversal: an id is used directly as a
// filename, so it must be exactly the hex randomID() shape (32 lowercase hex).
func validAttachID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (a *AttachmentStore) path(id string) string { return filepath.Join(a.dir, id+".enc") }

// Put seals data under a FRESH random nonce (crypto.Seal generates it — never
// derive a nonce from the id, or GCM's security collapses) bound to the id via
// AAD, and writes it atomically. Refuses a write that would push total storage
// past maxAttachStoreBytes.
func (a *AttachmentStore) Put(id string, data []byte) error {
	if !validAttachID(id) {
		return fmt.Errorf("invalid attachment id")
	}
	if len(data) > maxSingleAttachBytes {
		return fmt.Errorf("attachment too large: %d bytes (max %d)", len(data), maxSingleAttachBytes)
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return fmt.Errorf("create attachment dir: %w", err)
	}
	total, err := a.totalBytes()
	if err != nil {
		return err
	}
	if total+int64(len(data)) > maxAttachStoreBytes {
		return fmt.Errorf("attachment storage full")
	}
	nonce, ct, err := crypto.Seal(a.key, data, attachAAD(id))
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
	return atomicWrite(a.path(id), buf, 0o600)
}

// Get decrypts and returns an attachment's bytes. A missing file returns an
// error the caller treats as "not on this device yet" — a secondary backfills
// missing blobs from the primary via the /sync/attachment exchange (the bytes
// are portable because every device derives the same store key from the seed).
func (a *AttachmentStore) Get(id string) ([]byte, error) {
	if !validAttachID(id) {
		return nil, fmt.Errorf("invalid attachment id")
	}
	raw, err := os.ReadFile(a.path(id))
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("corrupt attachment")
	}
	nl := binary.BigEndian.Uint32(raw[:4])
	if int(nl) > len(raw)-4 {
		return nil, fmt.Errorf("corrupt attachment")
	}
	nonce := raw[4 : 4+nl]
	ct := raw[4+nl:]
	return crypto.Open(a.key, nonce, ct, attachAAD(id))
}

// Has reports whether an attachment's bytes are present on this device.
func (a *AttachmentStore) Has(id string) bool {
	if !validAttachID(id) {
		return false
	}
	_, err := os.Stat(a.path(id))
	return err == nil
}

// Delete removes one attachment. Called when its message is deleted (locally or
// via delete-for-everyone) so a blob never outlives the row that references it.
func (a *AttachmentStore) Delete(id string) {
	if validAttachID(id) {
		_ = os.Remove(a.path(id))
	}
}

// List returns the ids of every attachment currently on disk. Only files named
// exactly "<32-hex>.enc" are reported, so an in-flight atomicWrite temp file
// (".messages-*.tmp") is never mistaken for a stored id. The orphan sweep uses
// this to find blobs no live message row references any more — the store never
// evicts, so a leaked group-image blob would otherwise sit forever.
func (a *AttachmentStore) List() ([]string, error) {
	entries, err := os.ReadDir(a.dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		id, ok := strings.CutSuffix(e.Name(), ".enc")
		if !ok || !validAttachID(id) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// totalBytes sums the on-disk size of every stored attachment.
func (a *AttachmentStore) totalBytes() (int64, error) {
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

func attachAAD(id string) []byte { return []byte("onion-chat/v1 attachment " + id) }
