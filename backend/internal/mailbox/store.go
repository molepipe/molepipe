// Package mailbox is the storage core of the standalone mailbox server (and,
// later, the friend-relay). It holds encrypted, opaque blobs on behalf of
// recipients keyed by account number — it never decrypts them and holds no
// identity of its own. It imports only identity (for account validation) and the
// standard library; it must never depend on chatstore, the vault, or identity
// key material, so the server binary provably cannot read anyone's mail.
package mailbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/wipe"
)

var (
	// ErrNoMailbox means the recipient has never checked in, so drop-offs are
	// refused — this is what stops the mailbox becoming an open dead-drop.
	ErrNoMailbox = errors.New("no mailbox for that account (recipient has not checked in)")
	// ErrOverCap means a cap (count, total bytes, or single-message size) is hit.
	ErrOverCap = errors.New("mailbox is full")
	// ErrBackupDisabled means this mailbox does not offer durable backup storage
	// (the operator left MaxBackupBytes at zero). Backups are opt-in per server.
	ErrBackupDisabled = errors.New("mailbox does not offer backup storage")
	// ErrNotFound means a by-id fetch found no blob under that id.
	ErrNotFound = errors.New("no such blob")
)

const (
	checkinFile  = "checkin" // marker file inside a tenant dir; presence == checked in
	blobPrefix   = "msg-"
	backupPrefix = "bak-" // durable self-backup blobs; a class apart from msg-
	blobSuffix   = ".json"
)

var idRe = regexp.MustCompile(`^[0-9a-f]{1,64}$`) // blob ids are hex content hashes

// Caps bound one account's storage. A zero field means "unlimited" for that axis
// — except MaxBackupBytes, where zero means "backups disabled" (see below).
type Caps struct {
	MaxMessages int           // queued message count
	MaxBytes    int64         // total queued bytes
	MaxMessage  int64         // single message size
	BlobTTL     time.Duration // retention for an undelivered blob
	IdleTTL     time.Duration // retention for a silent (checked-in but unused) tenancy
	// MaxBackupBytes is the total-bytes budget for the durable backup class (the
	// bak- blobs a client stores in its OWN mailbox as a group-image backup). It
	// is accounted separately from the message caps above: backups never count
	// against MaxBytes/MaxMessages and vice versa, so an operator's true per-tenant
	// ceiling is MaxBytes + MaxBackupBytes. Unlike the other axes, ZERO means
	// backups are refused (ErrBackupDisabled) rather than unlimited — durable,
	// never-auto-expiring storage is opt-in per server. A client may request a
	// SMALLER budget at drop-off time; the effective budget is the min of the two.
	MaxBackupBytes int64
	// MaxBackupMessage is the per-blob ceiling for a single backup blob. A full
	// group image (unlike a text message) is megabytes, so backups can't reuse the
	// tiny MaxMessage ceiling that bounds the unauthenticated message drop-off.
	// Kept separate so raising the backup ceiling never widens the message body
	// cap. Zero or negative falls back to MaxMessage.
	MaxBackupMessage int64
}

// backupMessage is the effective per-blob ceiling for a backup blob: the
// dedicated MaxBackupMessage if set, else MaxMessage.
func (c Caps) backupMessage() int64 {
	if c.MaxBackupMessage > 0 {
		return c.MaxBackupMessage
	}
	return c.MaxMessage
}

// Config configures the store: a data dir, server-wide default caps, and
// optional per-account overrides an operator sets for tenants needing headroom.
type Config struct {
	Dir       string
	Defaults  Caps
	Overrides map[string]Caps
	// OpenDropOff, when true, lets a drop-off create the recipient's tenancy
	// instead of requiring a prior check-in. Used by the friend-relay store: the
	// recipient (Carol) has no relationship with the relay-holder (Bob) and never
	// checks in, so access is gated by the relay handler instead. A dedicated
	// mailbox server leaves this false (check-in stops open dead-drops).
	OpenDropOff bool
	// GlobalMaxTenants caps the total number of tenancies (zero = unlimited).
	// The per-account Caps bound each tenancy's size, but nothing bounded their
	// NUMBER: in OpenDropOff mode an approved relay sender chooses the recipient,
	// so it can address endless invented recipients and create a tenancy per
	// name, filling the disk one 5 MiB bucket at a time. This ceiling makes total
	// relay storage ≤ GlobalMaxTenants × per-account MaxBytes. A dedicated mailbox
	// server (tenancies created only by a signed check-in) can leave this 0.
	GlobalMaxTenants int
}

// Store is a filesystem-backed multi-tenant blob store. All operations are
// serialized by a single mutex — ample for a mailbox's load and keeps the
// on-disk layout race-free.
type Store struct {
	cfg Config
	mu  sync.Mutex
	now func() time.Time
}

// Usage is a tenant's current occupancy plus its effective caps, so a client can
// render "mailbox 67% full" instead of hitting an invisible wall.
type Usage struct {
	Messages    int   `json:"messages"`
	Bytes       int64 `json:"bytes"`
	BackupBytes int64 `json:"backup_bytes"` // occupancy of the durable backup (bak-) class
	Caps        Caps  `json:"caps"`
}

// New creates a store, ensuring the data dir exists.
func New(cfg Config) (*Store, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("mailbox: empty data dir")
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("mailbox: create data dir: %w", err)
	}
	return &Store{cfg: cfg, now: time.Now}, nil
}

// MaxBlobBytes is the largest per-blob size any tenant may store — the max of the
// default and every override MaxMessage. Zero means at least one is unlimited.
// The server uses it to size the drop-off request-body cap so an operator who
// raises MaxMessage (e.g. to accept images) can actually receive those blobs.
func (s *Store) MaxBlobBytes() int64 {
	m := s.cfg.Defaults.MaxMessage
	unlimited := m <= 0
	for _, c := range s.cfg.Overrides {
		if c.MaxMessage <= 0 {
			unlimited = true
		} else if c.MaxMessage > m {
			m = c.MaxMessage
		}
	}
	if unlimited {
		return 0
	}
	return m
}

// MaxBackupBlobBytes is the largest single backup blob any tenant may store — the
// max of the default and every override backup ceiling. Zero means at least one is
// unlimited. The server uses it to size the backup drop-off request-body cap,
// independently of the (smaller) message drop-off cap. Only tenants that actually
// offer backups (MaxBackupBytes > 0) contribute.
func (s *Store) MaxBackupBlobBytes() int64 {
	consider := func(c Caps, m *int64, unlimited *bool) {
		if c.MaxBackupBytes <= 0 {
			return // backups disabled for this tenant; it stores no backup blobs
		}
		bm := c.backupMessage()
		if bm <= 0 {
			*unlimited = true
		} else if bm > *m {
			*m = bm
		}
	}
	var m int64
	var unlimited bool
	consider(s.cfg.Defaults, &m, &unlimited)
	for _, c := range s.cfg.Overrides {
		consider(c, &m, &unlimited)
	}
	if unlimited {
		return 0
	}
	return m
}

// caps returns the effective caps for an account (per-account override else defaults).
func (s *Store) caps(account string) Caps {
	if c, ok := s.cfg.Overrides[account]; ok {
		return c
	}
	return s.cfg.Defaults
}

// tenantDir maps a validated account to its directory. Account strings are
// validated base32 onion addresses (fixed charset, no separators), so they are
// safe to use as a path element.
func (s *Store) tenantDir(account string) string {
	return filepath.Join(s.cfg.Dir, account)
}

// checkTenantRoomLocked enforces GlobalMaxTenants when a NEW tenancy (dir does
// not yet exist) is about to be created. Existing tenancies are already bounded
// by the per-account caps, so only creation is gated. Caller holds s.mu.
func (s *Store) checkTenantRoomLocked(dir string) error {
	if s.cfg.GlobalMaxTenants <= 0 {
		return nil
	}
	if _, err := os.Stat(dir); err == nil {
		return nil // tenancy already exists; not a new one
	}
	entries, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && validAccount(e.Name()) == nil {
			n++
		}
	}
	if n >= s.cfg.GlobalMaxTenants {
		return ErrOverCap
	}
	return nil
}

func validAccount(account string) error {
	if _, err := identity.AccountNumberFromString(account); err != nil {
		return fmt.Errorf("mailbox: invalid account: %w", err)
	}
	return nil
}

func (s *Store) checkedIn(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, checkinFile))
	return err == nil
}

// CheckIn records that an account is actively receiving here, creating its
// tenancy if needed, and returns current usage. Only check-in creates a tenancy.
func (s *Store) CheckIn(account string) (Usage, error) {
	if err := validAccount(account); err != nil {
		return Usage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(account)
	if err := s.checkTenantRoomLocked(dir); err != nil {
		return Usage{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Usage{}, fmt.Errorf("mailbox: create tenant: %w", err)
	}
	stamp := s.now().UTC().Format(time.RFC3339)
	if err := atomicWrite(filepath.Join(dir, checkinFile), []byte(stamp), 0o600); err != nil {
		return Usage{}, err
	}
	return s.usageLocked(account, dir)
}

// DropOff stores a blob for a recipient. It refuses if the recipient has not
// checked in (ErrNoMailbox) and never creates a tenancy as a side effect. A
// blob whose id already exists is a no-op (replay/de-dup), returning nil.
func (s *Store) DropOff(recipient, id string, blob []byte) error {
	if err := validAccount(recipient); err != nil {
		return err
	}
	if !idRe.MatchString(id) {
		return fmt.Errorf("mailbox: invalid blob id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(recipient)
	if !s.checkedIn(dir) {
		if !s.cfg.OpenDropOff {
			return ErrNoMailbox
		}
		// Relay mode: create the tenancy on first drop-off (recipient never
		// checks in with a relay-holder). Access is gated by the relay handler.
		// A new tenancy counts against the global cap so an approved sender can't
		// fill the disk by addressing endless invented recipients.
		if err := s.checkTenantRoomLocked(dir); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mailbox: create relay tenant: %w", err)
		}
	}
	caps := s.caps(recipient)
	if caps.MaxMessage > 0 && int64(len(blob)) > caps.MaxMessage {
		return ErrOverCap
	}
	path := filepath.Join(dir, blobPrefix+id+blobSuffix)
	if _, err := os.Stat(path); err == nil {
		return nil // already have it — replayed or duplicate drop-off
	}
	count, bytes, err := s.occupancyLocked(dir)
	if err != nil {
		return err
	}
	if caps.MaxMessages > 0 && count >= caps.MaxMessages {
		return ErrOverCap
	}
	if caps.MaxBytes > 0 && bytes+int64(len(blob)) > caps.MaxBytes {
		return ErrOverCap
	}
	return atomicWrite(path, blob, 0o600)
}

// Item is one stored blob returned on pickup.
type Item struct {
	ID       string
	StoredAt time.Time
	Blob     []byte
}

// Pickup returns all non-expired blobs waiting for an account, oldest first.
func (s *Store) Pickup(account string) ([]Item, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(account)
	caps := s.caps(account)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, e := range entries {
		id, ok := blobID(e.Name())
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if caps.BlobTTL > 0 && s.now().Sub(info.ModTime()) > caps.BlobTTL {
			continue // expired; Sweep removes it
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		items = append(items, Item{ID: id, StoredAt: info.ModTime(), Blob: blob})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].StoredAt.Before(items[j].StoredAt) })
	return items, nil
}

// Delete removes the named blobs after the client confirms local pickup.
func (s *Store) Delete(account string, ids []string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(account)
	for _, id := range ids {
		if !idRe.MatchString(id) {
			continue
		}
		if err := wipe.File(filepath.Join(dir, blobPrefix+id+blobSuffix)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// DropOffBackup stores a durable backup blob (the bak- class) for an account's
// OWN mailbox — a group-image backup the owner drops in for itself. It differs
// from DropOff in three ways that make it a backup rather than a forwarded
// message: (1) the blob survives Pickup/Delete (those only touch msg- blobs), so
// the owner's routine mailbox poll never consumes it; (2) when the backup budget
// would be exceeded it EVICTS the oldest backups to make room instead of
// rejecting the new blob; (3) it is bounded by a separate MaxBackupBytes budget.
//
// budget is the owner's requested byte budget; the effective budget is the min of
// it and the server's MaxBackupBytes (a zero/negative budget means "no client
// preference — use the server cap"). Like DropOff it requires a prior check-in
// (backups only ever go to one's own, checked-in mailbox) and de-dups by id.
func (s *Store) DropOffBackup(account, id string, blob []byte, budget int64) error {
	if err := validAccount(account); err != nil {
		return err
	}
	if !idRe.MatchString(id) {
		return fmt.Errorf("mailbox: invalid blob id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(account)
	if !s.checkedIn(dir) {
		// Backups are self-addressed to one's own mailbox; there is no relay/open
		// path for them. No check-in, no backup — and never create a tenancy here.
		return ErrNoMailbox
	}
	caps := s.caps(account)
	if caps.MaxBackupBytes <= 0 {
		return ErrBackupDisabled // operator does not offer backup storage
	}
	eff := caps.MaxBackupBytes
	if budget > 0 && budget < eff {
		eff = budget
	}
	if bm := caps.backupMessage(); bm > 0 && int64(len(blob)) > bm {
		return ErrOverCap // exceeds the per-blob backup ceiling
	}
	if int64(len(blob)) > eff {
		return ErrOverCap // a single blob larger than the whole budget can never fit
	}
	path := filepath.Join(dir, backupPrefix+id+blobSuffix)
	if _, err := os.Stat(path); err == nil {
		return nil // already have it — de-dup
	}
	// Evict oldest backups until the newcomer fits within the effective budget.
	backups, bytes, err := s.backupsLocked(dir)
	if err != nil {
		return err
	}
	need := int64(len(blob))
	for bytes+need > eff && len(backups) > 0 {
		oldest := backups[0]
		backups = backups[1:]
		if err := os.Remove(filepath.Join(dir, oldest.name)); err != nil && !os.IsNotExist(err) {
			return err
		}
		bytes -= oldest.size
	}
	return atomicWrite(path, blob, 0o600)
}

// PickupBackup returns all backup (bak-) blobs for an account, oldest first. It
// does NOT delete them: backups are durable and other devices of the same owner
// may still need to restore from them. A fresh device calls this once to rehydrate
// its group images, then leaves the backups in place.
func (s *Store) PickupBackup(account string) ([]Item, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(account)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, e := range entries {
		id, ok := backupBlobID(e.Name())
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		items = append(items, Item{ID: id, StoredAt: info.ModTime(), Blob: blob})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].StoredAt.Before(items[j].StoredAt) })
	return items, nil
}

// BackupMeta is one backup blob's id and size, WITHOUT its bytes. It lets a
// restoring device list what backups exist and fetch only the ones it is missing,
// one at a time — the whole-set PickupBackup response would blow past both the
// client's response-size limit and the request timeout at a realistic byte budget.
type BackupMeta struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
}

// ListBackups returns the ids and sizes of an account's backup blobs, oldest-first,
// without reading any blob bytes. A restoring device lists first, then fetches by id
// only the backups whose bytes it lacks locally.
func (s *Store) ListBackups(account string) ([]BackupMeta, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, _, err := s.backupsLocked(s.tenantDir(account))
	if err != nil {
		return nil, err
	}
	out := make([]BackupMeta, 0, len(files))
	for _, f := range files {
		id, ok := backupBlobID(f.name)
		if !ok {
			continue
		}
		out = append(out, BackupMeta{ID: id, Size: f.size})
	}
	return out, nil
}

// GetBackup returns a single backup blob by id (non-destructive), or ErrNotFound if
// the account has no backup under that id. Used by the by-id restore path so each
// response carries at most one group image rather than the whole backup set.
func (s *Store) GetBackup(account, id string) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	if !idRe.MatchString(id) {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, err := os.ReadFile(filepath.Join(s.tenantDir(account), backupPrefix+id+blobSuffix))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// PurgeBackups removes all backup blobs for an account (leaving its messages and
// tenancy intact). Used when the owner turns the backup feature off.
func (s *Store) PurgeBackups(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.tenantDir(account)
	backups, _, err := s.backupsLocked(dir)
	if err != nil {
		return err
	}
	for _, b := range backups {
		if err := os.Remove(filepath.Join(dir, b.name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// Forget purges all state for an account ("forget me").
func (s *Store) Forget(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return wipe.Dir(s.tenantDir(account))
}

// Recipients lists the accounts that currently have blobs waiting. Used by the
// friend-relay forward loop to know whom to try delivering to.
func (s *Store) Recipients() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if validAccount(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// Usage returns an account's current occupancy and effective caps.
func (s *Store) Usage(account string) (Usage, error) {
	if err := validAccount(account); err != nil {
		return Usage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usageLocked(account, s.tenantDir(account))
}

// Sweep expires stale blobs and silent tenancies. Intended to run periodically.
func (s *Store) Sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenants, err := os.ReadDir(s.cfg.Dir)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		if !t.IsDir() {
			continue
		}
		account := t.Name()
		dir := s.tenantDir(account)
		caps := s.caps(account)

		// Purge a tenancy that checked in but has been silent past IdleTTL —
		// UNLESS it holds durable backups. Backup blobs never TTL-expire (they are
		// the owner's group-image safety net, restored from on a fresh device), so
		// idle-purging a backup-bearing tenancy would silently destroy them.
		if caps.IdleTTL > 0 {
			if info, err := os.Stat(filepath.Join(dir, checkinFile)); err == nil {
				if s.now().Sub(info.ModTime()) > caps.IdleTTL {
					if backups, _, err := s.backupsLocked(dir); err != nil || len(backups) == 0 {
						_ = os.RemoveAll(dir)
						continue
					}
				}
			}
		}
		// Expire individual blobs past BlobTTL.
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		remaining := 0
		for _, e := range entries {
			if _, ok := blobID(e.Name()); !ok {
				continue
			}
			if info, err := e.Info(); err == nil && caps.BlobTTL > 0 && s.now().Sub(info.ModTime()) > caps.BlobTTL {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			} else {
				remaining++
			}
		}
		// Clean up a fully-delivered relay tenancy (no check-in marker, no blobs).
		if remaining == 0 && !s.checkedIn(dir) {
			_ = os.RemoveAll(dir)
		}
	}
	return nil
}

func (s *Store) usageLocked(account, dir string) (Usage, error) {
	count, bytes, err := s.occupancyLocked(dir)
	if err != nil {
		return Usage{}, err
	}
	_, backupBytes, err := s.backupsLocked(dir)
	if err != nil {
		return Usage{}, err
	}
	return Usage{Messages: count, Bytes: bytes, BackupBytes: backupBytes, Caps: s.caps(account)}, nil
}

func (s *Store) occupancyLocked(dir string) (count int, bytes int64, err error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if _, ok := blobID(e.Name()); !ok {
			continue
		}
		if info, err := e.Info(); err == nil {
			count++
			bytes += info.Size()
		}
	}
	return count, bytes, nil
}

// idFromName extracts the hex id from a "<prefix><id>.json" filename, or reports
// that the name isn't a blob of that class. The msg- and bak- prefixes are
// disjoint, so a bak- file never reads as a message blob and vice versa — which
// is exactly what keeps the backup class invisible to the message flow.
func idFromName(name, prefix string) (string, bool) {
	if len(name) <= len(prefix)+len(blobSuffix) {
		return "", false
	}
	if name[:len(prefix)] != prefix || name[len(name)-len(blobSuffix):] != blobSuffix {
		return "", false
	}
	id := name[len(prefix) : len(name)-len(blobSuffix)]
	if !idRe.MatchString(id) {
		return "", false
	}
	return id, true
}

// blobID extracts the id from a message (msg-) blob filename, or reports it isn't one.
func blobID(name string) (string, bool) { return idFromName(name, blobPrefix) }

// backupBlobID extracts the id from a backup (bak-) blob filename, or reports it isn't one.
func backupBlobID(name string) (string, bool) { return idFromName(name, backupPrefix) }

// backupFile is one backup blob's on-disk name and size, used for eviction.
type backupFile struct {
	name string
	size int64
	mod  time.Time
}

// backupsLocked lists the account's backup blobs oldest-first (eviction order)
// with their total byte occupancy. Caller holds s.mu.
func (s *Store) backupsLocked(dir string) (files []backupFile, bytes int64, err error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	for _, e := range entries {
		if _, ok := backupBlobID(e.Name()); !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, backupFile{name: e.Name(), size: info.Size(), mod: info.ModTime()})
		bytes += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	return files, bytes, nil
}

func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
