package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	// backupDropTimeout bounds a single self-backup drop-off (one full image,
	// ~4 MiB base64 over Tor). backupRestoreTimeout bounds a whole restore run,
	// which fetches many blobs one at a time; a run that runs out of time is
	// resumable — the next tick pulls whatever is still missing.
	backupDropTimeout    = 2 * time.Minute
	backupRestoreTimeout = 10 * time.Minute
	// backupRestoreEvery caps how often the auto-restore lists our mailbox. The
	// missing-set is almost never empty (on-demand fetch leaves most group images
	// undownloaded), so without this the tick would List over Tor every minute
	// forever. A fresh device that missed its window just waits for the next slot;
	// the manual restore button bypasses the throttle entirely.
	backupRestoreEvery = 15 * time.Minute
)

// backupGroupImage drops a self-sealed copy of a full group image into OUR OWN
// mailbox, off the request path, so a fresh device can restore group images the
// authors may no longer be online to serve. It is a no-op unless the user has
// opted in (a mailbox is configured AND a nonzero byte budget is set) and Tor is
// up. The blob id is the stable attachment id (fullID), so a re-send of the same
// image can Put() under that id on restore. (The id is fresh per send, so this
// de-dups a retry of one message, not two separate sends of identical bytes.)
func (s *Server) backupGroupImage(id *identity.Identity, fullID, mime string, data []byte) {
	s.sessMu.Lock()
	mailbox := s.mailboxURL
	budget := s.backupBudget
	s.sessMu.Unlock()
	if mailbox == "" || budget <= 0 || s.onion == nil || id == nil {
		return
	}
	env, err := protocol.SealSelfBackupImage(id, fullID, mime, data, time.Now())
	if err != nil {
		log.Printf("group-image backup seal: %v", err)
		return
	}
	ctx, cancel := deliveryContext(backupDropTimeout)
	defer cancel()
	if err := protocol.MailboxBackupDropOff(ctx, s.onion.Dialer(), id, mailbox, fullID, budget, env); err != nil {
		log.Printf("group-image backup drop-off: %v", err)
	}
}

// purgeGroupImageBackups clears every durable group-image backup from our own
// mailbox. Called when the user turns the budget off (nonzero → 0) so the copies
// don't linger on the server. Best-effort and off the request path.
func (s *Server) purgeGroupImageBackups() {
	s.sessMu.Lock()
	mailbox := s.mailboxURL
	id := s.sessID
	s.sessMu.Unlock()
	if mailbox == "" || id == nil || s.onion == nil {
		return
	}
	ctx, cancel := deliveryContext(backupDropTimeout)
	defer cancel()
	if err := protocol.MailboxBackupPurge(ctx, s.onion.Dialer(), id, mailbox); err != nil {
		log.Printf("group-image backup purge: %v", err)
	}
}

// missingGroupImagesLocked returns the full-blob ids we should try to restore,
// mapped to the author-signed hash each blob's bytes must match. A row qualifies
// only if it is a group image (Kind image + a group id) with an attach id whose
// blob the local store does not hold. Caller must hold sessMu.
func (s *Server) missingGroupImagesLocked() map[string][]byte {
	want := make(map[string][]byte)
	if s.attach == nil {
		return want
	}
	for i := range s.messages {
		m := s.messages[i]
		if m.Kind != chatstore.KindImage || m.GroupID == "" || m.AttachID == "" {
			continue
		}
		if !s.attach.Has(m.AttachID) {
			want[m.AttachID] = m.FullHash
		}
	}
	return want
}

// restoreGroupImageBackups pulls full group-image bytes we are missing from our
// own mailbox backups. "Missing" = a group-image row (synced to us over the
// device-sync path) whose full blob we don't hold. It lists backup ids, fetches
// only the missing ones one at a time (bounded per response), verifies each blob
// against the author-signed hash on the row before storing, and returns how many
// it restored. It short-circuits with zero network I/O when nothing is missing.
// On the auto path (force=false) it also lists at most once per backupRestoreEvery,
// since the missing-set is rarely empty; a manual restore passes force=true to
// bypass that throttle. Only one run proceeds at a time (backupRestoreRunning); a
// second caller returns immediately.
func (s *Server) restoreGroupImageBackups(ctx context.Context, id *identity.Identity, force bool) (int, error) {
	s.sessMu.Lock()
	if s.backupRestoreRunning {
		s.sessMu.Unlock()
		return 0, nil
	}
	mailbox := s.mailboxURL
	store := s.attach
	want := s.missingGroupImagesLocked()
	if mailbox == "" || id == nil || s.onion == nil || store == nil || len(want) == 0 {
		s.sessMu.Unlock()
		return 0, nil
	}
	if !force && time.Since(s.lastBackupRestore) < backupRestoreEvery {
		s.sessMu.Unlock() // listed recently; the on-demand fetch path will fill any urgent gap
		return 0, nil
	}
	s.lastBackupRestore = time.Now()
	s.backupRestoreRunning = true
	s.sessMu.Unlock()
	defer func() {
		s.sessMu.Lock()
		s.backupRestoreRunning = false
		s.sessMu.Unlock()
	}()

	cctx, cancel := context.WithTimeout(ctx, backupRestoreTimeout)
	defer cancel()
	metas, err := protocol.MailboxBackupList(cctx, s.onion.Dialer(), id, mailbox)
	if err != nil {
		return 0, err
	}
	restored := 0
	for _, meta := range metas {
		hash, missing := want[meta.ID]
		if !missing {
			continue
		}
		env, err := protocol.MailboxBackupFetch(cctx, s.onion.Dialer(), id, mailbox, meta.ID)
		if err != nil {
			log.Printf("group-image backup fetch %s: %v", meta.ID, err)
			continue
		}
		c, err := protocol.OpenMailContent(id, env)
		if err != nil {
			log.Printf("group-image backup open %s: %v", meta.ID, err)
			continue
		}
		// The blob is self-sealed, but keep the store's invariant that no bytes land
		// under a full-image id without matching the author-signed hash on the row.
		sum := sha256.Sum256(c.Data)
		if c.Kind != protocol.MailKindImage || c.MsgID != meta.ID || len(hash) == 0 || !bytes.Equal(sum[:], hash) {
			log.Printf("group-image backup %s failed verification, skipping", meta.ID)
			continue
		}
		s.sessMu.Lock()
		var putErr error
		if s.attach != nil {
			putErr = s.attach.Put(meta.ID, c.Data)
		}
		s.sessMu.Unlock()
		if putErr != nil {
			log.Printf("group-image backup store %s: %v", meta.ID, putErr)
			continue
		}
		restored++
	}
	return restored, nil
}
