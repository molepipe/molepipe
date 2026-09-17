package api

import (
	"context"
	"log"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	mailboxStartDelay = 15 * time.Second // let Tor warm up before the first tick
	mailboxInterval   = 60 * time.Second // check-in keeps the tenancy alive; pickup fetches mail
	mailboxOpTimeout  = 90 * time.Second // per-tick budget for the mailbox round trips
)

// mailboxLoop keeps our own mailbox alive (check-in) and pulls anything waiting
// (pickup → decrypt → gate → deliver → delete). It's a no-op on any tick where
// no mailbox is configured, so enabling a mailbox in settings simply starts
// having an effect on the next tick — no restart needed.
func (s *Server) mailboxLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(mailboxStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mailboxTick(ctx, id)
			t.Reset(mailboxInterval)
		}
	}
}

func (s *Server) mailboxTick(ctx context.Context, id *identity.Identity) {
	s.sessMu.Lock()
	mailbox := s.mailboxURL
	s.sessMu.Unlock()
	if mailbox == "" || s.onion == nil {
		return
	}

	cctx, cancel := context.WithTimeout(ctx, mailboxOpTimeout)
	defer cancel()

	// Check in so the mailbox accepts drop-offs for us and keeps our tenancy.
	if _, err := protocol.MailboxCheckIn(cctx, s.onion.Dialer(), id, mailbox); err != nil {
		log.Printf("mailbox check-in: %v", err)
		return
	}

	// Restore any full group images we're missing from our own durable backups.
	// Runs detached (it can fetch many blobs and take minutes) so it never stalls
	// check-in or pickup; the throttle + backupRestoreRunning guard keep it cheap
	// and non-overlapping across ticks. Use the loop ctx, not the per-tick one.
	go func() {
		if n, err := s.restoreGroupImageBackups(ctx, id, false); err != nil {
			log.Printf("group-image backup restore: %v", err)
		} else if n > 0 {
			log.Printf("restored %d group image(s) from backup", n)
		}
	}()

	items, err := protocol.MailboxPickup(cctx, s.onion.Dialer(), id, mailbox)
	if err != nil {
		log.Printf("mailbox pickup: %v", err)
		return
	}

	// Deliver what we can, then delete only what we delivered. Anything we can't
	// open or aren't allowed to accept yet (e.g. a pending_in sender we haven't
	// accepted) is left for a later tick, bounded by the server's TTL.
	var deliveredIDs []string
	for _, env := range items {
		// OpenMailContent enforces the image size cap + MIME allowlist on open (the
		// sender is untrusted) and distinguishes text from image.
		c, err := protocol.OpenMailContent(id, env)
		if err != nil {
			continue
		}
		s.sessMu.Lock()
		if s.allowMessageLocked(c.Sender) { // contacts-only gate, same as direct delivery
			var stored bool
			if c.Kind == protocol.MailKindImage {
				stored = s.deliverInboundImageLocked(c.Sender, c.MsgID, c.Mime, c.Data, c.SentAt)
			} else {
				stored = s.deliverInboundLocked(c.Sender, c.MsgID, c.Text, c.SentAt, c.Reply)
			}
			if stored {
				s.persistLocked()
			}
			// Delete from the box whenever the sender is allowed — a redelivered
			// duplicate (stored==false) is still ours to clear.
			deliveredIDs = append(deliveredIDs, env.ID())
		}
		s.sessMu.Unlock()
	}

	if len(deliveredIDs) > 0 {
		if err := protocol.MailboxDelete(cctx, s.onion.Dialer(), id, mailbox, deliveredIDs); err != nil {
			log.Printf("mailbox delete: %v", err)
		}
	}
}
