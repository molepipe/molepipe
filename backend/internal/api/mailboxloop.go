package api

import (
	"context"
	"log"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	mailboxInterval  = 60 * time.Second // check-in keeps the tenancy alive; pickup fetches mail
	mailboxOpTimeout = 90 * time.Second // per-tick budget for the mailbox round trips
)

// mailboxLoop keeps our own mailbox alive (check-in) and pulls anything waiting
// (pickup → decrypt → gate → deliver → delete). It's a no-op on any tick where
// no mailbox is configured, so enabling a mailbox in settings simply starts
// having an effect on the next tick — no restart needed.
func (s *Server) mailboxLoop(ctx context.Context, id *identity.Identity) {
	s.runLoop(ctx, mailboxInterval, func() {
		s.mailboxTick(ctx, id)
	})
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
		if c.Kind == protocol.MailKindRotation {
			// A rotation announcement arrives sealed under the sender's NEW (not-yet-
			// trusted) alias, so it can't clear the contacts-only gate on c.Sender. Its
			// authenticity rests on the CHANNEL: the static-DH mailbox seal only opens
			// for a holder of the sender's stable DHPub, so a successful open PROVES
			// possession of that key. Resolve env.SenderDHPub (NEVER a payload field) to
			// the accepted contact and apply. A genuine apply (or an idempotent dup,
			// both err==nil) clears the box; anything unresolved/stale is left for TTL.
			if acct, ok := s.lookupContactByDHPubLocked(env.SenderDHPub); ok {
				if err := s.applyAddressRotationLocked(acct, c.Rotation.NewOnion, c.Rotation.AliasIndex); err == nil {
					deliveredIDs = append(deliveredIDs, env.ID())
					// Ack back over the session (best-effort) so the rotator's resend
					// loop can stop; if we have no session yet, their next online resend
					// re-triggers an ack. Same idempotent-must-ack rule as the direct path.
					go s.deliverRotationAck(id, c.Rotation.NewOnion, c.Rotation.AliasIndex)
				}
			}
			s.sessMu.Unlock()
			continue
		}
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
