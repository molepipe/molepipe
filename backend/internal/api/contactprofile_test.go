package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// TestContactMailboxGate locks the read-only accepted-status gate that guards the
// mailbox on the gated contact-profile endpoint. The mailbox is disclosed ONLY to
// an accepted contact; a stranger and — critically — a pending_out contact both
// get "". The pending_out case is the one the audit flagged: it must NOT be
// upgraded to accepted as a side effect of asking (the bug you'd reintroduce by
// reusing allowMessageLocked here). We assert both the empty result AND that the
// pending_out status is untouched afterward, so a future refactor swapping in a
// mutating predicate is caught.
func TestContactMailboxGate(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1") // never dialed by this test
	const box = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"

	newAcct := func() string {
		id, err := identity.New()
		if err != nil {
			t.Fatal(err)
		}
		return id.AccountNumber()
	}
	accepted := newAcct()
	pending := newAcct()
	stranger := newAcct() // never added — no contact row at all

	s.sessMu.Lock()
	s.mailboxURL = box
	s.contacts[accepted] = chatstore.Contact{Account: accepted, Status: chatstore.StatusAccepted}
	s.contacts[pending] = chatstore.Contact{Account: pending, Status: chatstore.StatusPendingOut}
	s.sessMu.Unlock()

	if got := s.hookContactMailbox(accepted); got != box {
		t.Errorf("accepted contact: mailbox = %q, want %q", got, box)
	}
	if got := s.hookContactMailbox(pending); got != "" {
		t.Errorf("pending_out contact leaked mailbox %q, want empty", got)
	}
	if got := s.hookContactMailbox(stranger); got != "" {
		t.Errorf("stranger leaked mailbox %q, want empty", got)
	}

	// The read must not have mutated trust state: pending_out stays pending_out.
	s.sessMu.Lock()
	st := s.contacts[pending].Status
	s.sessMu.Unlock()
	if st != chatstore.StatusPendingOut {
		t.Errorf("asking upgraded pending_out to %q (mailbox gate must be a pure read)", st)
	}
}
