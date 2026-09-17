package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestInboundHookFires covers the callback that the Android shell turns into a
// system notification: deliverInboundLocked must fire it once for a newly
// delivered message (with the sender's display name and the text), and never for
// a duplicate re-delivery.
func TestInboundHookFires(t *testing.T) {
	s, _ := unlocked(t)
	fired := make(chan [2]string, 4)
	s.SetInboundHook(func(name, preview string, atMillis int64, _ string) {
		fired <- [2]string{name, preview}
	})

	peer, _ := identity.New()
	at := time.Now()
	s.sessMu.Lock()
	s.contacts[peer.AccountNumber()] = chatstore.Contact{
		Account: peer.AccountNumber(), Status: chatstore.StatusAccepted, Name: "Alice",
	}
	added := s.deliverInboundLocked(peer.AccountNumber(), "", "hello there", at, protocol.Reply{})
	s.sessMu.Unlock()
	if !added {
		t.Fatal("first delivery should be newly added")
	}
	select {
	case v := <-fired:
		if v[0] != "Alice" || v[1] != "hello there" {
			t.Fatalf("hook got name=%q preview=%q, want Alice/hello there", v[0], v[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inbound hook did not fire for a new message")
	}

	// A duplicate (same sender+text+time → same content id) is de-duped and must
	// not fire the hook again, or a lost mailbox delete would re-notify.
	s.sessMu.Lock()
	again := s.deliverInboundLocked(peer.AccountNumber(), "", "hello there", at, protocol.Reply{})
	s.sessMu.Unlock()
	if again {
		t.Fatal("duplicate delivery should not be re-added")
	}
	select {
	case v := <-fired:
		t.Fatalf("hook fired for a duplicate: %v", v)
	case <-time.After(300 * time.Millisecond):
	}
}
