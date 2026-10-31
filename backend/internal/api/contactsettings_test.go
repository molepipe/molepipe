package api

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestMutedContactStillDeliversButDoesNotNotify pins the whole point of mute:
// it suppresses the NOTIFICATION, not the message. A mute that silently dropped
// messages would be a data-loss bug wearing a settings toggle, and the two
// halves of that claim have to be asserted together — a test that only checked
// "no notification" would pass just as happily if delivery broke.
func TestMutedContactStillDeliversButDoesNotNotify(t *testing.T) {
	s, _ := unlocked(t)
	fired := make(chan string, 4)
	s.SetInboundHook(func(name, preview string, _ int64, _ string) { fired <- preview })

	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{
		Account: acct, Status: chatstore.StatusAccepted, Name: "Alice", Muted: true,
	}
	added := s.deliverInboundLocked(acct, "", "quiet one", time.Now(), protocol.Reply{})
	msgs := len(s.messages)
	s.sessMu.Unlock()

	if !added {
		t.Fatal("a muted contact's message must still be delivered")
	}
	if msgs != 1 {
		t.Fatalf("message log has %d messages, want 1 — mute must not drop the message", msgs)
	}
	select {
	case p := <-fired:
		t.Fatalf("muted contact still raised a notification: %q", p)
	case <-time.After(300 * time.Millisecond):
	}

	// Unmuting restores notifications — otherwise mute would be a one-way door.
	s.sessMu.Lock()
	c := s.contacts[acct]
	c.Muted = false
	s.contacts[acct] = c
	s.deliverInboundLocked(acct, "", "loud one", time.Now(), protocol.Reply{})
	s.sessMu.Unlock()
	select {
	case p := <-fired:
		if p != "loud one" {
			t.Fatalf("hook preview = %q, want \"loud one\"", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unmuted contact did not notify")
	}
}

// TestContactSettingsRoundTrip covers the tri-state media override, which is the
// part most likely to rot: "default" must be stored as nil (inherit) and stay
// distinguishable from an explicit "off".
func TestContactSettingsRoundTrip(t *testing.T) {
	s, tok := unlocked(t)
	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted, Name: "Alice"}
	s.sessMu.Unlock()

	org := authHdr(s, tok)
	org["Origin"] = s.origin()
	body := `{"account":"` + acct + `","muted":true,"media_auto_save":"off"}`
	if rr := s.do(t, "POST", "/api/contacts/settings", body, org); rr.Code != 200 {
		t.Fatalf("set settings: %d %s", rr.Code, rr.Body.String())
	}
	s.sessMu.Lock()
	c := s.contacts[acct]
	s.sessMu.Unlock()
	if !c.Muted {
		t.Fatal("muted was not persisted")
	}
	if c.MediaAutoSave == nil || *c.MediaAutoSave {
		t.Fatalf("media override = %v, want explicit false", c.MediaAutoSave)
	}
	if got := mediaPolicyOf(c); got != mediaPolicyOff {
		t.Fatalf("mediaPolicyOf = %q, want %q", got, mediaPolicyOff)
	}

	// Omitting a field must leave it alone, so one switch can't clobber the other.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","muted":false}`, org); rr.Code != 200 {
		t.Fatalf("partial update: %d", rr.Code)
	}
	s.sessMu.Lock()
	c = s.contacts[acct]
	s.sessMu.Unlock()
	if c.Muted {
		t.Fatal("muted was not cleared")
	}
	if c.MediaAutoSave == nil || *c.MediaAutoSave {
		t.Fatalf("omitted media_auto_save was clobbered: %v", c.MediaAutoSave)
	}

	// "default" clears the override back to inherit (nil), NOT to false.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","media_auto_save":"default"}`, org); rr.Code != 200 {
		t.Fatalf("reset to default: %d", rr.Code)
	}
	s.sessMu.Lock()
	c = s.contacts[acct]
	s.sessMu.Unlock()
	if c.MediaAutoSave != nil {
		t.Fatalf("media override = %v, want nil (inherit)", *c.MediaAutoSave)
	}

	// An unknown account must not be able to grow the contact map.
	other, _ := identity.New()
	rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+other.AccountNumber()+`","muted":true}`, org)
	if rr.Code != 404 {
		t.Fatalf("settings for an unknown contact: %d, want 404", rr.Code)
	}
	s.sessMu.Lock()
	_, grew := s.contacts[other.AccountNumber()]
	s.sessMu.Unlock()
	if grew {
		t.Fatal("settings call created a contact that did not exist")
	}

	// A bogus policy string is rejected rather than coerced.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","media_auto_save":"sometimes"}`, org); rr.Code != 400 {
		t.Fatalf("invalid policy: %d, want 400", rr.Code)
	}
}

// TestClearChatIsScopedAndTombstoned covers the two ways a bulk clear goes
// wrong: taking the neighbouring conversation with it, and forgetting the
// tombstones (which would let the next /sync pull the whole chat back from the
// user's other device, making "clear chat" look like it silently failed).
func TestClearChatIsScopedAndTombstoned(t *testing.T) {
	s, tok := unlocked(t)
	hdr := authHdr(s, tok)
	hdr["Origin"] = s.origin()

	a, _ := identity.New()
	b, _ := identity.New()
	s.sessMu.Lock()
	s.contacts[a.AccountNumber()] = chatstore.Contact{Account: a.AccountNumber(), Status: chatstore.StatusAccepted, Name: "Alice"}
	s.contacts[b.AccountNumber()] = chatstore.Contact{Account: b.AccountNumber(), Status: chatstore.StatusAccepted, Name: "Bob"}
	s.deliverInboundLocked(a.AccountNumber(), "", "one", time.Now(), protocol.Reply{})
	s.deliverInboundLocked(a.AccountNumber(), "", "two", time.Now().Add(time.Second), protocol.Reply{})
	s.deliverInboundLocked(b.AccountNumber(), "", "keep me", time.Now(), protocol.Reply{})
	s.sessMu.Unlock()

	rr := s.do(t, "POST", "/api/messages/clear", `{"account":"`+a.AccountNumber()+`"}`, hdr)
	if rr.Code != 200 {
		t.Fatalf("clear: %d %s", rr.Code, rr.Body.String())
	}
	if got := decode(t, rr.Body)["removed"]; got != float64(2) {
		t.Fatalf("removed = %v, want 2", got)
	}

	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for _, m := range s.messages {
		if m.Peer == a.AccountNumber() {
			t.Fatalf("message survived the clear: %+v", m)
		}
	}
	if len(s.messages) != 1 || s.messages[0].Text != "keep me" {
		t.Fatalf("the other conversation was damaged: %+v", s.messages)
	}
	if _, ok := s.contacts[a.AccountNumber()]; !ok {
		t.Fatal("clear chat removed the contact; it must only remove history")
	}
	if len(s.deleted) != 2 {
		t.Fatalf("tombstones = %d, want 2 — a sync would resurrect the chat", len(s.deleted))
	}
}
