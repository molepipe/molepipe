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
	s.SetInboundHook(func(_, name, preview string, atMillis int64, _ string) {
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

// TestInboundHookConvKeyIsStableAcrossARename is the regression test for a bug
// in the Android shell: it keyed each conversation's notification on the
// sender's DISPLAY NAME, so renaming a contact while an undismissed
// notification from them was still in the shade posted a second notification
// instead of replacing the first. The fix was to hand the shell a stable
// conversation key, and this pins the half the shell depends on — the key must
// be derived from the account and must NOT move when the display name does.
func TestInboundHookConvKeyIsStableAcrossARename(t *testing.T) {
	s, _ := unlocked(t)
	type call struct{ convKey, name string }
	fired := make(chan call, 4)
	s.SetInboundHook(func(convKey, name, _ string, _ int64, _ string) {
		fired <- call{convKey, name}
	})

	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{
		Account: acct, Status: chatstore.StatusAccepted, Name: "Alice",
	}
	s.deliverInboundLocked(acct, "", "first", time.Now(), protocol.Reply{})
	s.sessMu.Unlock()

	var before call
	select {
	case before = <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("inbound hook did not fire")
	}
	if before.name != "Alice" {
		t.Fatalf("display name = %q, want Alice", before.name)
	}
	// The key must not be the thing the user can edit. Checked explicitly
	// because passing the display name into the convKey slot is precisely the
	// mistake this exists to catch, and both are strings.
	if before.convKey == before.name {
		t.Fatalf("convKey %q is the display name; it must be derived from the account", before.convKey)
	}
	if want := convKeyDM(acct); before.convKey != want {
		t.Fatalf("convKey = %q, want %q", before.convKey, want)
	}

	// Rename the contact, exactly as the user giving them a nickname would.
	s.sessMu.Lock()
	c := s.contacts[acct]
	c.Name = "Alice (work)"
	s.contacts[acct] = c
	s.deliverInboundLocked(acct, "", "second", time.Now().Add(time.Second), protocol.Reply{})
	s.sessMu.Unlock()

	var after call
	select {
	case after = <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("inbound hook did not fire after the rename")
	}
	if after.name == before.name {
		t.Fatalf("display name did not change (%q); the test is not exercising a rename", after.name)
	}
	if after.convKey != before.convKey {
		t.Fatalf("convKey moved on rename: %q -> %q; the shell would post a second notification",
			before.convKey, after.convKey)
	}
}

// A group conversation must get a key too, and it must likewise survive the
// group being renamed — the group's title is the notification's display name.
func TestInboundHookConvKeyNamespacesGroupsApartFromDirectMessages(t *testing.T) {
	if got := convKeyDM("abc"); got == convKeyGroup("abc") {
		t.Fatalf("a direct message and a group sharing an id collide on %q", got)
	}
	if convKeyDM("abc") == "abc" {
		t.Fatal("convKeyDM must not return the bare account, or it could collide with a group id")
	}
}
