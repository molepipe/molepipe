package api

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/mailbox"
)

// mailboxTestServer builds an unlocked api.Server whose onion dialer routes to a
// fixed address (the mailbox httptest server), so the real app-side mailbox code
// (tryMailboxDropoff, mailboxTick) runs against a real mailbox with no Tor.
func mailboxTestServer(t *testing.T, mboxAddr string) (*Server, *identity.Identity) {
	t.Helper()
	store, err := identity.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	s := New(store, &routeOnion{target: func() string { return mboxAddr }})
	if _, err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(nil) })
	s.startSession(id)
	t.Cleanup(s.clearSession)
	return s, id
}

// TestMailboxOfflineFlowEndToEnd exercises the APP-level offline path against a
// real mailbox server: a sender drops a message at an offline recipient's
// mailbox exactly as the outbox does, and the recipient's mailboxTick checks in,
// picks up, gates on the contact, delivers, and deletes. The mailbox client core
// is covered separately (mailbox.TestMailboxClientServerEndToEnd); this locks the
// wiring in internal/api that turns that into "an offline message actually
// arrives".
func TestMailboxOfflineFlowEndToEnd(t *testing.T) {
	mstore, err := mailbox.New(mailbox.Config{Dir: t.TempDir(), Defaults: mailbox.Caps{}})
	if err != nil {
		t.Fatal(err)
	}
	msrv := httptest.NewServer(mailbox.NewServer(mstore).Handler())
	defer msrv.Close()
	mboxAddr := msrv.Listener.Addr().String()
	const box = "recipient-mailbox.onion"
	ctx := context.Background()

	sender, senderID := mailboxTestServer(t, mboxAddr)
	recipient, recipientID := mailboxTestServer(t, mboxAddr)

	// The sender holds the recipient as an accepted contact, with the mailbox
	// address and X25519 key it would have cached from the recipient's profile.
	rdh := recipientID.Keys.DH.Public
	sender.sessMu.Lock()
	rContact := chatstore.Contact{
		Account: recipientID.AccountNumber(), Status: chatstore.StatusAccepted,
		MailboxURL: box, DHPub: rdh[:],
	}
	sender.contacts[recipientID.AccountNumber()] = rContact
	sender.sessMu.Unlock()

	// The recipient holds the sender as an accepted contact (so the pickup gate
	// admits the message) and has this mailbox configured as its own.
	recipient.sessMu.Lock()
	recipient.contacts[senderID.AccountNumber()] = chatstore.Contact{
		Account: senderID.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	recipient.mailboxURL = box
	recipient.sessMu.Unlock()

	// Recipient checks in first (a drop-off for an account that never checked in
	// is refused — that is what stops the box being an open dead-drop).
	recipient.mailboxTick(ctx, recipientID)

	// Sender's direct attempt has "failed"; it falls back to the mailbox exactly
	// as deliverOutboxItem does.
	if !sender.tryMailboxDropoff(ctx, senderID, rContact, "mid-offline-1", "offline hello") {
		t.Fatal("sender could not drop off at the recipient's mailbox")
	}

	// The message is waiting on the server, not yet delivered.
	if items, _ := mstore.Pickup(recipientID.AccountNumber()); len(items) != 1 {
		t.Fatalf("mailbox holds %d blobs before pickup, want 1", len(items))
	}

	// Recipient comes online: pickup -> gate -> deliver -> delete.
	recipient.mailboxTick(ctx, recipientID)

	recipient.sessMu.Lock()
	var got string
	for _, m := range recipient.messages {
		if m.ID == "mid-offline-1" {
			got = m.Text
		}
	}
	recipient.sessMu.Unlock()
	if got != "offline hello" {
		t.Fatalf("recipient did not receive the offline message via the mailbox (got %q)", got)
	}

	// Delivered blobs are deleted from the box.
	if items, _ := mstore.Pickup(recipientID.AccountNumber()); len(items) != 0 {
		t.Fatalf("mailbox still holds %d blobs after delivery, want 0", len(items))
	}
}

// TestMailboxPickupGateRejectsNonContact locks the security property that a
// mailbox pickup is contacts-only: a blob from an account the recipient has NOT
// accepted is neither delivered nor deleted (it waits, in case they accept
// later), so the mailbox can't be used to inject messages from strangers.
func TestMailboxPickupGateRejectsNonContact(t *testing.T) {
	mstore, err := mailbox.New(mailbox.Config{Dir: t.TempDir(), Defaults: mailbox.Caps{}})
	if err != nil {
		t.Fatal(err)
	}
	msrv := httptest.NewServer(mailbox.NewServer(mstore).Handler())
	defer msrv.Close()
	mboxAddr := msrv.Listener.Addr().String()
	const box = "recipient-mailbox.onion"
	ctx := context.Background()

	stranger, strangerID := mailboxTestServer(t, mboxAddr)
	recipient, recipientID := mailboxTestServer(t, mboxAddr)

	// The stranger knows the recipient's mailbox + key, but the recipient has NOT
	// accepted the stranger.
	rdh := recipientID.Keys.DH.Public
	strangerView := chatstore.Contact{
		Account: recipientID.AccountNumber(), Status: chatstore.StatusAccepted,
		MailboxURL: box, DHPub: rdh[:],
	}
	stranger.sessMu.Lock()
	stranger.contacts[recipientID.AccountNumber()] = strangerView
	stranger.sessMu.Unlock()
	recipient.sessMu.Lock()
	recipient.mailboxURL = box
	recipient.sessMu.Unlock()

	recipient.mailboxTick(ctx, recipientID) // check in
	if !stranger.tryMailboxDropoff(ctx, strangerID, strangerView, "mid-stranger", "let me in") {
		t.Fatal("drop-off itself should succeed; the gate is on pickup, not drop-off")
	}

	recipient.mailboxTick(ctx, recipientID) // pickup: must NOT deliver

	recipient.sessMu.Lock()
	n := len(recipient.messages)
	recipient.sessMu.Unlock()
	if n != 0 {
		t.Fatalf("recipient delivered %d messages from a non-contact, want 0", n)
	}
	// The blob is left on the server (not deleted), so it still arrives if the
	// recipient later accepts the sender.
	if items, _ := mstore.Pickup(recipientID.AccountNumber()); len(items) != 1 {
		t.Fatalf("undelivered non-contact blob was dropped from the box (%d left, want 1)", len(items))
	}
}

// TestMailboxImageOfflineFlow: with a mailbox whose operator has opted into
// images (a larger per-blob cap), a direct-failed image is dropped at the
// recipient's box and picked up byte-exact as an image row.
func TestMailboxImageOfflineFlow(t *testing.T) {
	mstore, err := mailbox.New(mailbox.Config{Dir: t.TempDir(), Defaults: mailbox.Caps{MaxMessage: 4 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	msrv := httptest.NewServer(mailbox.NewServer(mstore).Handler())
	defer msrv.Close()
	mboxAddr := msrv.Listener.Addr().String()
	const box = "recipient-mailbox.onion"
	ctx := context.Background()

	sender, senderID := mailboxTestServer(t, mboxAddr)
	recipient, recipientID := mailboxTestServer(t, mboxAddr)

	rdh := recipientID.Keys.DH.Public
	sender.sessMu.Lock()
	sender.contacts[recipientID.AccountNumber()] = chatstore.Contact{
		Account: recipientID.AccountNumber(), Status: chatstore.StatusAccepted,
		MailboxURL: box, DHPub: rdh[:],
	}
	sender.sessMu.Unlock()
	recipient.sessMu.Lock()
	recipient.contacts[senderID.AccountNumber()] = chatstore.Contact{
		Account: senderID.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	recipient.mailboxURL = box
	recipient.sessMu.Unlock()

	recipient.mailboxTick(ctx, recipientID) // check in

	imgID := randomID() // an image's wire id is its attachment id (32-hex)
	img := bytes.Repeat([]byte{0x77}, 100_000)
	if !sender.tryMailboxImageDropoff(senderID, recipientID.AccountNumber(), imgID, "image/png", img) {
		t.Fatal("image drop-off to an image-allowing mailbox failed")
	}
	recipient.mailboxTick(ctx, recipientID) // pickup + deliver

	recipient.sessMu.Lock()
	var row *chatMessage
	for i := range recipient.messages {
		if recipient.messages[i].ID == imgID {
			row = &recipient.messages[i]
		}
	}
	store := recipient.attach
	recipient.sessMu.Unlock()
	if row == nil || row.Kind != chatstore.KindImage || row.Mime != "image/png" {
		t.Fatalf("recipient has no image row (%+v)", row)
	}
	got, err := store.Get(imgID)
	if err != nil || !bytes.Equal(got, img) {
		t.Fatal("recipient's image blob is not byte-exact")
	}
	if items, _ := mstore.Pickup(recipientID.AccountNumber()); len(items) != 0 {
		t.Fatalf("mailbox not emptied after delivery: %d", len(items))
	}
}

// TestMailboxImageRejectedByDefaultCap: a default 32 KiB box refuses an image
// (the operator hasn't opted in), so the drop-off returns false and the image
// waits until the recipient is online rather than being silently lost.
func TestMailboxImageRejectedByDefaultCap(t *testing.T) {
	mstore, err := mailbox.New(mailbox.Config{Dir: t.TempDir(), Defaults: mailbox.Caps{MaxMessage: 32 << 10}})
	if err != nil {
		t.Fatal(err)
	}
	msrv := httptest.NewServer(mailbox.NewServer(mstore).Handler())
	defer msrv.Close()
	mboxAddr := msrv.Listener.Addr().String()
	const box = "recipient-mailbox.onion"
	ctx := context.Background()

	sender, senderID := mailboxTestServer(t, mboxAddr)
	recipient, recipientID := mailboxTestServer(t, mboxAddr)
	rdh := recipientID.Keys.DH.Public
	sender.sessMu.Lock()
	sender.contacts[recipientID.AccountNumber()] = chatstore.Contact{
		Account: recipientID.AccountNumber(), Status: chatstore.StatusAccepted,
		MailboxURL: box, DHPub: rdh[:],
	}
	sender.sessMu.Unlock()
	recipient.sessMu.Lock()
	recipient.mailboxURL = box
	recipient.sessMu.Unlock()
	recipient.mailboxTick(ctx, recipientID) // check in

	img := bytes.Repeat([]byte{0x77}, 100_000) // > 32 KiB
	if sender.tryMailboxImageDropoff(senderID, recipientID.AccountNumber(), randomID(), "image/png", img) {
		t.Fatal("a default-cap mailbox accepted an image it should refuse")
	}
	if items, _ := mstore.Pickup(recipientID.AccountNumber()); len(items) != 0 {
		t.Fatalf("box stored a rejected image: %d", len(items))
	}
}
