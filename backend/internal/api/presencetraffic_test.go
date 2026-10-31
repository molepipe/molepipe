package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/mailbox"
)

// gatedOnion is dialable only once the test says so, so the loop gate can be
// driven both ways. Everything else behaves like routeOnion.
type gatedOnion struct {
	routeOnion
	dialable atomic.Bool
}

func (o *gatedOnion) Dialable() bool { return o.dialable.Load() }

func newGatedOnion() *gatedOnion {
	return &gatedOnion{routeOnion: routeOnion{target: func() string { return "127.0.0.1:1" }}}
}

// acceptedContact registers an accepted contact sitting at offline, which is
// what every promotion test below starts from.
func acceptedContact(t *testing.T, s *Server) string {
	t.Helper()
	peer, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusAccepted}
	if s.presence == nil {
		s.presence = map[string]string{}
	}
	s.presence[acct] = presenceOffline
	return acct
}

// --- the loop gate (replaces the fixed start delays) ---

// The whole point of the gate: a loop must not burn its first attempt on a
// dialer that cannot carry it, and must not idle once the dialer works. The
// interval here is an hour, so the second half can only pass via the immediate
// first tick — not by the timer coming round.
func TestRunLoopWaitsForDialableThenTicksImmediately(t *testing.T) {
	o := newGatedOnion()
	s := newServerOnOnion(t, o)

	ticks := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.runLoop(ctx, time.Hour, func() { ticks <- struct{}{} })

	select {
	case <-ticks:
		t.Fatal("runLoop ticked while the onion was not dialable")
	case <-time.After(300 * time.Millisecond):
	}

	o.dialable.Store(true)

	select {
	case <-ticks:
	case <-time.After(5 * time.Second):
		t.Fatal("runLoop never ticked after the onion became dialable")
	}
}

// A session that is torn down while still bootstrapping must not leave a loop
// parked in the gate.
func TestRunLoopStopsWhenCancelledBeforeDialable(t *testing.T) {
	s := newServerOnOnion(t, newGatedOnion())

	var ticked atomic.Bool
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		s.runLoop(ctx, time.Hour, func() { ticked.Store(true) })
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runLoop did not return after its context was cancelled")
	}
	if ticked.Load() {
		t.Error("runLoop ticked despite being cancelled before the onion was dialable")
	}
}

// --- Flaw B: authenticated DIRECT inbound traffic proves reachability ---

// Someone who dialed our onion and passed signature + nonce verification is
// reachable right now, which is better evidence than the probe sweep's and
// arrives up to a sweep interval earlier.
func TestDirectInboundMessagePromotesPresence(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	acct := acceptedContact(t, s)

	if !s.hookAllowMessage(acct) {
		t.Fatal("an accepted contact was refused by the message gate")
	}
	if got := presenceOf(s, acct); got != presenceOnline {
		t.Errorf("presence after direct inbound = %q, want %q", got, presenceOnline)
	}
}

// Promotion hangs off the ALLOWED path only. A pending_in sender (we have not
// accepted them) is refused, and refused traffic must not move a dot.
func TestRefusedInboundDoesNotPromotePresence(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	acct := acceptedContact(t, s)

	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{Account: acct, Status: chatstore.StatusPendingIn}
	s.sessMu.Unlock()

	if s.hookAllowMessage(acct) {
		t.Fatal("a pending_in sender cleared the message gate")
	}
	if got := presenceOf(s, acct); got != presenceOffline {
		t.Errorf("presence after refused inbound = %q, want it left at %q", got, presenceOffline)
	}
}

// The reaction hook runs after the protocol layer verified the signature and
// consumed the nonce, so the evidence is good even when the message they
// reacted to is one we no longer hold.
func TestDirectReactionPromotesPresenceWithoutTheMessage(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	acct := acceptedContact(t, s)

	if err := s.hookOnReaction(acct, "no-such-message", "\U0001F44D", false); err != nil {
		t.Fatalf("hookOnReaction: %v", err)
	}
	if got := presenceOf(s, acct); got != presenceOnline {
		t.Errorf("presence after direct reaction = %q, want %q", got, presenceOnline)
	}
}

func TestDirectDeleteRequestPromotesPresence(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	acct := acceptedContact(t, s)

	if err := s.hookOnDeleteMessage(acct, "no-such-message"); err != nil {
		t.Fatalf("hookOnDeleteMessage: %v", err)
	}
	if got := presenceOf(s, acct); got != presenceOnline {
		t.Errorf("presence after direct delete = %q, want %q", got, presenceOnline)
	}
}

// The seam that makes the promotion correct. Indirectly delivered traffic — the
// mailbox tick and handleRelayDeliver — clears the SAME contacts gate, but via
// allowMessageLocked rather than the hook, precisely because a stored blob
// proves only that the sender was online when they dropped it off, perhaps
// hours ago. If this ever starts promoting, a peer who has been offline all day
// shows up green the moment we collect their mail.
func TestIndirectDeliveryGateLeavesPresenceAlone(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	acct := acceptedContact(t, s)

	s.sessMu.Lock()
	allowed := s.allowMessageLocked(acct)
	s.sessMu.Unlock()

	if !allowed {
		t.Fatal("an accepted contact was refused by the indirect-delivery gate")
	}
	if got := presenceOf(s, acct); got != presenceOffline {
		t.Errorf("presence after a mailbox/relay gate check = %q, want it left at %q", got, presenceOffline)
	}
}

// Inbound traffic refreshes the stickiness window too, so a contact who is
// actively talking to us stops flickering offline on one failed probe.
func TestDirectInboundRefreshesTheStickinessWindow(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")
	acct := acceptedContact(t, s)

	stale := time.Now().Add(-helloStickiness - time.Second)
	s.sessMu.Lock()
	s.helloAt = map[string]time.Time{acct: stale}
	s.sessMu.Unlock()

	s.hookAllowMessage(acct)

	s.sessMu.Lock()
	got := s.helloAt[acct]
	s.sessMu.Unlock()
	if !got.After(stale) {
		t.Errorf("helloAt not refreshed by direct inbound traffic (still %v)", got)
	}
}

// --- Flaw C: a completed direct send proves the RECIPIENT is reachable ---

// Flaw C at its real call site: an ordinary send that completes over a direct
// dial leaves the recipient marked online, with no probe sweep involved.
// sendV2 has no internal mailbox fallback, so reaching markDelivered by this
// route means the recipient answered a direct dial.
func TestASuccessfulDirectSendMarksTheRecipientOnline(t *testing.T) {
	sA, _, _, accB, tokA, _ := friendedPair(t)

	// Start from offline, so a pass can only come from the send itself.
	sA.sessMu.Lock()
	sA.presence = map[string]string{accB: presenceOffline}
	sA.sessMu.Unlock()

	r := sA.do(t, "POST", "/api/messages", `{"to":"`+accB+`","text":"direct"}`, authHdr(sA, tokA))
	if r.Code != http.StatusOK {
		t.Fatalf("send: %d (%s)", r.Code, r.Body)
	}
	id, _ := decode(t, r.Body)["id"].(string)
	awaitDelivered(t, sA, id)

	if got := presenceOf(sA, accB); got != presenceOnline {
		t.Errorf("presence after a delivered direct send = %q, want %q", got, presenceOnline)
	}
	// presence alone cannot discriminate here: these two servers can reach each
	// other, so the probe sweep would mark accB online by itself. helloAt is the
	// sharper witness — the sweep only ever writes presence, and the only writer
	// of helloAt is touchPeerPresenceLocked. A timestamp here therefore means the
	// send is what promoted them.
	sA.sessMu.Lock()
	at := sA.helloAt[accB]
	sA.sessMu.Unlock()
	if at.IsZero() {
		t.Error("a delivered direct send did not promote the recipient (helloAt unset); presence above may just be the probe sweep")
	}
}

// The deterministic half of the same property, with no sweep in play: the
// recipient is promoted under markDelivered's own lock when the delivery was
// direct, and left alone when it was not.
func TestMarkDeliveredPromotesOnlyOnADirectSend(t *testing.T) {
	s, _ := mailboxTestServer(t, "127.0.0.1:1")

	direct := acceptedContact(t, s)
	s.markDelivered("m1", direct)
	if got := presenceOf(s, direct); got != presenceOnline {
		t.Errorf("presence after a direct send = %q, want %q", got, presenceOnline)
	}

	viaBox := acceptedContact(t, s)
	s.markDelivered("m2", "")
	if got := presenceOf(s, viaBox); got != presenceOffline {
		t.Errorf("presence after a mailbox drop = %q, want it left at %q", got, presenceOffline)
	}
}

// The other half of the same call site, and the one worth guarding: a message
// that only got as far as the recipient's mailbox must NOT mark them online. We
// handed it to a third party and learned nothing about whether they can be
// reached — if this ever flips, a contact who has been offline all week shows
// up green the moment we post to their box.
func TestAMailboxDropDoesNotMarkTheRecipientOnline(t *testing.T) {
	mstore, err := mailbox.New(mailbox.Config{Dir: t.TempDir(), Defaults: mailbox.Caps{}})
	if err != nil {
		t.Fatal(err)
	}
	msrv := httptest.NewServer(mailbox.NewServer(mstore).Handler())
	defer msrv.Close()
	mboxAddr := msrv.Listener.Addr().String()
	const box = "recipient-mailbox.onion"
	ctx := context.Background()

	// Every dial from these servers lands on the mailbox, so the direct send
	// cannot succeed — exactly the shape in which deliverOutboxItem falls back.
	sender, senderID := mailboxTestServer(t, mboxAddr)
	recipient, recipientID := mailboxTestServer(t, mboxAddr)
	accB := recipientID.AccountNumber()

	rdh := recipientID.Keys.DH.Public
	rContact := chatstore.Contact{
		Account: accB, Status: chatstore.StatusAccepted,
		MailboxURL: box, DHPub: rdh[:],
	}
	sender.sessMu.Lock()
	sender.contacts[accB] = rContact
	sender.presence = map[string]string{accB: presenceOffline}
	sender.sessMu.Unlock()

	recipient.sessMu.Lock()
	recipient.contacts[senderID.AccountNumber()] = chatstore.Contact{
		Account: senderID.AccountNumber(), Status: chatstore.StatusAccepted,
	}
	recipient.mailboxURL = box
	recipient.sessMu.Unlock()
	recipient.mailboxTick(ctx, recipientID) // check in: an unvisited box refuses drops

	it := chatstore.OutboxItem{ID: "mid-mailbox-presence", To: accB, Text: "via the box", QueuedAt: time.Now()}
	sender.sessMu.Lock()
	sender.outbox[it.ID] = it
	sender.sessMu.Unlock()

	sender.deliverOutboxItem(ctx, senderID, it)

	if items, _ := mstore.Pickup(accB); len(items) != 1 {
		t.Fatalf("mailbox holds %d blobs, want 1 — the drop-off path did not run, so this proves nothing", len(items))
	}
	if got := presenceOf(sender, accB); got != presenceOffline {
		t.Errorf("presence after a mailbox drop = %q, want it left at %q", got, presenceOffline)
	}
}
