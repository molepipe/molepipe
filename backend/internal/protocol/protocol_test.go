package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// fakeDialer ignores the onion name and connects to a local test server.
type fakeDialer struct{ addr string }

func (d fakeDialer) DialOnion(_ context.Context, _ string) (net.Conn, error) {
	return net.Dial("tcp", d.addr)
}

func msgHooks(allow func(string) bool, delivered chan<- [2]string) Hooks {
	return Hooks{
		DisplayName:     func() string { return "" },
		AllowMessage:    allow,
		Deliver:         func(sender, _, text string, _ Reply) { delivered <- [2]string{sender, text} },
		OnFriendRequest: func(string, string, string) error { return nil },
		OnFriendAccept:  func(string, string, string) error { return nil },
	}
}

func serve(t *testing.T, peer *Peer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(ChallengePath, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(peer.Challenge()) })
	mux.HandleFunc(ProfilePath, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(peer.ProfileCard()) })
	mux.HandleFunc(MessagePath, func(w http.ResponseWriter, r *http.Request) {
		var e Envelope
		_ = json.NewDecoder(r.Body).Decode(&e)
		if err := peer.Receive(e); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	mux.HandleFunc(ContactProfilePath, func(w http.ResponseWriter, r *http.Request) {
		var req ContactProfileRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		cp, err := peer.ServeContactProfile(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(cp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestSendReceiveRoundTrip(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	delivered := make(chan [2]string, 1)
	peer := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, delivered))
	srv := serve(t, peer)

	if err := SendMessage(context.Background(), fakeDialer{srv.Listener.Addr().String()}, alice, bob.AccountNumber(), "mid-1", "hello bob"); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-delivered:
		if got[0] != alice.AccountNumber() || got[1] != "hello bob" {
			t.Errorf("delivered %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not delivered")
	}
}

func TestReceiveRejectsNonContact(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	peer := NewPeer(bob, msgHooks(func(string) bool { return false }, make(chan [2]string, 1)))
	srv := serve(t, peer)
	if err := SendMessage(context.Background(), fakeDialer{srv.Listener.Addr().String()}, alice, bob.AccountNumber(), "mid-1", "hi"); err == nil {
		t.Fatal("expected rejection of non-contact sender")
	}
}

// Mallory claims Sender=alice but signs with her own key: rejected at sig check,
// before the status hook is ever consulted.
func TestReceiveRejectsForgedSender(t *testing.T) {
	alice, _ := identity.New()
	mallory, _ := identity.New()
	bob, _ := identity.New()
	allowCalled := false
	peer := NewPeer(bob, Hooks{
		DisplayName:  func() string { return "" },
		AllowMessage: func(string) bool { allowCalled = true; return true },
		Deliver:      func(string, string, string, Reply) {},
	})
	ch := peer.Challenge()
	mdh := mallory.Keys.DH.Public
	forged := Envelope{
		Sender: alice.AccountNumber(), SenderDHPub: mdh[:], Nonce: ch.Nonce,
		Sig: ed25519.Sign(mallory.Keys.Signing.Private,
			signBlob([]byte(sigContext), []byte("message"), ch.Nonce, []byte(bob.AccountNumber()), mdh[:])),
		Box: []byte("x"),
	}
	if err := peer.Receive(forged); err == nil {
		t.Fatal("forged sender accepted")
	}
	if allowCalled {
		t.Fatal("status hook ran before signature verification")
	}
}

func TestReceiveRejectsReplayedNonce(t *testing.T) {
	alice, _ := identity.New()
	bob, _ := identity.New()
	peer := NewPeer(bob, msgHooks(func(a string) bool { return a == alice.AccountNumber() }, make(chan [2]string, 2)))
	ch := peer.Challenge()
	env := buildEnvelope(alice, bob, ch, "first")
	if err := peer.Receive(env); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := peer.Receive(env); err == nil {
		t.Fatal("replayed nonce accepted")
	}
}

// A fetched profile must verify against the account's key and match it. The
// public card carries the avatar hash (for add-time recognition) but NOT the
// mailbox — that moved to the gated contact-profile (see TestContactProfileGate).
func TestProfileRoundTrip(t *testing.T) {
	bob, _ := identity.New()
	avatar := "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" // 64-char sha256-shaped hex
	peer := NewPeer(bob, Hooks{
		DisplayName: func() string { return "Bob B" },
		AvatarHash:  func() string { return avatar },
	})
	srv := serve(t, peer)

	pr, err := FetchProfile(context.Background(), fakeDialer{srv.Listener.Addr().String()}, bob.AccountNumber())
	if err != nil {
		t.Fatal(err)
	}
	if pr.Account != bob.AccountNumber() || pr.DisplayName != "Bob B" || pr.AvatarHash != avatar {
		t.Errorf("profile = %+v", pr)
	}
	// The mailbox is not even a field on the public card any more — its absence is
	// enforced at compile time, so there is nothing to assert here at runtime.
	if [32]byte(pr.DHPub) != bob.Keys.DH.Public {
		t.Error("profile dh_pub does not match bob's X25519 key")
	}

	// avatar_hash and dh_pub are inside the signature: verifying the served card
	// with a tampered avatar must fail (a relay can't swap in its own avatar or
	// its own DH key).
	card := peer.ProfileCard()
	ed, _ := identity.AccountNumberFromString(bob.AccountNumber())
	tampered := signBlob([]byte(sigContext), []byte("profile"), []byte(card.Account), []byte(card.DisplayName), card.DHPub, []byte("deadbeef"))
	if ed25519.Verify(ed, tampered, card.Sig) {
		t.Error("signature verified against a tampered avatar_hash")
	}
}

// The gated contact-profile discloses the mailbox ONLY to a caller the hook
// considers an accepted contact; a stranger gets "" (a uniform non-oracle), and
// a replayed request is rejected (the nonce is single-use).
func TestContactProfileGate(t *testing.T) {
	bob, _ := identity.New()
	alice, _ := identity.New() // an accepted contact
	carol, _ := identity.New() // a stranger
	mailbox := "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
	peer := NewPeer(bob, Hooks{
		DisplayName: func() string { return "Bob B" },
		ContactMailbox: func(sender string) string {
			if sender == alice.AccountNumber() {
				return mailbox
			}
			return ""
		},
	})
	srv := serve(t, peer)
	dialer := fakeDialer{srv.Listener.Addr().String()}

	cp, err := FetchContactProfile(context.Background(), dialer, alice, bob.AccountNumber())
	if err != nil {
		t.Fatal(err)
	}
	if cp.MailboxURL != mailbox {
		t.Errorf("accepted contact got mailbox %q, want %q", cp.MailboxURL, mailbox)
	}

	cp2, err := FetchContactProfile(context.Background(), dialer, carol, bob.AccountNumber())
	if err != nil {
		t.Fatal(err)
	}
	if cp2.MailboxURL != "" {
		t.Errorf("stranger got mailbox %q, want empty", cp2.MailboxURL)
	}

	// A captured request must not be replayable to re-pull the mailbox: the nonce
	// is consumed on first use.
	ch := peer.Challenge()
	sig := ed25519.Sign(alice.Keys.Signing.Private,
		signBlob([]byte(sigContext), []byte("contact-profile"), ch.Nonce, []byte(bob.AccountNumber())))
	req := ContactProfileRequest{From: alice.AccountNumber(), Nonce: ch.Nonce, Sig: sig}
	if _, err := peer.ServeContactProfile(req); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	if _, err := peer.ServeContactProfile(req); err == nil {
		t.Error("replayed contact-profile nonce accepted")
	}
}

// TestAvatarUngatedMailboxGated pins BOTH halves of the ProfileCard privacy
// change in one place: a STRANGER (non-contact) who holds bob's account can read
// his avatar_hash from the signed card and pull the avatar bytes from the ungated
// AvatarPath — that is deliberate, a face at add-time — yet the same stranger
// gets "" for the mailbox from the gated contact-profile. Avatar out in the open,
// mailbox behind the accepted-contact gate.
func TestAvatarUngatedMailboxGated(t *testing.T) {
	bob, _ := identity.New()
	carol, _ := identity.New() // a stranger to bob
	avatarBytes := []byte("\xFF\xD8\xFF\xE0 pretend jpeg avatar bytes")
	sum := sha256.Sum256(avatarBytes)
	avatarHash := hex.EncodeToString(sum[:])

	peer := NewPeer(bob, Hooks{
		DisplayName: func() string { return "Bob B" },
		AvatarHash:  func() string { return avatarHash },
		// Gate as the real hook does: a stranger is never an accepted contact, so
		// the mailbox is withheld no matter what bob's own mailbox is.
		ContactMailbox: func(string) string { return "" },
	})

	mux := http.NewServeMux()
	mux.HandleFunc(ChallengePath, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(peer.Challenge()) })
	mux.HandleFunc(ProfilePath, func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(peer.ProfileCard()) })
	mux.HandleFunc(ContactProfilePath, func(w http.ResponseWriter, r *http.Request) {
		var req ContactProfileRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		cp, err := peer.ServeContactProfile(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(cp)
	})
	// Minimal stand-in for handleP2PAvatar: serve the bytes for the advertised hash.
	mux.HandleFunc(AvatarPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("h") != avatarHash {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(avatarBytes)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	dialer := fakeDialer{srv.Listener.Addr().String()}

	// The card carol pulls carries the avatar hash (verified against bob's key).
	pr, err := FetchProfile(context.Background(), dialer, bob.AccountNumber())
	if err != nil {
		t.Fatal(err)
	}
	if pr.AvatarHash != avatarHash {
		t.Fatalf("card avatar_hash = %q, want %q", pr.AvatarHash, avatarHash)
	}
	// Ungated: the stranger fetches the bytes and they verify against the hash.
	got, err := FetchAvatar(context.Background(), dialer, bob.AccountNumber(), avatarHash)
	if err != nil {
		t.Fatalf("stranger could not fetch ungated avatar: %v", err)
	}
	if string(got) != string(avatarBytes) {
		t.Fatal("fetched avatar bytes differ")
	}
	// Gated: the same stranger gets no mailbox.
	cp, err := FetchContactProfile(context.Background(), dialer, carol, bob.AccountNumber())
	if err != nil {
		t.Fatal(err)
	}
	if cp.MailboxURL != "" {
		t.Errorf("stranger leaked mailbox %q via gated endpoint", cp.MailboxURL)
	}
}

// FetchAvatar must reject bytes that do not hash to the requested hash — a relay
// that swaps the image is caught, because the hash came from bob's signed card.
func TestFetchAvatarRejectsTampered(t *testing.T) {
	bob, _ := identity.New()
	wantHash := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("real")); return s[:] }())
	mux := http.NewServeMux()
	mux.HandleFunc(AvatarPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("TAMPERED bytes, not the real avatar")) // hashes to something else
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if _, err := FetchAvatar(context.Background(), fakeDialer{srv.Listener.Addr().String()}, bob.AccountNumber(), wantHash); err == nil {
		t.Fatal("accepted avatar bytes that do not match the hash")
	}
}

func buildEnvelope(sender, recipient *identity.Identity, ch Challenge, text string) Envelope {
	var theirDH [32]byte
	copy(theirDH[:], ch.DHPub)
	shared, _ := crypto.SharedSecret(sender.Keys.DH.Private, theirDH)
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(sender.AccountNumber(), recipient.AccountNumber()))
	box, _ := crypto.SealMessage(key, []byte(text), aad(sender.AccountNumber(), recipient.AccountNumber()))
	dh := sender.Keys.DH.Public
	sig := ed25519.Sign(sender.Keys.Signing.Private,
		signBlob([]byte(sigContext), []byte("message"), ch.Nonce, []byte(recipient.AccountNumber()), dh[:]))
	return Envelope{Sender: sender.AccountNumber(), SenderDHPub: dh[:], Nonce: ch.Nonce, Sig: sig, Box: box}
}
