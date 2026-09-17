package protocol

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

func TestGroupMessageSignAndVerify(t *testing.T) {
	author, _ := identity.New()
	gm, err := NewGroupMessage(author, "grp-1", "hello group", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !gm.Verify() {
		t.Fatal("freshly signed group message did not verify")
	}
	// Tampering with the text breaks the signature.
	bad := gm
	bad.Text = "evil edit"
	if bad.Verify() {
		t.Fatal("a modified message still verified")
	}
	// Reattributing to someone else fails — the signature only verifies under the
	// real author's key.
	other, _ := identity.New()
	reattributed := gm
	reattributed.Author = other.AccountNumber()
	if reattributed.Verify() {
		t.Fatal("a reattributed message still verified")
	}
}

// TestGroupReplySignAndCarry covers group reply-with-context: the reply id is
// inside the signed blob (so a courier can't repoint the quote), it survives the
// seal/open wire round-trip, and — crucially for members who predate the field —
// a plain (non-reply) text message's signed bytes are byte-for-byte unchanged.
func TestGroupReplySignAndCarry(t *testing.T) {
	author, _ := identity.New()
	at := time.Now()

	reply, err := NewGroupMessage(author, "grp-1", "answering you", at, "quoted-msg-id")
	if err != nil {
		t.Fatal(err)
	}
	if reply.ReplyID != "quoted-msg-id" || !reply.Verify() {
		t.Fatalf("reply did not sign/verify: %+v", reply)
	}
	// Repointing the quote to a different message breaks the signature — the id is
	// signed, so a forwarding courier cannot rewrite what was replied to.
	repointed := reply
	repointed.ReplyID = "some-other-id"
	if repointed.Verify() {
		t.Fatal("a repointed reply id still verified")
	}
	// The reply id survives the seal/open round trip.
	recipient, _ := identity.New()
	env, err := SealGroupMessage(author, reply, recipient.AccountNumber(), recipient.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenGroupEnvelope(recipient, env)
	if err != nil {
		t.Fatalf("open reply: %v", err)
	}
	if got.ReplyID != "quoted-msg-id" || !got.Verify() {
		t.Fatalf("reply id lost across the wire: %+v", got)
	}

	// Backward-compat invariant: a NON-reply message signs over the same bytes it
	// did before ReplyID existed — an empty ReplyID must not enter the blob, or a
	// member who predates the field would compute a different blob and reject it.
	plain, _ := NewGroupMessage(author, "grp-1", "answering you", at)
	if plain.ReplyID != "" {
		t.Fatal("a plain message should carry no reply id")
	}
	if string(plain.signingBlob()) == string(reply.signingBlob()) {
		t.Fatal("reply and non-reply produced the same signed blob")
	}
	// And a reply and a plain message with the same text/time differ ONLY by the
	// reply domain — proving the plain blob is untouched by the feature's presence.
	var refPlain GroupMessage = GroupMessage{GroupID: "grp-1", Author: author.AccountNumber(), At: at.UTC(), Text: "answering you"}
	if string(refPlain.signingBlob()) != string(plain.signingBlob()) {
		t.Fatal("non-reply signed bytes changed after adding the reply field")
	}
}

func TestGroupEnvelopeRoundTrip(t *testing.T) {
	author, _ := identity.New()
	recipient, _ := identity.New()
	gm, _ := NewGroupMessage(author, "grp-1", "sealed hello", time.Now())

	env, err := SealGroupMessage(author, gm, recipient.AccountNumber(), recipient.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenGroupEnvelope(recipient, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Text != "sealed hello" || got.Author != author.AccountNumber() {
		t.Fatalf("round trip changed content: %+v", got)
	}

	// Wrong recipient is rejected.
	stranger, _ := identity.New()
	if _, err := OpenGroupEnvelope(stranger, env); err == nil {
		t.Fatal("an envelope opened for the wrong recipient")
	}
}

// TestGroupResealPreservesAuthor is the property the whole "everyone relays"
// model rests on: a member who is NOT the author can re-seal the message for
// another member, and that member still sees it as authored by the original
// sender, verified.
func TestGroupResealPreservesAuthor(t *testing.T) {
	author, _ := identity.New()
	forwarder, _ := identity.New()
	finalRecipient, _ := identity.New()

	gm, _ := NewGroupMessage(author, "grp-1", "relayed hello", time.Now())

	// The forwarder (a different identity) re-seals the author's signed message
	// for a third member, using the forwarder's own key as the carrier.
	env, err := SealGroupMessage(forwarder, gm, finalRecipient.AccountNumber(), finalRecipient.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenGroupEnvelope(finalRecipient, env)
	if err != nil {
		t.Fatalf("open re-sealed: %v", err)
	}
	if got.Author != author.AccountNumber() {
		t.Fatalf("re-seal lost authorship: got %s want %s", got.Author, author.AccountNumber())
	}
	if !got.Verify() || got.Text != "relayed hello" {
		t.Fatal("re-sealed message failed author verification")
	}
}

// TestGroupMessageAtMaxLength: a message at exactly the plaintext ceiling must
// survive the seal/open round trip — the JSON wrapper and base64 signature push
// the box past maxPlaintext, so the open-side limit has to be on the text, not
// the wrapper, or the effective group ceiling would silently be lower than 1:1's.
func TestGroupMessageAtMaxLength(t *testing.T) {
	author, _ := identity.New()
	recipient, _ := identity.New()
	big := make([]byte, 16*1024) // == maxPlaintext
	for i := range big {
		big[i] = 'a'
	}
	gm, err := NewGroupMessage(author, "grp-1", string(big), time.Now())
	if err != nil {
		t.Fatalf("seal at max length: %v", err)
	}
	env, err := SealGroupMessage(author, gm, recipient.AccountNumber(), recipient.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenGroupEnvelope(recipient, env)
	if err != nil {
		t.Fatalf("a max-length group message was rejected on open: %v", err)
	}
	if len(got.Text) != 16*1024 {
		t.Fatalf("max-length text corrupted: got %d bytes", len(got.Text))
	}
}

func TestGroupEnvelopeTamperedBoxRejected(t *testing.T) {
	author, _ := identity.New()
	recipient, _ := identity.New()
	gm, _ := NewGroupMessage(author, "grp-1", "hello", time.Now())
	env, _ := SealGroupMessage(author, gm, recipient.AccountNumber(), recipient.Keys.DH.Public)
	if len(env.Box) > 0 {
		env.Box[len(env.Box)-1] ^= 0xff
	}
	if _, err := OpenGroupEnvelope(recipient, env); err == nil {
		t.Fatal("a tampered box was accepted")
	}
}
