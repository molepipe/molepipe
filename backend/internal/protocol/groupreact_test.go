package protocol

import (
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// TestGroupReactionSignAndCarry covers the group-reaction event: every field that
// matters is inside the signed blob (so a courier can rewrite none of them), the
// event survives the seal/open wire round trip — including re-sealed by a THIRD
// party, the property the everyone-relays gossip rests on — and a remove event
// carries its bit intact.
func TestGroupReactionSignAndCarry(t *testing.T) {
	by, _ := identity.New()
	at := time.Now()

	gr, err := NewGroupReaction(by, "grp-1", "target-msg-id", "👍", false, at)
	if err != nil {
		t.Fatal(err)
	}
	if !gr.Verify() {
		t.Fatal("a freshly signed reaction did not verify")
	}
	// Each signed component, if rewritten by a courier, breaks the signature.
	for name, mut := range map[string]func(g *GroupReaction){
		"target": func(g *GroupReaction) { g.Target = "other-target" },
		"emoji":  func(g *GroupReaction) { g.Emoji = "❤️" },
		"remove": func(g *GroupReaction) { g.Remove = true },
		"time":   func(g *GroupReaction) { g.AtNanos++ },
		"group":  func(g *GroupReaction) { g.GroupID = "grp-2" },
	} {
		bad := gr
		mut(&bad)
		if bad.Verify() {
			t.Fatalf("a reaction with a rewritten %s still verified", name)
		}
	}
	// Reattributing to someone else fails — the signature only verifies under By's key.
	other, _ := identity.New()
	reattr := gr
	reattr.By = other.AccountNumber()
	if reattr.Verify() {
		t.Fatal("a reattributed reaction still verified")
	}

	// Seal/open round trip via a THIRD-party carrier (not the reactor): the recipient
	// still sees it as authentically from By, verified.
	recipient, _ := identity.New()
	carrier, _ := identity.New()
	env, err := SealGroupReaction(carrier, gr, recipient.AccountNumber(), recipient.Keys.DH.Public)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenGroupReactionEnvelope(recipient, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.By != by.AccountNumber() || got.Target != "target-msg-id" || got.Emoji != "👍" ||
		got.AtNanos != at.UTC().UnixNano() || got.Remove || !got.Verify() {
		t.Fatalf("round trip changed the reaction: %+v", got)
	}
	// Wrong recipient is rejected.
	stranger, _ := identity.New()
	if _, err := OpenGroupReactionEnvelope(stranger, env); err == nil {
		t.Fatal("an envelope opened for the wrong recipient")
	}

	// A remove event carries its bit across the wire and verifies.
	rm, _ := NewGroupReaction(by, "grp-1", "target-msg-id", "👍", true, at.Add(time.Second))
	renv, _ := SealGroupReaction(by, rm, recipient.AccountNumber(), recipient.Keys.DH.Public)
	gotRm, err := OpenGroupReactionEnvelope(recipient, renv)
	if err != nil || !gotRm.Remove || !gotRm.Verify() {
		t.Fatalf("remove event lost across the wire: %+v err=%v", gotRm, err)
	}
}
