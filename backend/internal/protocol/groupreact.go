package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// groupReactContext is the distinct signing label for a group reaction event, so
// its signed bytes can never be replayed as a group message (or a 1:1 reaction,
// which is nonce-bound instead) and vice versa.
const groupReactContext = "group-reaction"

// GroupReaction is one member's add-or-remove of one emoji on one group message,
// signed by the reactor (By) over the content. Like GroupMessage it is
// self-authenticating: any member holding it can re-seal it for another member
// and forward it, and that member still verifies it as authentically from By — so
// the same "everyone relays / everyone catches you up" gossip that carries
// messages carries reactions, with no live challenge nonce (a courier isn't the
// recipient, so the 1:1 nonce model can't apply). Convergence is per
// (Target, Emoji, By): By is the SOLE authorized writer of that key, so keeping
// the highest AtNanos By signed totally orders their own add/remove events. Remove
// and AtNanos are inside the signed blob so a courier can rewrite neither — it
// can't turn a stale add into a fresh one, nor flip an add to a remove.
type GroupReaction struct {
	GroupID string
	Target  string // GroupMessageID of the reacted-to message
	Emoji   string
	By      string // reactor's account (== the verifying key; not covered by the sig, like GroupMessage.Author)
	Remove  bool
	AtNanos int64 // unix-nanos of the event; the LWW clock for this reactor's key
	Sig     []byte
}

func (gr GroupReaction) signingBlob() []byte {
	var rb byte
	if gr.Remove {
		rb = 1
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(gr.AtNanos))
	return signBlob(sigContextFor(protoVerCurrent), []byte(groupReactContext), []byte(gr.GroupID),
		[]byte(gr.Target), []byte(gr.Emoji), ts[:], []byte{rb})
}

// Verify reports whether By's signature is valid. The caller still decides whether
// By and the carrier belong to the group — the signature proves who reacted, not
// that they are a member.
func (gr GroupReaction) Verify() bool {
	byEd, err := identity.AccountNumberFromString(gr.By)
	if err != nil {
		return false
	}
	return ed25519.Verify(byEd, gr.signingBlob(), gr.Sig)
}

// NewGroupReaction builds and signs a reaction event authored by id.
func NewGroupReaction(id *identity.Identity, groupID, target, emoji string, remove bool, at time.Time) (GroupReaction, error) {
	if groupID == "" || target == "" {
		return GroupReaction{}, fmt.Errorf("missing group or target")
	}
	if len(emoji) == 0 || len(emoji) > maxReactionEmojiBytes {
		return GroupReaction{}, fmt.Errorf("bad reaction")
	}
	gr := GroupReaction{
		GroupID: groupID, Target: target, Emoji: emoji,
		By: id.AccountNumber(), Remove: remove, AtNanos: at.UTC().UnixNano(),
	}
	gr.Sig = ed25519.Sign(id.Keys.Signing.Private, gr.signingBlob())
	return gr, nil
}

// GroupReactionEnvelope carries a signed GroupReaction to one member, encrypted
// under the directional key between the CARRIER (author or any forwarding member)
// and the recipient — exactly like GroupEnvelope, so a hop leaks nothing about the
// group, the reactor, or the target to anyone but the recipient.
type GroupReactionEnvelope struct {
	Recipient    string `json:"recipient"`
	Carrier      string `json:"carrier"`
	CarrierDHPub []byte `json:"carrier_dh_pub"`
	Box          []byte `json:"box"`
}

// groupReactWire is the exact serialized form sealed inside the Box.
type groupReactWire struct {
	GroupID string `json:"g"`
	Target  string `json:"tg"`
	Emoji   string `json:"e"`
	By      string `json:"b"`
	Remove  bool   `json:"rm,omitempty"`
	AtNanos int64  `json:"t"`
	Sig     []byte `json:"s"`
}

// SealGroupReaction encrypts a signed reaction for one recipient, from carrier's
// identity (author when first sending, any relaying member when forwarding).
func SealGroupReaction(carrier *identity.Identity, gr GroupReaction, recipient string, recipientDH [32]byte) (GroupReactionEnvelope, error) {
	if _, err := identity.AccountNumberFromString(recipient); err != nil {
		return GroupReactionEnvelope{}, fmt.Errorf("bad recipient: %w", err)
	}
	if len(gr.Emoji) == 0 || len(gr.Emoji) > maxReactionEmojiBytes {
		return GroupReactionEnvelope{}, fmt.Errorf("bad reaction")
	}
	carrierAcct := carrier.AccountNumber()
	wire, err := json.Marshal(groupReactWire{
		GroupID: gr.GroupID, Target: gr.Target, Emoji: gr.Emoji, By: gr.By,
		Remove: gr.Remove, AtNanos: gr.AtNanos, Sig: gr.Sig,
	})
	if err != nil {
		return GroupReactionEnvelope{}, err
	}
	shared, err := crypto.SharedSecret(carrier.Keys.DH.Private, recipientDH)
	if err != nil {
		return GroupReactionEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(carrierAcct, recipient))
	box, err := crypto.SealMessage(key, wire, aad(carrierAcct, recipient))
	if err != nil {
		return GroupReactionEnvelope{}, err
	}
	dh := carrier.Keys.DH.Public
	return GroupReactionEnvelope{Recipient: recipient, Carrier: carrierAcct, CarrierDHPub: dh[:], Box: box}, nil
}

// OpenGroupReactionEnvelope decrypts an envelope addressed to id and returns the
// inner reaction, having verified By's signature. It does NOT check membership —
// the caller decides whether By (and the carrier) belong to the group.
func OpenGroupReactionEnvelope(id *identity.Identity, env GroupReactionEnvelope) (GroupReaction, error) {
	if env.Recipient != id.AccountNumber() {
		return GroupReaction{}, fmt.Errorf("recipient mismatch")
	}
	if _, err := identity.AccountNumberFromString(env.Carrier); err != nil {
		return GroupReaction{}, fmt.Errorf("bad carrier account: %w", err)
	}
	if len(env.CarrierDHPub) != 32 {
		return GroupReaction{}, fmt.Errorf("bad carrier dh key length")
	}
	var carrierDH [32]byte
	copy(carrierDH[:], env.CarrierDHPub)
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, carrierDH)
	if err != nil {
		return GroupReaction{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(env.Carrier, id.AccountNumber()))
	pt, err := crypto.OpenMessage(key, env.Box, aad(env.Carrier, id.AccountNumber()))
	if err != nil {
		return GroupReaction{}, err
	}
	if len(pt) > 4*maxPlaintext {
		return GroupReaction{}, fmt.Errorf("reaction too large")
	}
	var w groupReactWire
	if err := json.Unmarshal(pt, &w); err != nil {
		return GroupReaction{}, fmt.Errorf("bad group reaction: %w", err)
	}
	gr := GroupReaction{
		GroupID: w.GroupID, Target: w.Target, Emoji: w.Emoji, By: w.By,
		Remove: w.Remove, AtNanos: w.AtNanos, Sig: w.Sig,
	}
	// Enforce the emoji cap ON OPEN (the carrier/reactor is untrusted), the same
	// discipline as the 1:1 reaction and the group image paths.
	if len(gr.Emoji) == 0 || len(gr.Emoji) > maxReactionEmojiBytes {
		return GroupReaction{}, fmt.Errorf("bad reaction")
	}
	if gr.GroupID == "" || gr.Target == "" {
		return GroupReaction{}, fmt.Errorf("missing group or target")
	}
	if !gr.Verify() {
		return GroupReaction{}, fmt.Errorf("reaction signature verification failed")
	}
	return gr, nil
}

// OpenGroupReaction verifies and decrypts a reaction envelope addressed to this
// peer (mirrors OpenGroup).
func (p *Peer) OpenGroupReaction(env GroupReactionEnvelope) (GroupReaction, error) {
	return OpenGroupReactionEnvelope(p.id, env)
}

// SealGroupReactionAs seals a reaction for one recipient using this peer's
// identity as the carrier — used when answering a gossip pull (we forward on the
// reactor's behalf).
func (p *Peer) SealGroupReactionAs(gr GroupReaction, recipient string, recipientDH [32]byte) (GroupReactionEnvelope, error) {
	return SealGroupReaction(p.id, gr, recipient, recipientDH)
}
