package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// MailKindRotation is the payload.Kind for an address-rotation announcement,
// alongside "" (text) and MailKindImage. It rides the same sealed plaintext as a
// message, so a rotation can travel on EITHER authenticated channel without a new
// envelope type: an established Double-Ratchet session (online) or a static-DH
// mailbox seal (offline). Both channels are rooted in the sender's non-rotating
// m/0'/1' DH identity key.
const MailKindRotation = "rotation"

// MailKindRotationAck is the payload.Kind for the receiver's acknowledgement of
// an applied address rotation. It rides the SAME established ratchet session back
// to the rotator (never the mailbox — an ack is only ever sent by a contact who
// just processed a rotation on a live session), so it needs no envelope of its
// own: the rotator's pendingRotations resend drives liveness, and this ack is
// what lets it stop. It carries only the alias index the receiver applied; the
// acking contact's identity is the CHANNEL (the ratchet session's account), never
// a field here, exactly as for the rotation itself.
const MailKindRotationAck = "rotation-ack"

// EncodeRotationAckPayload builds the sealed plaintext acknowledging that the
// receiver has applied the rotation to alias `index`. Interchangeable with the
// other Encode*Payload builders so the same session seal/open path carries it.
func EncodeRotationAckPayload(index uint32) []byte {
	b, err := json.Marshal(payload{Kind: MailKindRotationAck, AliasIndex: index})
	if err != nil {
		return nil // cannot happen for these field types
	}
	return b
}

// DecodeRotationAckPayload extracts the acked alias index from a decrypted
// plaintext. ok is false for any plaintext that isn't a rotation-ack payload.
func DecodeRotationAckPayload(pt []byte) (uint32, bool) {
	p, ok := decodePayload(pt)
	if !ok || p.Kind != MailKindRotationAck {
		return 0, false
	}
	return p.AliasIndex, true
}

// AddressRotationPath is the dedicated onion route for pushing a rotation to an
// online contact, kept separate so it decodes exactly one concrete type (the
// repo does no union-sniffing on a route). Reserved for the Phase E sender/handler
// wiring; defined here so the wire surface lands with the protocol type.
const AddressRotationPath = "/p2p/address-rotation"

// AddressRotation announces that the sender's externally-visible onion address
// has rotated to NewOnion. It deliberately carries NO identity of its own: the
// sender is authenticated by the CHANNEL it arrives on — an established ratchet
// session or a static-DH mailbox seal — both rooted in the sender's non-rotating
// m/0'/1' X25519 DH identity key, which is the continuity anchor the receiver
// already caches as Contact.DHPub. The receiver therefore takes the sender's
// identity ONLY from the channel (the session's account, or the contact whose
// cached DHPub matches the seal's SenderDHPub) and never from any field here —
// trusting a payload-carried identity would reopen the ungated-Profile hijack
// (an attacker can read a victim's public DHPub and would otherwise redirect the
// victim's contacts to an attacker onion).
//
// AliasIndex is monotonic and is the rollback-replay guard: the receiver rejects
// any announcement whose index is <= the highest it has already accepted for that
// contact (Contact.AliasIndex). It need not be sequential — a contact that misses
// indexes N+1..N+4 and later receives N+5 accepts it fine.
//
// ValidFrom (unix seconds) is RESERVED for a future clock-skew tolerance rule and
// is NOT read on verify today; it is carried so the field need not be added to the
// wire later.
type AddressRotation struct {
	NewOnion   string `json:"new_onion"`
	AliasIndex uint32 `json:"alias_index"`
	ValidFrom  int64  `json:"valid_from,omitempty"`
}

// EncodeRotationPayload builds the sealed plaintext for an address rotation,
// interchangeable with EncodePayload/EncodeImagePayload so the same seal/open
// machinery carries it on either channel.
func EncodeRotationPayload(r AddressRotation) []byte {
	b, err := json.Marshal(payload{
		Kind:       MailKindRotation,
		NewOnion:   r.NewOnion,
		AliasIndex: r.AliasIndex,
		ValidFrom:  r.ValidFrom,
	})
	if err != nil {
		return nil // cannot happen for these field types
	}
	return b
}

// DecodeRotationPayload extracts an AddressRotation from a decrypted plaintext.
// ok is false for any plaintext that isn't a rotation payload (text, image, or
// legacy bare text). NewOnion is peer-supplied, so its shape is validated here
// (a well-formed v3 account/onion label) before the caller acts on it; the
// sender's IDENTITY is still the caller's job to take from the channel, never
// from this struct.
func DecodeRotationPayload(pt []byte) (AddressRotation, bool) {
	p, ok := decodePayload(pt)
	if !ok || p.Kind != MailKindRotation {
		return AddressRotation{}, false
	}
	if _, err := identity.AccountNumberFromString(p.NewOnion); err != nil {
		return AddressRotation{}, false
	}
	return AddressRotation{NewOnion: p.NewOnion, AliasIndex: p.AliasIndex, ValidFrom: p.ValidFrom}, true
}

// SealMailRotationEnvelope seals an address rotation as a mailbox envelope for an
// offline contact, over the same static-DH channel as any offline message: the
// AEAD is keyed by SharedSecret(sender stable DH, recipientDH), and SenderDHPub
// carries the sender's non-rotating m/0'/1' DH key so the recipient can match it
// to the contact's cached anchor and authenticate the rotation without trusting
// any account string. Mirrors SealMailImageEnvelope. Phase E's sender calls this.
func SealMailRotationEnvelope(id *identity.Identity, recipient string, recipientDH [32]byte, r AddressRotation, sentAt time.Time) (MailEnvelope, error) {
	if _, err := identity.AccountNumberFromString(r.NewOnion); err != nil {
		return MailEnvelope{}, fmt.Errorf("bad new onion: %w", err)
	}
	if _, err := identity.AccountNumberFromString(recipient); err != nil {
		return MailEnvelope{}, fmt.Errorf("bad recipient: %w", err)
	}
	sender := id.AccountNumber()
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, recipientDH)
	if err != nil {
		return MailEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(sender, recipient))
	box, err := crypto.SealMessage(key, EncodeRotationPayload(r), aad(sender, recipient))
	if err != nil {
		return MailEnvelope{}, err
	}
	myDH := id.Keys.DH.Public
	m := MailEnvelope{Recipient: recipient, Sender: sender, SenderDHPub: myDH[:], SentAt: sentAt.Unix(), Box: box}
	m.Sig = ed25519.Sign(id.Keys.Signing.Private, m.signingBlob())
	return m, nil
}
