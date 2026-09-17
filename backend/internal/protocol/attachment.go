package protocol

import (
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// attachmentContext is the signing label for an image attachment, distinct from
// "message"/"mailbox-message"/"group-*" so signed bytes can't be replayed across
// paths.
const attachmentContext = "attachment"

// MaxAttachmentBytes is the plaintext image cap AND the DoS boundary in one
// number: the sender downscales below it before sealing, SealAttachment refuses
// anything larger, and the receive handler's MaxBytesReader is derived from it.
// Keep it the tightest value the product can live with — a looser wire cap just
// hands an attacker a bigger blob to throw at every peer.
const MaxAttachmentBytes = 3 << 20 // 3 MiB

// MaxAvatarBytes is the plaintext avatar cap and the DoS boundary for the ungated
// AvatarPath: the set-avatar handler refuses anything larger, the client fetch
// reads at most this many bytes, and it bounds an anonymous GET response. Avatars
// are single-digit KB after the client's square crop; 64 KiB is generous.
const MaxAvatarBytes = 64 << 10 // 64 KiB

const maxMimeLen = 64

// allowedImageMIME is the exact set of content types an attachment may declare.
// It is enforced on RECEIPT (not just at the serve endpoint) because the type is
// attacker-controlled: without this, a peer could send an "image" of
// "text/html", and any endpoint that later echoes the stored type as
// Content-Type would render attacker HTML. Restricting to real image types at
// the door removes that class entirely.
var allowedImageMIME = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/webp": true,
	"image/gif":  true,
}

// AllowedImageMIME reports whether m is an accepted image content type. Exposed
// so the sender and the serve endpoint apply the identical allowlist.
func AllowedImageMIME(m string) bool { return allowedImageMIME[m] }

// AttachmentEnvelope carries one image to a recipient over the direct path,
// challenge-gated exactly like a text Envelope (fresh nonce, signed, sealed
// under the sender→recipient directional key). MsgID is the shared wire id (it
// is also the attachment id, one image per message), so both sides file it under
// the same identifier and "delete for everyone" can name it.
type AttachmentEnvelope struct {
	Sender      string `json:"sender"`
	SenderDHPub []byte `json:"sender_dh_pub"`
	Nonce       []byte `json:"nonce"`
	MsgID       string `json:"msg_id"`
	Mime        string `json:"mime"`
	Sig         []byte `json:"sig"` // Sign(sender_Ed, ctx‖"attachment"‖nonce‖recipient‖sender_dh_pub‖msg_id‖mime)
	Box         []byte `json:"box"` // XChaCha20-Poly1305 sealed image bytes
}

func attachSignBlob(nonce []byte, recipient string, senderDH []byte, msgID, mime string) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte(attachmentContext), nonce,
		[]byte(recipient), senderDH, []byte(msgID), []byte(mime))
}

// SealAttachment seals an image for one recipient, given a challenge nonce and
// the recipient's X25519 key (both from the recipient's challenge). Enforces the
// size cap and the MIME allowlist so a bad attachment never even goes on the
// wire.
func SealAttachment(id *identity.Identity, recipient string, recipientDH [32]byte, nonce []byte, msgID, mime string, data []byte) (AttachmentEnvelope, error) {
	if len(data) == 0 || len(data) > MaxAttachmentBytes {
		return AttachmentEnvelope{}, fmt.Errorf("attachment size out of range")
	}
	if !allowedImageMIME[mime] {
		return AttachmentEnvelope{}, fmt.Errorf("unsupported image type")
	}
	if _, err := identity.AccountNumberFromString(recipient); err != nil {
		return AttachmentEnvelope{}, fmt.Errorf("bad recipient: %w", err)
	}
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, recipientDH)
	if err != nil {
		return AttachmentEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(id.AccountNumber(), recipient))
	box, err := crypto.SealMessage(key, data, aad(id.AccountNumber(), recipient))
	if err != nil {
		return AttachmentEnvelope{}, err
	}
	myDH := id.Keys.DH.Public
	sig := ed25519.Sign(id.Keys.Signing.Private, attachSignBlob(nonce, recipient, myDH[:], msgID, mime))
	return AttachmentEnvelope{
		Sender: id.AccountNumber(), SenderDHPub: myDH[:], Nonce: nonce,
		MsgID: msgID, Mime: mime, Sig: sig, Box: box,
	}, nil
}

// ReceiveAttachment verifies and decrypts an inbound image, returning its wire
// id, MIME and bytes for the caller to store. Order mirrors Receive: consume
// nonce → verify signature → contacts-only gate → decrypt → bound size — so an
// unauthenticated or non-contact sender is neither stored nor able to hand us an
// oversized blob.
func (p *Peer) ReceiveAttachment(env AttachmentEnvelope) (msgID, mime string, data []byte, err error) {
	if !p.consumeNonce(env.Nonce) {
		return "", "", nil, fmt.Errorf("unknown or expired challenge nonce")
	}
	senderEd, err := identity.AccountNumberFromString(env.Sender)
	if err != nil {
		return "", "", nil, fmt.Errorf("bad sender account: %w", err)
	}
	if len(env.SenderDHPub) != 32 {
		return "", "", nil, fmt.Errorf("bad sender dh key length")
	}
	if len(env.Mime) > maxMimeLen || !allowedImageMIME[env.Mime] {
		return "", "", nil, fmt.Errorf("unsupported image type")
	}
	if !ed25519.Verify(senderEd, attachSignBlob(env.Nonce, p.account(), env.SenderDHPub, env.MsgID, env.Mime), env.Sig) {
		return "", "", nil, fmt.Errorf("signature verification failed")
	}
	if !p.hooks.AllowMessage(env.Sender) {
		return "", "", nil, fmt.Errorf("sender is not an accepted contact")
	}
	var theirDH [32]byte
	copy(theirDH[:], env.SenderDHPub)
	shared, err := crypto.SharedSecret(p.id.Keys.DH.Private, theirDH)
	if err != nil {
		return "", "", nil, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(env.Sender, p.account()))
	pt, err := crypto.OpenMessage(key, env.Box, aad(env.Sender, p.account()))
	if err != nil {
		return "", "", nil, err
	}
	if len(pt) == 0 || len(pt) > MaxAttachmentBytes {
		return "", "", nil, fmt.Errorf("attachment too large")
	}
	return env.MsgID, env.Mime, pt, nil
}
