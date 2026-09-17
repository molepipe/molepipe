package protocol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// "Delete for everyone" (security doc §3). Deliberately NOT a remote wipe: a
// request is scoped to ONE message the sender sent, it is signed so only that
// sender can issue it, and the recipient's client honours it as a courtesy —
// exactly the Signal model. It removes a message from the recipient's view. It
// cannot guarantee the message is gone: a modified client can ignore the
// request, an offline recipient may never receive it, and a screenshot already
// taken is beyond anyone's reach. That limit is a property of the problem, not
// of this implementation, and the UI says so in those words.

// DeleteRequest asks a recipient to remove one message we sent them. The
// signature covers the recipient's challenge nonce, so a request captured off
// the wire cannot be replayed at anyone else, and the recipient's own account,
// so it cannot be forwarded to a third party.
type DeleteRequest struct {
	From      string `json:"from"`       // sender's account (the original author)
	MessageID string `json:"message_id"` // chatstore.MessageID of the message to remove
	Nonce     []byte `json:"nonce"`      // recipient's challenge nonce
	Sig       []byte `json:"sig"`        // Sign(from_Ed, ctx‖"delete-message"‖nonce‖recipient‖message_id)
}

// ReceiveDeleteRequest verifies an inbound delete request and applies it. The
// hook is responsible for the authorization that matters — that the requester
// only gets to delete messages they themselves sent.
func (p *Peer) ReceiveDeleteRequest(d DeleteRequest) error {
	if !p.consumeNonce(d.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(d.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("delete-message"), d.Nonce,
		[]byte(p.account()), []byte(d.MessageID))
	if !ed25519.Verify(fromEd, blob, d.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnDeleteMessage(d.From, d.MessageID)
}

// SendDeleteMessage asks recipient to remove the message with this ID.
func SendDeleteMessage(ctx context.Context, dialer tor.Dialer, id *identity.Identity, messageID, recipient string) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("delete-message"), ch.Nonce,
			[]byte(recipient), []byte(messageID)))
	req := DeleteRequest{From: id.AccountNumber(), MessageID: messageID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+DeleteMessagePath, req); err != nil {
		return fmt.Errorf("delete message: %w", err)
	}
	return nil
}

// payload is the sealed plaintext of a message.
//
// Messages carry an explicit, sender-assigned ID because "delete for everyone"
// needs an identifier BOTH sides agree on, and the local chatstore ID cannot be
// one: it is a content hash over direction, peer and local timestamp, so the
// sender and the recipient derive different values for the same message. The ID
// travels inside the AEAD, not beside it, so it stays confidential and is
// authenticated along with the text rather than being forgeable metadata.
type payload struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	// Kind distinguishes an image payload from the default text one. Empty ⇒ text,
	// so an existing {id,text} plaintext decodes byte-for-byte unchanged (Kind,
	// Mime and Data are all omitempty). "image" carries Mime + Data in place of
	// Text; used only inside a mailbox envelope (SealMailImageEnvelope), never on
	// the direct text path.
	Kind string `json:"kind,omitempty"`
	Mime string `json:"mime,omitempty"`
	Data []byte `json:"data,omitempty"`
	// Reply-with-context. All three are omitempty so a plaintext with no reply
	// decodes byte-for-byte as before (append-safe). They travel inside the AEAD,
	// so on the direct/mailbox path the authenticated sender cannot be tampered
	// with by a courier; ReplyPreview/ReplyAuthor are still peer-supplied text and
	// are clamped on receive (see clampReply). ReplyID names the quoted message's
	// shared wire id, which the recipient normally already holds and resolves
	// locally — the preview/author are only a fallback for a quote it never saw.
	ReplyID      string `json:"reply_id,omitempty"`
	ReplyPreview string `json:"reply_preview,omitempty"`
	ReplyAuthor  string `json:"reply_author,omitempty"`
}

// MailKindImage is the payload.Kind value for an image carried through a mailbox.
const MailKindImage = "image"

// Reply is the context a message carries when it is a reply to another message.
// A zero Reply means the message is not a reply.
type Reply struct {
	ID      string // quoted message's shared wire id (chatstore Message.ID)
	Preview string // short snippet of the quoted message, fallback for display
	Author  string // display name of the quoted message's author, fallback
}

// maxReplyPreviewRunes / maxReplyAuthorRunes bound the peer-supplied quote text.
// It is authenticated (the sender signed the envelope) but still attacker-chosen,
// and maxPlaintext bounds the WHOLE plaintext, so an oversized preview would
// otherwise be accepted and rendered. Cap before storing/displaying, like a name.
const (
	maxReplyPreviewRunes = 160
	maxReplyAuthorRunes  = maxNameRunes
)

// clampReply bounds the peer-supplied preview/author before we store or show them.
// The ID is our own-format identifier, matched against our store, so it needs no
// clamp beyond what a lookup already imposes.
func clampReply(r Reply) Reply {
	if p := []rune(r.Preview); len(p) > maxReplyPreviewRunes {
		r.Preview = string(p[:maxReplyPreviewRunes])
	}
	if a := []rune(r.Author); len(a) > maxReplyAuthorRunes {
		r.Author = string(a[:maxReplyAuthorRunes])
	}
	return r
}

// EncodePayload builds the plaintext to seal. An optional Reply attaches
// reply-with-context; passing none (or a zero Reply) encodes a plain message.
func EncodePayload(msgID, text string, reply ...Reply) []byte {
	p := payload{ID: msgID, Text: text}
	if len(reply) > 0 {
		p.ReplyID = reply[0].ID
		p.ReplyPreview = reply[0].Preview
		p.ReplyAuthor = reply[0].Author
	}
	b, err := json.Marshal(p)
	if err != nil {
		return []byte(text) // cannot happen for strings; degrade to legacy form
	}
	return b
}

// EncodeImagePayload builds the plaintext for an image carried through a mailbox:
// the wire id, the (allowlisted) MIME, and the raw image bytes, all inside the
// AEAD so the mailbox operator sees only opaque ciphertext.
func EncodeImagePayload(msgID, mime string, data []byte) []byte {
	b, _ := json.Marshal(payload{ID: msgID, Kind: MailKindImage, Mime: mime, Data: data})
	return b
}

// decodePayload parses a sealed plaintext into its structured form. ok is false
// for anything that isn't a JSON payload (a legacy bare-text message).
func decodePayload(pt []byte) (p payload, ok bool) {
	if err := json.Unmarshal(pt, &p); err != nil {
		return payload{}, false
	}
	return p, true
}

// DecodePayload reverses EncodePayload. Anything that isn't a payload is
// treated as a legacy bare-text message with no ID, so conversations that
// predate this format keep working — they simply cannot be deleted remotely.
func DecodePayload(pt []byte) (msgID, text string) {
	var p payload
	if err := json.Unmarshal(pt, &p); err != nil || (p.ID == "" && p.Text == "") {
		return "", string(pt)
	}
	return p.ID, p.Text
}

// DecodePayloadFull reverses EncodePayload and also returns the reply context.
// A legacy bare-text plaintext yields the text with a zero Reply. The reply
// fields are clamped here, at the trust boundary, before the caller stores or
// displays them.
func DecodePayloadFull(pt []byte) (msgID, text string, reply Reply) {
	var p payload
	if err := json.Unmarshal(pt, &p); err != nil || (p.ID == "" && p.Text == "") {
		return "", string(pt), Reply{}
	}
	return p.ID, p.Text, clampReply(Reply{ID: p.ReplyID, Preview: p.ReplyPreview, Author: p.ReplyAuthor})
}
