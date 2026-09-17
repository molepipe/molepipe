package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Emoji reactions. Like "delete for everyone" (delete.go) a reaction is a signed,
// per-message courtesy request: the recipient's client chooses to honour it. The
// signature proves who is asking; the recipient enforces that a peer may only
// react to messages in the conversation between the two of them (the hook). A
// reaction names the message by its shared wire id, so both sides agree on which
// message it lands on.

// ReactMessagePath is the peer-facing endpoint for a reaction request.
const ReactMessagePath = "/p2p/react-message"

// maxReactionEmojiBytes bounds the attacker-controlled emoji. A reaction is meant
// to be a single glyph; the cap keeps a peer from smuggling arbitrary text into
// the reaction chips.
const maxReactionEmojiBytes = 32

// ReactionRequest asks a recipient to add or remove one emoji reaction on a
// message in our shared conversation. The signature covers the recipient's
// challenge nonce (no replay elsewhere) and the recipient's own account (no
// forwarding to a third party), exactly like DeleteRequest.
type ReactionRequest struct {
	From      string `json:"from"`       // reactor's account
	MessageID string `json:"message_id"` // shared wire id of the target message
	Emoji     string `json:"emoji"`      // the reaction glyph
	Remove    bool   `json:"remove"`     // true removes the reaction, false adds it
	Nonce     []byte `json:"nonce"`      // recipient's challenge nonce
	Sig       []byte `json:"sig"`        // Sign(from_Ed, ctx‖"react-message"‖nonce‖recipient‖message_id‖emoji‖remove)
}

// reactSignBlob builds the signed bytes for a reaction. remove is folded in as a
// single byte so add and remove cannot be swapped by an attacker replaying the
// other one.
func reactSignBlob(nonce []byte, recipient, messageID, emoji string, remove bool) []byte {
	var rb byte
	if remove {
		rb = 1
	}
	return signBlob(sigContextFor(protoVerCurrent), []byte("react-message"), nonce,
		[]byte(recipient), []byte(messageID), []byte(emoji), []byte{rb})
}

// ReceiveReactionRequest verifies an inbound reaction and applies it via the hook.
func (p *Peer) ReceiveReactionRequest(req ReactionRequest) error {
	if !p.consumeNonce(req.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	if len(req.Emoji) == 0 || len(req.Emoji) > maxReactionEmojiBytes {
		return fmt.Errorf("bad reaction")
	}
	fromEd, err := identity.AccountNumberFromString(req.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	blob := reactSignBlob(req.Nonce, p.account(), req.MessageID, req.Emoji, req.Remove)
	if !ed25519.Verify(fromEd, blob, req.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnReaction(req.From, req.MessageID, req.Emoji, req.Remove)
}

// SendReaction asks recipient to add or remove our reaction on one message.
func SendReaction(ctx context.Context, dialer tor.Dialer, id *identity.Identity, messageID, recipient, emoji string, remove bool) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private,
		reactSignBlob(ch.Nonce, recipient, messageID, emoji, remove))
	req := ReactionRequest{From: id.AccountNumber(), MessageID: messageID, Emoji: emoji, Remove: remove, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+ReactMessagePath, req); err != nil {
		return fmt.Errorf("react to message: %w", err)
	}
	return nil
}
