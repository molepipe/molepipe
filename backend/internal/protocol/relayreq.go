package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Relay-request / relay-accept: a permission handshake, DISTINCT from a friend
// request, by which one contact asks another to act as a relay-holder for them.
// It only ever runs between accounts that are already accepted contacts.
const (
	RelayRequestPath = "/p2p/relay-request"
	RelayAcceptPath  = "/p2p/relay-accept"
)

// RelayRequest asks a contact to relay messages on our behalf.
type RelayRequest struct {
	From  string `json:"from"`
	ReqID string `json:"req_id"`
	Nonce []byte `json:"nonce"`
	Sig   []byte `json:"sig"` // Sign(from_Ed, ctx‖"relay-request"‖nonce‖recipient‖req_id)
}

// RelayAccept confirms a relay request; echoes the request's ReqID.
type RelayAccept struct {
	From  string `json:"from"`
	ReqID string `json:"req_id"`
	Nonce []byte `json:"nonce"`
	Sig   []byte `json:"sig"` // Sign(from_Ed, ctx‖"relay-accept"‖nonce‖recipient‖req_id)
}

// ReceiveRelayRequest verifies an inbound relay request and records it.
func (p *Peer) ReceiveRelayRequest(r RelayRequest) error {
	if !p.consumeNonce(r.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(r.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("relay-request"), r.Nonce, []byte(p.account()), []byte(r.ReqID))
	if !ed25519.Verify(fromEd, blob, r.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnRelayRequest(r.From, r.ReqID)
}

// ReceiveRelayAccept verifies an inbound relay accept and applies it.
func (p *Peer) ReceiveRelayAccept(a RelayAccept) error {
	if !p.consumeNonce(a.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(a.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	blob := signBlob(sigContextFor(protoVerCurrent), []byte("relay-accept"), a.Nonce, []byte(p.account()), []byte(a.ReqID))
	if !ed25519.Verify(fromEd, blob, a.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	return p.hooks.OnRelayAccept(a.From, a.ReqID)
}

// SendRelayRequest asks recipient to relay for us, bound to reqID.
func SendRelayRequest(ctx context.Context, dialer tor.Dialer, id *identity.Identity, reqID, recipient string) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("relay-request"), ch.Nonce, []byte(recipient), []byte(reqID)))
	req := RelayRequest{From: id.AccountNumber(), ReqID: reqID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+RelayRequestPath, req); err != nil {
		return fmt.Errorf("relay request: %w", err)
	}
	return nil
}

// SendRelayAccept confirms a relay request, echoing reqID.
func SendRelayAccept(ctx context.Context, dialer tor.Dialer, id *identity.Identity, reqID, recipient string) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("relay-accept"), ch.Nonce, []byte(recipient), []byte(reqID)))
	acc := RelayAccept{From: id.AccountNumber(), ReqID: reqID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+RelayAcceptPath, acc); err != nil {
		return fmt.Errorf("relay accept: %w", err)
	}
	return nil
}
