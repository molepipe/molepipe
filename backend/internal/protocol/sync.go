package protocol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Multi-device sync auth. A sync caller proves TWO things over a server-issued
// nonce: that it holds the account identity key (it's "you"), and that it holds
// an ENROLLED device key (this specific device was paired). Both are required —
// identity-key proof alone would let a stolen recovery phrase pull your history,
// defeating the point of pairing.

// SyncIdentityBlob is signed by the account identity key. It binds the device
// pubkey so the identity authorization is tied to this specific device.
func SyncIdentityBlob(nonce, devicePub []byte) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte("sync"), nonce, devicePub)
}

// SyncDeviceBlob is signed by the device key, proving possession of it.
func SyncDeviceBlob(nonce []byte) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte("sync-device"), nonce)
}

// SyncVerify checks a sync request's two signatures and enrollment. The nonce
// must already have been consumed (single-use) by the caller. Returns nil iff
// the request is authorized.
func SyncVerify(account string, nonce, devicePub, idSig, deviceSig []byte, isEnrolled func(devicePub []byte) bool) error {
	idKey, err := identity.AccountNumberFromString(account)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	if len(devicePub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad device key length")
	}
	if !ed25519.Verify(idKey, SyncIdentityBlob(nonce, devicePub), idSig) {
		return fmt.Errorf("identity signature invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(devicePub), SyncDeviceBlob(nonce), deviceSig) {
		return fmt.Errorf("device signature invalid")
	}
	if !isEnrolled(devicePub) {
		return fmt.Errorf("device not enrolled")
	}
	return nil
}

// SyncExchange dials our own account onion (which reaches the current primary),
// authenticates as an enrolled device, and exchanges state: it uploads myState
// and returns the primary's merged state. deviceSign signs with this device's key.
func SyncExchange(ctx context.Context, dialer tor.Dialer, id *identity.Identity, devicePub []byte, deviceSign func([]byte) []byte, myState []byte) ([]byte, error) {
	client, base := onionClient(dialer, id.AccountNumber())
	var ch struct {
		Nonce []byte `json:"nonce"`
	}
	if err := getJSON(ctx, client, base+"/sync/challenge", &ch); err != nil {
		return nil, fmt.Errorf("sync challenge: %w", err)
	}
	if len(ch.Nonce) == 0 {
		return nil, fmt.Errorf("empty sync challenge")
	}
	idSig := ed25519.Sign(id.Keys.Signing.Private, SyncIdentityBlob(ch.Nonce, devicePub))
	devSig := deviceSign(SyncDeviceBlob(ch.Nonce))
	body := map[string]any{
		"device_pub": devicePub,
		"nonce":      ch.Nonce,
		"id_sig":     idSig,
		"device_sig": devSig,
		"state":      json.RawMessage(myState),
	}
	var resp struct {
		State json.RawMessage `json:"state"`
	}
	if err := postJSONInto(ctx, client, base+"/sync", body, &resp); err != nil {
		return nil, fmt.Errorf("sync exchange: %w", err)
	}
	return resp.State, nil
}
