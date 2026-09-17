package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Device pairing enrolls a new device's key into the account's linked-devices
// list. It is gated by TWO factors: the account identity key (the new device
// recovered from the phrase) AND a short-lived single-use pairing secret shown
// on an existing device (physical access). Requiring both is what makes a stolen
// phrase insufficient to enroll a device and pull history.

// PairEnrollBlob is signed by the identity key to authorize enrolling devicePub.
func PairEnrollBlob(nonce, devicePub []byte) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte("pair-enroll"), nonce, devicePub)
}

// PairEnroll dials our own account onion (which reaches the existing primary) and
// enrolls devicePub, presenting the pairing secret and an identity-key signature.
func PairEnroll(ctx context.Context, dialer tor.Dialer, id *identity.Identity, devicePub []byte, deviceName string, secret []byte) error {
	client, base := onionClient(dialer, id.AccountNumber())
	var ch struct {
		Nonce []byte `json:"nonce"`
	}
	if err := getJSON(ctx, client, base+"/pair/challenge", &ch); err != nil {
		return fmt.Errorf("pair challenge: %w", err)
	}
	if len(ch.Nonce) == 0 {
		return fmt.Errorf("empty pair challenge")
	}
	idSig := ed25519.Sign(id.Keys.Signing.Private, PairEnrollBlob(ch.Nonce, devicePub))
	body := map[string]any{
		"device_pub":  devicePub,
		"device_name": deviceName,
		"secret":      secret,
		"nonce":       ch.Nonce,
		"id_sig":      idSig,
	}
	if err := postJSONInto(ctx, client, base+"/pair/enroll", body, nil); err != nil {
		return fmt.Errorf("pair enroll: %w", err)
	}
	return nil
}

// PairVerify checks an enrollment request's identity signature. The pairing
// secret and nonce are checked by the caller (they're server-held state). Returns
// nil iff the identity signature over (nonce, devicePub) is valid for account.
func PairVerify(account string, nonce, devicePub, idSig []byte) error {
	idKey, err := identity.AccountNumberFromString(account)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	if len(devicePub) != ed25519.PublicKeySize {
		return fmt.Errorf("bad device key length")
	}
	if !ed25519.Verify(idKey, PairEnrollBlob(nonce, devicePub), idSig) {
		return fmt.Errorf("identity signature invalid")
	}
	return nil
}
