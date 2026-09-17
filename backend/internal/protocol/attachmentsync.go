package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Cross-device attachment backfill. A message row carries an image's metadata
// (id/mime/size) and syncs between a user's devices via /sync, but the image
// BYTES live only on the device that sent or received it. This exchange moves
// those bytes between the user's own devices so an image opened on a second
// device isn't a "not on this device" placeholder.
//
// It is secondary-driven, exactly like state sync: only the secondary can dial
// the primary's account onion, so the secondary both pulls blobs it is missing
// (want) and pushes blobs the primary asked for (push, driven by the primary's
// need list from a prior round). Because every device of an account derives the
// SAME store key from the shared seed, a blob is portable between them; the
// bytes travel as plaintext over the enrolled-device-authenticated Tor channel,
// the same trust boundary /sync already uses for the whole message history.

// AttachmentBlob is one image's bytes on the wire (Data marshals as base64).
type AttachmentBlob struct {
	ID   string `json:"id"`
	Mime string `json:"mime"`
	Data []byte `json:"data"`
}

// AttachmentSyncExchange runs one attachment reconcile round with the primary.
// It authenticates as an enrolled device the same way SyncExchange does
// (identity key + device key signed over a fresh single-use challenge nonce),
// uploads push (blobs the primary previously said it needs) and requests want
// (ids this device is missing), and returns what the primary provided plus the
// ids the primary still needs.
func AttachmentSyncExchange(ctx context.Context, dialer tor.Dialer, id *identity.Identity, devicePub []byte, deviceSign func([]byte) []byte, want []string, push []AttachmentBlob) (provide []AttachmentBlob, need []string, err error) {
	client, base := onionClient(dialer, id.AccountNumber())
	var ch struct {
		Nonce []byte `json:"nonce"`
	}
	if err := getJSON(ctx, client, base+"/sync/challenge", &ch); err != nil {
		return nil, nil, fmt.Errorf("attachment sync challenge: %w", err)
	}
	if len(ch.Nonce) == 0 {
		return nil, nil, fmt.Errorf("empty attachment sync challenge")
	}
	idSig := ed25519.Sign(id.Keys.Signing.Private, SyncIdentityBlob(ch.Nonce, devicePub))
	devSig := deviceSign(SyncDeviceBlob(ch.Nonce))
	body := map[string]any{
		"device_pub": devicePub,
		"nonce":      ch.Nonce,
		"id_sig":     idSig,
		"device_sig": devSig,
		"want":       want,
		"push":       push,
	}
	var resp struct {
		Provide []AttachmentBlob `json:"provide"`
		Need    []string         `json:"need"`
	}
	if err := postJSONInto(ctx, client, base+"/sync/attachment", body, &resp); err != nil {
		return nil, nil, fmt.Errorf("attachment sync exchange: %w", err)
	}
	return resp.Provide, resp.Need, nil
}
