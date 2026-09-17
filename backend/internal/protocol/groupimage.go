package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// On-demand full-image fetch for group images. The thumbnail fanned out with the
// group message (see GroupMessage); the full bytes are pulled only when a member
// asks. Any member who HOLDS the full image can serve it — the requester verifies
// what comes back against the author-signed FullHash from the group message, so a
// serving member cannot substitute a different image.

// GroupImagePath is the onion endpoint a member dials to fetch a full group image.
const GroupImagePath = "/p2p/group-image"

const groupImageReqContext = "group-image-request"

// GroupImageRequest asks a holder for the full bytes of one group image. It is
// signed so the holder can confirm the requester is a roster member (and only
// members trigger the re-seal). No live nonce is needed: the request reveals
// nothing, and the response is sealed for the requester so it helps no one else.
type GroupImageRequest struct {
	GroupID   string `json:"group_id"`
	FullID    string `json:"full_id"`
	Requester string `json:"requester"`
	Sig       []byte `json:"sig"`
}

func groupImageReqBlob(groupID, fullID, requester string) []byte {
	return signBlob(sigContextFor(protoVerCurrent), []byte(groupImageReqContext), []byte(groupID), []byte(fullID), []byte(requester))
}

// SignGroupImageRequest builds a signed request from the fetching member.
func SignGroupImageRequest(id *identity.Identity, groupID, fullID string) GroupImageRequest {
	r := GroupImageRequest{GroupID: groupID, FullID: fullID, Requester: id.AccountNumber()}
	r.Sig = ed25519.Sign(id.Keys.Signing.Private, groupImageReqBlob(groupID, fullID, r.Requester))
	return r
}

// Verify checks the requester's signature. The caller still confirms the
// requester is actually a member of the group's roster.
func (r GroupImageRequest) Verify() bool {
	reqEd, err := identity.AccountNumberFromString(r.Requester)
	if err != nil {
		return false
	}
	return ed25519.Verify(reqEd, groupImageReqBlob(r.GroupID, r.FullID, r.Requester), r.Sig)
}

// GroupImageEnvelope carries the full image bytes sealed from the HOLDER to the
// requester under their directional key, so a hop reveals nothing.
type GroupImageEnvelope struct {
	Holder      string `json:"holder"`
	HolderDHPub []byte `json:"holder_dh_pub"`
	Box         []byte `json:"box"`
}

// SealGroupImage seals full image bytes for the requester, from the holder.
func SealGroupImage(holder *identity.Identity, requester string, requesterDH [32]byte, data []byte) (GroupImageEnvelope, error) {
	if len(data) == 0 || len(data) > MaxAttachmentBytes {
		return GroupImageEnvelope{}, fmt.Errorf("image size out of range")
	}
	if _, err := identity.AccountNumberFromString(requester); err != nil {
		return GroupImageEnvelope{}, fmt.Errorf("bad requester: %w", err)
	}
	holderAcct := holder.AccountNumber()
	shared, err := crypto.SharedSecret(holder.Keys.DH.Private, requesterDH)
	if err != nil {
		return GroupImageEnvelope{}, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(holderAcct, requester))
	box, err := crypto.SealMessage(key, data, aad(holderAcct, requester))
	if err != nil {
		return GroupImageEnvelope{}, err
	}
	dh := holder.Keys.DH.Public
	return GroupImageEnvelope{Holder: holderAcct, HolderDHPub: dh[:], Box: box}, nil
}

// OpenGroupImage decrypts a fetched full image. The caller MUST still verify the
// bytes against the author-signed FullHash from the group message — decryption
// only proves the holder sealed it, not that it is the right image.
func OpenGroupImage(id *identity.Identity, env GroupImageEnvelope) ([]byte, error) {
	if _, err := identity.AccountNumberFromString(env.Holder); err != nil {
		return nil, fmt.Errorf("bad holder account: %w", err)
	}
	if len(env.HolderDHPub) != 32 {
		return nil, fmt.Errorf("bad holder dh key length")
	}
	var holderDH [32]byte
	copy(holderDH[:], env.HolderDHPub)
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, holderDH)
	if err != nil {
		return nil, err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(env.Holder, id.AccountNumber()))
	pt, err := crypto.OpenMessage(key, env.Box, aad(env.Holder, id.AccountNumber()))
	if err != nil {
		return nil, err
	}
	if len(pt) == 0 || len(pt) > MaxAttachmentBytes {
		return nil, fmt.Errorf("image size out of range")
	}
	return pt, nil
}

// FetchGroupImage dials a holder and pulls the full bytes for one group image.
// The caller verifies the result against the author-signed FullHash.
func FetchGroupImage(ctx context.Context, dialer tor.Dialer, id *identity.Identity, holder, groupID, fullID string) ([]byte, error) {
	client, base := onionClient(dialer, holder)
	req := SignGroupImageRequest(id, groupID, fullID)
	var env GroupImageEnvelope
	if err := postJSONInto(ctx, client, base+GroupImagePath, req, &env); err != nil {
		return nil, fmt.Errorf("group image fetch: %w", err)
	}
	return OpenGroupImage(id, env)
}
