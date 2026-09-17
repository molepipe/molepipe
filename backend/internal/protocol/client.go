package protocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// clientBackstopTimeout is a last-resort ceiling, NOT the delivery policy.
//
// It used to be 90s, which silently capped every caller regardless of the
// deadline they passed: a friend-accept given a 2-minute context actually got
// 90 seconds. A live-Tor run measured a cold first contact — fetching a
// freshly-published descriptor, building a circuit, reaching an introduction
// point — taking 88 seconds, two seconds inside that cap. That is the coin
// flip that stranded a real requester.
//
// Every caller already bounds its own context (send probes, mailbox drop-offs,
// presence sweeps, sync and pairing all pass a deadline), so the policy belongs
// there and this only has to be generous enough never to fire first.
const clientBackstopTimeout = 3 * time.Minute

// onionClient builds an HTTP client that dials one peer onion over Tor.
func onionClient(dialer tor.Dialer, account string) (*http.Client, string) {
	onion := account + ".onion:80"
	client := &http.Client{
		Timeout: clientBackstopTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialOnion(ctx, onion)
			},
			DisableKeepAlives: true,
		},
	}
	return client, "http://" + account + ".onion"
}

// fetchChallenge gets and verifies a challenge from the recipient (confirms the
// onion controls the account key and returns a fresh nonce + their X25519 key).
func fetchChallenge(ctx context.Context, client *http.Client, base, recipient string) (Challenge, error) {
	recipientEd, err := identity.AccountNumberFromString(recipient)
	if err != nil {
		return Challenge{}, err
	}
	var ch Challenge
	if err := getJSON(ctx, client, base+ChallengePath, &ch); err != nil {
		return Challenge{}, fmt.Errorf("challenge: %w", err)
	}
	if len(ch.DHPub) != 32 {
		return Challenge{}, fmt.Errorf("bad recipient dh key: %w", ErrProtocol)
	}
	if !ed25519.Verify(recipientEd,
		signBlob(sigContextFor(protoVerCurrent), []byte("challenge"), []byte(recipient), ch.DHPub), ch.Sig) {
		return Challenge{}, fmt.Errorf("recipient challenge signature invalid: %w", ErrProtocol)
	}
	// Every gated exchange begins here, so this is the one place that rejects a
	// peer whose advertised version is outside our window — uniformly, up front,
	// as a clear error rather than an opaque signature failure downstream. At v1
	// this never trips (the sole version is 1); it is the seam v2 negotiates on.
	if _, err := negotiateVersion(ch.Ver); err != nil {
		return Challenge{}, fmt.Errorf("challenge: %w", err)
	}
	return ch, nil
}

// FetchProfile dials an account's onion and returns its signed profile. Verifies
// the profile is signed by that account's key (confirms reachable + authentic).
func FetchProfile(ctx context.Context, dialer tor.Dialer, account string) (Profile, error) {
	ed, err := identity.AccountNumberFromString(account)
	if err != nil {
		return Profile{}, fmt.Errorf("bad account: %w", err)
	}
	client, base := onionClient(dialer, account)
	var pr Profile
	if err := getJSON(ctx, client, base+ProfilePath, &pr); err != nil {
		return Profile{}, err
	}
	if pr.Account != account {
		return Profile{}, fmt.Errorf("profile account mismatch: %w", ErrProtocol)
	}
	if !verifyProfileSig(ed, account, pr) {
		return Profile{}, fmt.Errorf("profile signature invalid: %w", ErrProtocol)
	}
	pr.DisplayName = clampName(pr.DisplayName)
	pr.AvatarHash = clampAvatarHash(pr.AvatarHash)
	return pr, nil
}

// verifyProfileSig checks a self-signed card, tolerant of the wire version that
// signed it. The card is ungated with no handshake, so pr.Ver is only a hint:
// we try the hinted version first, then every other supported version, and
// accept if any matches (see candidateVersions). This is what lets one build
// verify cards from peers on either side of a version bump — and, deliberately,
// what stops a flipped Ver byte on an otherwise-valid card from denying it.
func verifyProfileSig(ed ed25519.PublicKey, account string, pr Profile) bool {
	return verifyProfileSigUnder(candidateVersions(pr.Ver), ed, account, pr)
}

// verifyProfileSigUnder is the arg-taking core: it accepts if the card verifies
// under ANY version in candidates. Production always calls it via
// verifyProfileSig with candidateVersions(pr.Ver), so at the current window it
// only ever tries [1]. Splitting the candidate list out (mirroring
// negotiate/negotiateVersion) is what lets the cross-version test drive a real
// two-version world — e.g. candidates {2,1} accepts a v2-signed card while a
// v1-only [1] verifier rejects it — without opening the production window.
func verifyProfileSigUnder(candidates []uint16, ed ed25519.PublicKey, account string, pr Profile) bool {
	for _, v := range candidates {
		if ed25519.Verify(ed, signBlob(sigContextFor(v), []byte("profile"), []byte(account), []byte(pr.DisplayName), pr.DHPub, []byte(pr.AvatarHash)), pr.Sig) {
			return true
		}
	}
	return false
}

// FetchContactProfile pulls the operational profile fields (mailbox URL) that are
// kept out of the public card. Does the challenge handshake and signs the request
// so the recipient can confirm WE are asking, then gate on our being an accepted
// contact. A non-contact (or a stranger) gets an empty mailbox, not an error, so
// the response is a uniform non-oracle.
func FetchContactProfile(ctx context.Context, dialer tor.Dialer, id *identity.Identity, recipient string) (ContactProfile, error) {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return ContactProfile{}, err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("contact-profile"), ch.Nonce, []byte(recipient)))
	req := ContactProfileRequest{From: id.AccountNumber(), Nonce: ch.Nonce, Sig: sig}
	var out ContactProfile
	if err := postJSONInto(ctx, client, base+ContactProfilePath, req, &out); err != nil {
		return ContactProfile{}, fmt.Errorf("contact profile: %w", err)
	}
	out.MailboxURL = clampMailbox(out.MailboxURL)
	return out, nil
}

// FetchAvatar pulls a peer's avatar bytes from their ungated AvatarPath by hash.
// The endpoint is content-addressed and unauthenticated (an avatar is meant to be
// visible at add-time, before friendship), so integrity comes from the hash, NOT
// a signature: the caller got `hash` from the peer's SIGNED profile card, and we
// verify sha256(bytes) == hash here — a relay that swaps the bytes is caught, and
// the hash's provenance (the signed card) is what ties the face to the account.
// Reads at most MaxAvatarBytes.
func FetchAvatar(ctx context.Context, dialer tor.Dialer, account, hash string) ([]byte, error) {
	if len(hash) != 64 {
		return nil, fmt.Errorf("bad avatar hash")
	}
	client, base := onionClient(dialer, account)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+AvatarPath+"?h="+url.QueryEscape(hash), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("avatar status %d", resp.StatusCode)
	}
	// +1 so an oversized body trips the cap check rather than being silently
	// truncated to exactly MaxAvatarBytes (which could then mis-hash).
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxAvatarBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > MaxAvatarBytes {
		return nil, fmt.Errorf("avatar size out of range")
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != sha256.Size {
		return nil, fmt.Errorf("bad avatar hash")
	}
	if sum := sha256.Sum256(data); subtle.ConstantTimeCompare(sum[:], hashBytes) != 1 {
		return nil, fmt.Errorf("avatar bytes do not match hash: %w", ErrProtocol)
	}
	return data, nil
}

// SendFriendRequest sends a signed friend request bound to reqID.
func SendFriendRequest(ctx context.Context, dialer tor.Dialer, id *identity.Identity, myName, reqID, recipient string) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	name := clampName(myName)
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("friend-request"), ch.Nonce, []byte(recipient), []byte(name), []byte(reqID)))
	req := FriendRequest{From: id.AccountNumber(), FromName: name, ReqID: reqID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+FriendRequestPath, req); err != nil {
		return fmt.Errorf("friend request: %w", err)
	}
	return nil
}

// SendFriendAccept sends a signed accept echoing reqID.
func SendFriendAccept(ctx context.Context, dialer tor.Dialer, id *identity.Identity, myName, reqID, recipient string) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	name := clampName(myName)
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("friend-accept"), ch.Nonce, []byte(recipient), []byte(name), []byte(reqID)))
	acc := FriendAccept{From: id.AccountNumber(), FromName: name, ReqID: reqID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+FriendAcceptPath, acc); err != nil {
		return fmt.Errorf("friend accept: %w", err)
	}
	return nil
}

// SendMessage dials the recipient's onion, does the challenge handshake, and
// delivers one authenticated, encrypted message.
func SendMessage(ctx context.Context, dialer tor.Dialer, id *identity.Identity, recipientAccount, msgID, text string, reply ...Reply) error {
	if len(text) == 0 {
		return fmt.Errorf("empty message")
	}
	if len(text) > maxPlaintext {
		return fmt.Errorf("message too long (max %d bytes)", maxPlaintext)
	}
	client, base := onionClient(dialer, recipientAccount)
	ch, err := fetchChallenge(ctx, client, base, recipientAccount)
	if err != nil {
		return err
	}

	var theirDH [32]byte
	copy(theirDH[:], ch.DHPub)
	shared, err := crypto.SharedSecret(id.Keys.DH.Private, theirDH)
	if err != nil {
		return err
	}
	key := crypto.DeriveDirectionalKey(shared, msgKeyInfo(id.AccountNumber(), recipientAccount))
	box, err := crypto.SealMessage(key, EncodePayload(msgID, text, reply...), aad(id.AccountNumber(), recipientAccount))
	if err != nil {
		return err
	}

	myDH := id.Keys.DH.Public
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte("message"), ch.Nonce, []byte(recipientAccount), myDH[:]))
	env := Envelope{Sender: id.AccountNumber(), SenderDHPub: myDH[:], Nonce: ch.Nonce, Sig: sig, Box: box}
	if err := postJSON(ctx, client, base+MessagePath, env); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// SendGroupEnvelope delivers a sealed group message to one member. Unlike
// SendMessage it does NO live challenge handshake: a group message is
// self-authenticating (the inner author signature) and sealed with the
// recipient's roster key, so the author OR any forwarding member can deliver it
// the same way — which is what the "everyone relays" model needs.
func SendGroupEnvelope(ctx context.Context, dialer tor.Dialer, env GroupEnvelope, recipient string) error {
	client, base := onionClient(dialer, recipient)
	if err := postJSONInto(ctx, client, base+GroupMessagePath, map[string]any{"envelope": env}, nil); err != nil {
		return fmt.Errorf("group send: %w", err)
	}
	return nil
}

// SendGroupReactionEnvelope delivers a sealed group reaction to one member. Like
// SendGroupEnvelope it does no challenge handshake — the reaction is
// self-authenticating (the inner reactor signature) and sealed with the
// recipient's roster key, so the reactor or any forwarding member can deliver it.
func SendGroupReactionEnvelope(ctx context.Context, dialer tor.Dialer, env GroupReactionEnvelope, recipient string) error {
	client, base := onionClient(dialer, recipient)
	if err := postJSONInto(ctx, client, base+GroupReactPath, map[string]any{"envelope": env}, nil); err != nil {
		return fmt.Errorf("group react: %w", err)
	}
	return nil
}

// SendRoster pushes a signed roster to one member. Like a group message it is
// self-authenticating (the committer's signature), so no live challenge is
// needed and any member holding the roster can forward it the same way.
func SendRoster(ctx context.Context, dialer tor.Dialer, r SignedRoster, recipient string) error {
	client, base := onionClient(dialer, recipient)
	if err := postJSONInto(ctx, client, base+GroupRosterPath, map[string]any{"roster": r}, nil); err != nil {
		return fmt.Errorf("roster push: %w", err)
	}
	return nil
}

// GroupSyncPull sends a signed have-list to one member and returns the group
// messages they hold that we're missing (each sealed for us) plus, when the
// responder holds a roster newer than our HaveEpoch, that signed roster — so
// membership converges over the same gossip exchange as history. Reconciliation
// is pull-based and symmetric: every member periodically pulls from the others,
// so the union converges without any push-back (which also keeps backfill silent
// — the puller stores without notifying). A nil roster means "nothing newer".
// The reactions field rides the UNSIGNED response (only the request is signed),
// so a responder that predates build 4 simply omits it and an older requester
// ignores it — group-reaction catch-up is fully backward-compatible and never
// touches the signed groupSyncSignBlob.
func GroupSyncPull(ctx context.Context, dialer tor.Dialer, req GroupSyncRequest, responder string) ([]GroupEnvelope, *SignedRoster, []GroupReactionEnvelope, error) {
	client, base := onionClient(dialer, responder)
	var out struct {
		Missing   []GroupEnvelope         `json:"missing"`
		Roster    *SignedRoster           `json:"roster,omitempty"`
		Reactions []GroupReactionEnvelope `json:"reactions,omitempty"`
	}
	if err := postJSONInto(ctx, client, base+GroupSyncPath, req, &out); err != nil {
		return nil, nil, nil, fmt.Errorf("group sync: %w", err)
	}
	return out.Missing, out.Roster, out.Reactions, nil
}

// SendAttachment dials the recipient, does the challenge handshake, and delivers
// one sealed image. Direct only — there is no relay or mailbox fallback for
// attachments (relay would overload friends; the mailbox caps blobs far below an
// image). SealAttachment enforces the size cap and MIME allowlist before the
// bytes ever go on the wire.
func SendAttachment(ctx context.Context, dialer tor.Dialer, id *identity.Identity, recipient, msgID, mime string, data []byte) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	var theirDH [32]byte
	copy(theirDH[:], ch.DHPub)
	env, err := SealAttachment(id, recipient, theirDH, ch.Nonce, msgID, mime, data)
	if err != nil {
		return err
	}
	if err := postJSON(ctx, client, base+AttachmentPath, env); err != nil {
		return fmt.Errorf("send attachment: %w", err)
	}
	return nil
}

func getJSON(ctx context.Context, c *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Structured like postJSON's non-200 path, so a peer that answers and
		// refuses (a 4xx) classifies as terminal (ClassPeerRejected) instead of
		// being retried for the whole budget. GET bodies here are small/absent, so
		// the reason string is best-effort and bounded.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{Code: resp.StatusCode, Body: string(bytes.TrimSpace(msg))}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(out)
}

func postJSON(ctx context.Context, c *http.Client, url string, body any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{Code: resp.StatusCode, Body: string(bytes.TrimSpace(msg))}
	}
	return nil
}

// StatusError is a non-200 answer from a peer. It exists so a caller holding a
// retry queue can tell "the peer answered and refused" (final — stop retrying)
// from "we could not reach the peer at all" (transport error — worth retrying).
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("status %d: %s", e.Code, e.Body) }
