package protocol

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// GroupInvite invites an account to join a group. Like a friend request it is
// challenge-gated (the inviter asserts their identity, bound to the recipient's
// fresh nonce) — the invitee learns only the group's name and who invited them,
// not the membership, until they accept. ReqID ties this invite to the accept
// the invitee will send back.
type GroupInvite struct {
	GroupID     string `json:"group_id"`
	GroupName   string `json:"group_name"`
	Inviter     string `json:"inviter"`
	InviterName string `json:"inviter_name"`
	ReqID       string `json:"req_id"`
	Nonce       []byte `json:"nonce"`
	Sig         []byte `json:"sig"` // Sign(inviter_Ed, ctx‖"group-invite"‖nonce‖recipient‖group_id‖group_name‖req_id)
}

// GroupInviteAccept is the invitee's consent: it carries the DHPub the group
// will seal messages to and echoes the invite's ReqID. Signed and challenge-
// gated so the inviter can confirm both consent (the invitee's own key signs it)
// and that it answers the invite they issued.
type GroupInviteAccept struct {
	GroupID  string `json:"group_id"`
	From     string `json:"from"`
	FromName string `json:"from_name"`
	DHPub    []byte `json:"dh_pub"`
	ReqID    string `json:"req_id"`
	Nonce    []byte `json:"nonce"`
	Sig      []byte `json:"sig"` // Sign(from_Ed, ctx‖"group-invite-accept"‖nonce‖recipient‖group_id‖dh_pub‖req_id)
}

const (
	groupInviteContext       = "group-invite"
	groupInviteAcceptContext = "group-invite-accept"
)

// ReceiveGroupInvite verifies an inbound invite and records it.
func (p *Peer) ReceiveGroupInvite(gi GroupInvite) error {
	if !p.consumeNonce(gi.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	inviterEd, err := identity.AccountNumberFromString(gi.Inviter)
	if err != nil {
		return fmt.Errorf("bad inviter account: %w", err)
	}
	blob := signBlob(sigContextFor(protoVerCurrent), []byte(groupInviteContext), gi.Nonce,
		[]byte(p.account()), []byte(gi.GroupID), []byte(gi.GroupName), []byte(gi.ReqID))
	if !ed25519.Verify(inviterEd, blob, gi.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	if p.hooks.OnGroupInvite == nil {
		return fmt.Errorf("group invites unsupported")
	}
	return p.hooks.OnGroupInvite(gi.GroupID, clampName(gi.GroupName), gi.Inviter, clampName(gi.InviterName), gi.ReqID)
}

// ReceiveGroupInviteAccept verifies an inbound accept and applies it.
func (p *Peer) ReceiveGroupInviteAccept(a GroupInviteAccept) error {
	if !p.consumeNonce(a.Nonce) {
		return fmt.Errorf("unknown or expired challenge nonce")
	}
	fromEd, err := identity.AccountNumberFromString(a.From)
	if err != nil {
		return fmt.Errorf("bad account: %w", err)
	}
	if len(a.DHPub) != 32 {
		return fmt.Errorf("bad dh key length")
	}
	blob := signBlob(sigContextFor(protoVerCurrent), []byte(groupInviteAcceptContext), a.Nonce,
		[]byte(p.account()), []byte(a.GroupID), a.DHPub, []byte(a.ReqID))
	if !ed25519.Verify(fromEd, blob, a.Sig) {
		return fmt.Errorf("signature verification failed")
	}
	if p.hooks.OnGroupInviteAccept == nil {
		return fmt.Errorf("group invites unsupported")
	}
	return p.hooks.OnGroupInviteAccept(a.GroupID, a.From, clampName(a.FromName), a.DHPub, a.ReqID)
}

// SendGroupInvite dials the recipient, does the challenge handshake, and delivers
// a signed invite bound to reqID.
func SendGroupInvite(ctx context.Context, dialer tor.Dialer, id *identity.Identity, myName, groupID, groupName, reqID, recipient string) error {
	client, base := onionClient(dialer, recipient)
	ch, err := fetchChallenge(ctx, client, base, recipient)
	if err != nil {
		return err
	}
	name := clampName(myName)
	gname := clampName(groupName)
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte(groupInviteContext), ch.Nonce, []byte(recipient), []byte(groupID), []byte(gname), []byte(reqID)))
	gi := GroupInvite{GroupID: groupID, GroupName: gname, Inviter: id.AccountNumber(), InviterName: name, ReqID: reqID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+GroupInvitePath, gi); err != nil {
		return fmt.Errorf("group invite: %w", err)
	}
	return nil
}

// SendGroupInviteAccept dials the inviter and delivers a signed acceptance
// carrying our DHPub, echoing reqID.
func SendGroupInviteAccept(ctx context.Context, dialer tor.Dialer, id *identity.Identity, myName, groupID, reqID, inviter string) error {
	client, base := onionClient(dialer, inviter)
	ch, err := fetchChallenge(ctx, client, base, inviter)
	if err != nil {
		return err
	}
	name := clampName(myName)
	dh := id.Keys.DH.Public
	sig := ed25519.Sign(id.Keys.Signing.Private,
		signBlob(sigContextFor(protoVerCurrent), []byte(groupInviteAcceptContext), ch.Nonce, []byte(inviter), []byte(groupID), dh[:], []byte(reqID)))
	acc := GroupInviteAccept{GroupID: groupID, From: id.AccountNumber(), FromName: name, DHPub: dh[:], ReqID: reqID, Nonce: ch.Nonce, Sig: sig}
	if err := postJSON(ctx, client, base+GroupInviteAcceptPath, acc); err != nil {
		return fmt.Errorf("group invite accept: %w", err)
	}
	return nil
}
