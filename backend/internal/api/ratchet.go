package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
	"github.com/molepipe/molepipe/backend/internal/session"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// --- adapters bridging crypto/session to the protocol interfaces ---

// ratchetSession adapts a *crypto.RatchetSession to protocol.RatchetSession,
// mapping the crypto MessageHeader (which carries local-only fields like the
// SessionID) to/from the on-wire protocol.RatchetHeader.
type ratchetSession struct{ s *crypto.RatchetSession }

func (a *ratchetSession) Encrypt(plaintext, aad []byte) ([]byte, protocol.RatchetHeader, error) {
	box, h, err := a.s.Encrypt(plaintext, aad)
	if err != nil {
		return nil, protocol.RatchetHeader{}, err
	}
	return box, protocol.RatchetHeader{
		RatchetPub:   h.RatchetPub,
		PrevChainLen: h.PrevChainLen,
		MsgNum:       h.MsgNum,
	}, nil
}

func (a *ratchetSession) Decrypt(box []byte, h protocol.RatchetHeader, aad []byte) ([]byte, error) {
	return a.s.Decrypt(box, crypto.MessageHeader{
		ProtocolVersion: crypto.PrekeyProtocolVersion,
		RatchetPub:      h.RatchetPub,
		PrevChainLen:    h.PrevChainLen,
		MsgNum:          h.MsgNum,
	}, aad)
}

func (a *ratchetSession) IsEstablished() bool { return a.s.IsEstablished() }

// ratchetSessionManager adapts the server's session.Manager to the
// protocol.SessionManager interface used by Peer.ReceiveRatchet for ESTABLISHED
// messages. GetOrCreateSession here never establishes: an established-session
// message whose session we don't hold is undecryptable (the peer should have
// sent an initial X3DH envelope), so it errors rather than creating one.
type ratchetSessionManager struct{ s *Server }

func (m ratchetSessionManager) GetOrCreateSession(account string) (protocol.RatchetSession, error) {
	// A resend from a contact's retired alias keys the same established session we
	// migrated to their current account; resolve so the lookup finds it instead of
	// reporting no session. Resolved before touching the manager (no lock overlap).
	account = m.s.resolvePeerAccount(account)
	mgr := m.s.ratchetMgr()
	if mgr == nil {
		return nil, fmt.Errorf("locked")
	}
	sess, ok := mgr.GetOrLoadSession(session.SessionKeyFor(account, ""))
	if !ok {
		return nil, fmt.Errorf("no established session for %s", account)
	}
	return &ratchetSession{sess}, nil
}

func (m ratchetSessionManager) SaveSession(account string) error {
	// Resolve a retired alias to the current account so the advanced ratchet state
	// is saved under the same key GetOrCreateSession loaded it from.
	account = m.s.resolvePeerAccount(account)
	return m.s.saveRatchetSession(session.SessionKeyFor(account, ""))
}

// ratchetMgr returns the live session manager under sessMu, or nil while locked.
func (s *Server) ratchetMgr() *session.Manager {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.sessMgr
}

// currentIdentity returns the unlocked identity, or nil while locked.
func (s *Server) currentIdentity() *identity.Identity {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return s.sessID
}

// newSessionManager builds a session.Manager whose persistence callbacks read
// and write s.ratchetSessions and then persist the store. Persisting a session's
// advanced state BEFORE its message goes on the wire is what stops a crash from
// reusing a ratchet key. The callbacks acquire sessMu; they are only ever called
// from within a manager-lock, so the lock order is always manager → sessMu and
// nothing takes them in the reverse order.
func (s *Server) newSessionManager() *session.Manager {
	save := func(key session.SessionKey, st *session.SessionState) error {
		b, err := json.Marshal(st)
		if err != nil {
			return err
		}
		s.sessMu.Lock()
		if s.ratchetSessions == nil {
			s.ratchetSessions = map[string][]byte{}
		}
		s.ratchetSessions[key.Account] = b
		s.persistLocked()
		s.sessMu.Unlock()
		return nil
	}
	load := func(key session.SessionKey) (*session.SessionState, error) {
		s.sessMu.Lock()
		b, ok := s.ratchetSessions[key.Account]
		s.sessMu.Unlock()
		if !ok {
			return nil, nil
		}
		var st session.SessionState
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, err
		}
		return &st, nil
	}
	del := func(key session.SessionKey) error {
		s.sessMu.Lock()
		delete(s.ratchetSessions, key.Account)
		s.persistLocked()
		s.sessMu.Unlock()
		return nil
	}
	return session.NewManager(save, load, del)
}

// saveRatchetSession persists one session's current state through the manager
// (which serializes it and writes the store).
func (s *Server) saveRatchetSession(key session.SessionKey) error {
	mgr := s.ratchetMgr()
	if mgr == nil {
		return fmt.Errorf("locked")
	}
	return mgr.SaveSession(key)
}

// --- X3DH establishment ---

// establishInitiatorSession runs the initiator half of X3DH against a fetched
// bundle and stands up an initiator ratchet session, returning the X3DH init
// fields to ride the first message. ch.DHPub is the responder's X25519 identity
// key (the same key served in every challenge), which X3DH needs as IK_B.
func (s *Server) establishInitiatorSession(idn *identity.Identity, to string, bundle crypto.PrekeyBundle, ch protocol.Challenge) (*ratchetSession, protocol.X3DHInit, error) {
	if len(ch.DHPub) != 32 || len(bundle.SignedPrekeyPub) != 32 {
		return nil, protocol.X3DHInit{}, fmt.Errorf("bad key length")
	}
	var ikA, spkB, ikBPub [32]byte
	copy(ikA[:], idn.Keys.DH.Private[:])
	copy(spkB[:], bundle.SignedPrekeyPub)
	copy(ikBPub[:], ch.DHPub)

	var opkB *[32]byte
	if len(bundle.OneTimePrekeyPub) == 32 {
		var o [32]byte
		copy(o[:], bundle.OneTimePrekeyPub)
		opkB = &o
	}

	_, ephPub, secret, err := crypto.X3DHInitiate(ikA, spkB, ikBPub, opkB)
	if err != nil {
		return nil, protocol.X3DHInit{}, fmt.Errorf("x3dh initiate: %w", err)
	}

	mgr := s.ratchetMgr()
	if mgr == nil {
		return nil, protocol.X3DHInit{}, fmt.Errorf("locked")
	}
	// Initiator: bobStaticPub = responder's signed prekey; bobStaticPriv unused.
	sess, err := mgr.GetOrCreateSession(session.SessionKeyFor(to, ""), secret, spkB, [32]byte{})
	if err != nil {
		return nil, protocol.X3DHInit{}, fmt.Errorf("create initiator session: %w", err)
	}

	myDH := idn.Keys.DH.Public
	init := protocol.X3DHInit{
		EphemeralPub:    ephPub[:],
		IdentityDHPub:   myDH[:],
		SignedPrekeyID:  bundle.SignedPrekeyID,
		OneTimePrekeyID: bundle.OneTimePrekeyID,
	}
	return &ratchetSession{sess}, init, nil
}

// establishResponderSession runs the responder half of X3DH from an incoming
// init envelope and stands up a responder ratchet session. The caller MUST have
// already verified the signature AND passed the accepted-contact gate before
// calling this, because it consumes a one-time prekey (an irreversible, single-
// use action a stranger must never be able to trigger).
func (s *Server) establishResponderSession(idn *identity.Identity, e protocol.InitialRatchetEnvelope) (*ratchetSession, error) {
	if len(e.Init.EphemeralPub) != 32 || len(e.Init.IdentityDHPub) != 32 {
		return nil, fmt.Errorf("bad init key length")
	}

	s.sessMu.Lock()
	// Check the signed prekey FIRST, before consuming any one-time prekey. A bad
	// SignedPrekeyID must not burn an OTP on the way to failing — otherwise an
	// accepted contact sending inits with a bogus signed-prekey id could drain the
	// one-time pool one key per attempt.
	spkPriv := s.signedPrekeyPrivByIDLocked(e.Init.SignedPrekeyID)
	if spkPriv == nil {
		s.sessMu.Unlock()
		return nil, fmt.Errorf("signed prekey %d unknown", e.Init.SignedPrekeyID)
	}
	var opkPriv []byte
	hasOTP := false
	if e.Init.OneTimePrekeyID != nil {
		opkPriv = s.consumeOneTimePrekeyLocked(*e.Init.OneTimePrekeyID)
		hasOTP = opkPriv != nil
		if !hasOTP {
			// The initiator derived its secret WITH this one-time prekey; if we no
			// longer have it (replay, or already consumed), we cannot reproduce the
			// secret — fail rather than derive a doomed no-OTP secret.
			s.sessMu.Unlock()
			return nil, fmt.Errorf("one-time prekey %d unavailable", *e.Init.OneTimePrekeyID)
		}
	}
	// Copy the prekey privates out before releasing the lock (the OTP was zeroed
	// in the store by consume; spkPriv is still referenced by the store slice).
	spkPrivCopy := append([]byte(nil), spkPriv...)
	// Record this handshake's signature in the SAME durable write that consumes
	// the one-time prekey, so an ack-lost resend is recognised (idempotent ack)
	// even after a crash here — the alternative, recording only once the message
	// is delivered, leaves a window where the OTP is durably consumed but the
	// resend can no longer re-establish (its prekey is gone), reviving the
	// poisoning. A genuinely new handshake from this peer carries a different
	// signature and overwrites this, so it is still processed fresh.
	if s.processedInits == nil {
		s.processedInits = map[string][]byte{}
	}
	s.processedInits[e.Sender] = append([]byte(nil), e.Sig...)
	s.persistLocked() // durably record the consumed one-time prekey + processed init
	s.sessMu.Unlock()

	var ikB, ephPub, ikAPub [32]byte
	copy(ikB[:], idn.Keys.DH.Private[:])
	copy(ephPub[:], e.Init.EphemeralPub)
	copy(ikAPub[:], e.Init.IdentityDHPub)

	secret, err := crypto.X3DHRespond(ikB, spkPrivCopy, opkPriv, ephPub, ikAPub, hasOTP)
	if err != nil {
		return nil, fmt.Errorf("x3dh respond: %w", err)
	}

	mgr := s.ratchetMgr()
	if mgr == nil {
		return nil, fmt.Errorf("locked")
	}
	var spkPrivArr [32]byte
	copy(spkPrivArr[:], spkPrivCopy)
	// Responder: bobStaticPriv = our signed prekey private (our ratchet key).
	sess, err := mgr.GetResponderSession(session.SessionKeyFor(e.Sender, ""), secret, [32]byte{}, spkPrivArr)
	if err != nil {
		return nil, fmt.Errorf("create responder session: %w", err)
	}
	return &ratchetSession{sess}, nil
}

// --- pending-init bookkeeping ---
//
// An initiator session is created as Established the moment X3DH runs, but the
// peer does not hold its half until it has received and processed our initial
// (handshake) envelope. Between those two points the session must NOT be used to
// send ordinary ratchet messages — the peer would reject them, and worse, the
// send path would keep taking the established branch forever, poisoning the
// session. pendingInits records the exact envelope to (re)send until the peer
// acks it; only then does the session become usable for ordinary messages.

// pendingInit is the durable record of an unacknowledged X3DH handshake.
type pendingInit struct {
	// Envelope is the marshaled protocol.InitialRatchetEnvelope to resend verbatim
	// (reissuing would reserve a fresh one-time prekey and risk forking sessions).
	Envelope []byte `json:"envelope"`
	// MsgID is the outbox id of the message this handshake carries, so a different
	// queued message to the same peer waits rather than clobbering the handshake.
	MsgID string `json:"msg_id"`
}

// pendingInitFor returns the unacked handshake for a peer, if any.
func (s *Server) pendingInitFor(account string) (pendingInit, bool) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	b, ok := s.pendingInits[account]
	if !ok {
		return pendingInit{}, false
	}
	var pi pendingInit
	if err := json.Unmarshal(b, &pi); err != nil {
		return pendingInit{}, false
	}
	return pi, true
}

// setPendingInit durably records an unacked handshake before it goes on the wire,
// so a crash between the wire write and the ack still resends (idempotently)
// rather than treating the never-delivered session as usable.
func (s *Server) setPendingInit(account string, pi pendingInit) error {
	b, err := json.Marshal(pi)
	if err != nil {
		return err
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.pendingInits == nil {
		s.pendingInits = map[string][]byte{}
	}
	s.pendingInits[account] = b
	s.persistLocked()
	return nil
}

// clearPendingInit records that a peer has acked our handshake; the session is
// now usable for ordinary messages.
func (s *Server) clearPendingInit(account string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if _, ok := s.pendingInits[account]; !ok {
		return
	}
	delete(s.pendingInits, account)
	s.persistLocked()
}

// initAlreadyProcessed reports whether sig matches the signature of the last
// init we processed from account — i.e. this is an ack-lost resend of a
// handshake we already established, not a fresh one. Keyed on the signature
// rather than the one-time prekey so it still recognises the resend after the
// prekey has been reclaimed by cleanup or the session has survived a restart.
func (s *Server) initAlreadyProcessed(account string, sig []byte) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	prev, ok := s.processedInits[account]
	return ok && bytes.Equal(prev, sig)
}

// --- send orchestration ---

// outboundIdentity returns the account a peer `to` currently knows us by and the
// Ed25519 signing key that vouches for it, for stamping an outbound message's
// Sender/AAD/signature. Because the peer derives our verifying key FROM the
// Sender string, an alias Sender is only accepted if signed with that alias's
// key — so the account and the key are returned together and must be used
// together.
//
// A contact with an empty MyAccountKnown — the pre-rotation default, and every
// contact until a rotation of ours is acked — is addressed as our PRIMARY
// account with the primary key, so behaviour is unchanged until rotation goes
// live. A NON-empty MyAccountKnown is honoured strictly: it NEVER falls back to
// the primary (that would re-leak the permanent address to a contact who only
// knows an alias of ours), and its signing key MUST be resident. If the alias
// has aged past its grace window and been swept from the live set, the send
// fails — the documented orphan trade-off, failing loudly rather than silently
// leaking the primary. Takes sessMu.
func (s *Server) outboundIdentity(idn *identity.Identity, to string) (string, ed25519.PrivateKey, error) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[to]
	if !ok || c.MyAccountKnown == "" {
		return idn.AccountNumber(), idn.Keys.Signing.Private, nil
	}
	kp, ok := s.aliasSigningKeys[c.MyAccountKnown]
	if !ok {
		return "", nil, fmt.Errorf("send to %s: alias %s no longer live (contact orphaned by address rotation)", to, c.MyAccountKnown)
	}
	return c.MyAccountKnown, kp.Private, nil
}

// sendV2 delivers one message under v2. If a session is already established it
// sends a plain ratchet message; otherwise it fetches the peer's bundle, runs
// X3DH, and sends an initial (handshake) envelope. There is deliberately NO
// silent fallback to v1 on an establishment failure — with no legacy peers, a
// transient bundle-fetch or handshake error must fail the send so the outbox
// retries, rather than quietly dropping forward secrecy.
//
// One establishment per peer is assumed to be in flight at a time. The outbox
// delivers messages concurrently, but the common case is a single message to a
// new contact; two messages racing to establish the SAME new peer in one tick
// would each fetch a bundle and the later init would win. That wastes a one-time
// prekey but does not corrupt state, and the pending-init machinery below makes a
// single message's retries safe, which is the case that actually recurs.
func (s *Server) sendV2(ctx context.Context, dialer tor.Dialer, idn *identity.Identity, to, msgID, text string, reply protocol.Reply) error {
	payload := protocol.EncodePayload(msgID, text, reply)
	// Resolve, once, the account this peer knows us by and the key that vouches
	// for it. Sender, AAD, and signature MUST all carry the SAME account (the peer
	// derives our verifying key from the Sender string), so they move together.
	// Defaults to our primary account+key until a rotation of ours is acked.
	myAcct, signer, err := s.outboundIdentity(idn, to)
	if err != nil {
		return err
	}
	aad := protocol.RatchetAAD(myAcct, to)
	key := session.SessionKeyFor(to, "")

	mgr := s.ratchetMgr()
	if mgr == nil {
		return fmt.Errorf("locked")
	}

	// A handshake is outstanding for this peer: they have not yet acked our X3DH
	// init, so the session is not usable for ordinary messages.
	if pi, awaiting := s.pendingInitFor(to); awaiting {
		if pi.MsgID != msgID {
			// A different queued message must wait until the handshake lands, or it
			// would be sent on a session the peer does not hold yet.
			return fmt.Errorf("still establishing session with %s", to)
		}
		// Resend the exact handshake. If the peer already processed it and only the
		// ack was lost, its init handler acks idempotently (same one-time prekey).
		var env protocol.InitialRatchetEnvelope
		if err := json.Unmarshal(pi.Envelope, &env); err != nil {
			return fmt.Errorf("decode pending init: %w", err)
		}
		if err := protocol.SendRatchetInit(ctx, dialer, to, env); err != nil {
			return err
		}
		s.clearPendingInit(to)
		return nil
	}

	if sess, ok := mgr.GetOrLoadSession(key); ok && sess.IsEstablished() {
		as := &ratchetSession{sess}
		box, hdr, err := as.Encrypt(payload, aad)
		if err != nil {
			return fmt.Errorf("ratchet encrypt: %w", err)
		}
		// Persist the advanced sending chain BEFORE the message goes on the wire.
		if err := s.saveRatchetSession(key); err != nil {
			return fmt.Errorf("persist session: %w", err)
		}
		sig := ed25519.Sign(signer, protocol.RatchetMsgSigningBlob(myAcct, to, hdr.HeaderBytes()))
		env := protocol.RatchetEnvelope{Sender: myAcct, Ratchet: hdr, Sig: sig, Box: box}
		return protocol.SendRatchetMessage(ctx, dialer, to, env)
	}

	// Establish as initiator: fetch bundle, X3DH, send the first (init) message.
	// The X3DH handshake (challenge, bundle fetch, init signing blob) is bound to
	// our primary account, so a fresh session is always bootstrapped under the
	// primary. A contact who has acked a rotation of ours (non-empty
	// MyAccountKnown) already holds an established session; if one is somehow being
	// re-established here, bootstrapping it as the primary would disclose the
	// permanent address the rotation hides. Fail loudly instead — establishing as
	// an alias is Phase-F (invite-code bootstrap) work, not this path.
	if myAcct != idn.AccountNumber() {
		return fmt.Errorf("cannot re-establish session with %s as alias %s: alias-bootstrap unsupported", to, myAcct)
	}
	// The guard above established myAcct == primary on this branch, so bootstrapping
	// under the primary identity is correct here (alias-bootstrap is Phase-F work).
	// If that guard ever moves, this call silently reintroduces the primary leak.
	bundle, ch, err := protocol.FetchPrekeyBundle(ctx, dialer, idn.AccountNumber(), idn.Keys.Signing.Private, to)
	if err != nil {
		return err // outbox retries; no v1 fallback
	}
	as, init, err := s.establishInitiatorSession(idn, to, bundle, ch)
	if err != nil {
		return err
	}
	box, hdr, err := as.Encrypt(payload, aad)
	if err != nil {
		return fmt.Errorf("ratchet encrypt: %w", err)
	}
	if err := s.saveRatchetSession(key); err != nil {
		return fmt.Errorf("persist session: %w", err)
	}
	sig := ed25519.Sign(idn.Keys.Signing.Private, protocol.RatchetInitSigningBlob(idn.AccountNumber(), to, init, hdr.HeaderBytes()))
	env := protocol.InitialRatchetEnvelope{Sender: idn.AccountNumber(), Init: init, Ratchet: hdr, Sig: sig, Box: box}
	// Record the handshake as pending BEFORE the wire write: if the send fails, or
	// a crash follows a send that actually landed, the retry resends this exact
	// envelope rather than treating the unacked session as established. Only a
	// successful ack clears it and unlocks ordinary sends.
	envBytes, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encode init: %w", err)
	}
	if err := s.setPendingInit(to, pendingInit{Envelope: envBytes, MsgID: msgID}); err != nil {
		return fmt.Errorf("persist pending init: %w", err)
	}
	if err := protocol.SendRatchetInit(ctx, dialer, to, env); err != nil {
		return err // pending init persisted; a retry resends it
	}
	s.clearPendingInit(to)
	return nil
}

// sendSealedOverSessionV2 seals an already-encoded plaintext payload over an
// ESTABLISHED ratchet session to `to` and sends it, stamped as the account `to`
// knows us by (outboundIdentity). Unlike sendV2 it NEVER establishes a new
// session and never touches pendingInits: a rotation or its ack only ever
// travels to a contact we already share a live session with. It returns an error
// (locked / no established session / encrypt / wire failure) so a caller's resend
// logic can retry. Like sendV2 it persists the advanced sending chain before the
// message goes on the wire.
func (s *Server) sendSealedOverSessionV2(ctx context.Context, dialer tor.Dialer, idn *identity.Identity, to string, pt []byte) error {
	myAcct, signer, err := s.outboundIdentity(idn, to)
	if err != nil {
		return err
	}
	aad := protocol.RatchetAAD(myAcct, to)
	key := session.SessionKeyFor(to, "")
	mgr := s.ratchetMgr()
	if mgr == nil {
		return fmt.Errorf("locked")
	}
	sess, ok := mgr.GetOrLoadSession(key)
	if !ok || !sess.IsEstablished() {
		return fmt.Errorf("no established session with %s", to)
	}
	as := &ratchetSession{sess}
	box, hdr, err := as.Encrypt(pt, aad)
	if err != nil {
		return fmt.Errorf("ratchet encrypt: %w", err)
	}
	if err := s.saveRatchetSession(key); err != nil {
		return fmt.Errorf("persist session: %w", err)
	}
	sig := ed25519.Sign(signer, protocol.RatchetMsgSigningBlob(myAcct, to, hdr.HeaderBytes()))
	env := protocol.RatchetEnvelope{Sender: myAcct, Ratchet: hdr, Sig: sig, Box: box}
	return protocol.SendRatchetMessage(ctx, dialer, to, env)
}

// --- receive handlers ---

// handleP2PRatchetInit receives the first v2 message of a session: verify the
// signature, gate on accepted-contact, THEN establish (consuming a prekey) and
// decrypt. The gate precedes prekey consumption so a stranger can never drain
// the one-time-prekey pool.
func (s *Server) handleP2PRatchetInit(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	idn := s.currentIdentity()
	if peer == nil || idn == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var e protocol.InitialRatchetEnvelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&e); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	senderEd, err := identity.AccountNumberFromString(e.Sender)
	if err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	// The initiator signed the handshake to whichever of our accounts they dialed
	// (the primary, or an alias-of-us during a rotation grace window). Discover which
	// from the signature so the AAD below matches; a handshake to none of our live
	// accounts is forged or misaddressed and rejected.
	recipient, matched := "", false
	headerBytes := e.Ratchet.HeaderBytes()
	for _, r := range s.recipientCandidates(idn) {
		if ed25519.Verify(senderEd, protocol.RatchetInitSigningBlob(e.Sender, r, e.Init, headerBytes), e.Sig) {
			recipient, matched = r, true
			break
		}
	}
	if !matched {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	// Gate BEFORE consuming any prekey.
	if !s.hookAllowMessage(e.Sender) {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	// Bind the initiator's claimed X25519 identity to the DH key we already hold
	// for this contact, if any — the signature proves the Ed account owns the
	// claimed key, this proves it's the same key we added.
	if !s.ratchetIdentityMatches(e.Sender, e.Init.IdentityDHPub) {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	// Idempotent duplicate handshake: the initiator resends the byte-identical
	// init until we ack it, so an init whose signature matches one we already
	// processed is a resend whose ack was lost. Ack it again without
	// re-establishing, re-consuming a prekey, or re-delivering the message (which
	// was delivered the first time). The signature is the key — not the one-time
	// prekey — because the prekey's row is dropped by cleanup once consumed, so an
	// OTP-based check stops recognising the resend after the responder's next
	// unlock, reviving the poisoning it was meant to prevent. Verified signature +
	// the accepted gate above mean only the genuine sender can reach this point.
	if s.initAlreadyProcessed(e.Sender, e.Sig) {
		w.WriteHeader(http.StatusOK)
		return
	}

	as, err := s.establishResponderSession(idn, e)
	if err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	aad := protocol.RatchetAAD(e.Sender, recipient)
	pt, err := as.Decrypt(e.Box, e.Ratchet, aad)
	if err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	if len(pt) > maxRatchetPlaintext {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	if err := s.saveRatchetSession(session.SessionKeyFor(e.Sender, "")); err != nil {
		http.Error(w, "rejected", http.StatusInternalServerError)
		return
	}
	msgID, text, reply := protocol.DecodePayloadFull(pt)
	s.deliverMessage(e.Sender, msgID, text, reply)
	// The handshake's signature was recorded durably inside establishResponderSession
	// (atomically with consuming the one-time prekey), so an ack-lost resend of this
	// exact init is already recognised and acked idempotently above.
	w.WriteHeader(http.StatusOK)
}

// handleP2PRatchetMessage receives a v2 message on an already-established
// session and hands it to the peer's ratchet receive path.
func (s *Server) handleP2PRatchetMessage(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	if peer == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var e protocol.RatchetEnvelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&e); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := peer.ReceiveRatchet(e, ratchetSessionManager{s}); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleP2PPrekeyBundle serves our v2 prekey bundle to an accepted contact,
// consuming a one-time prekey. Gated exactly like the contact-profile endpoint:
// verify a fresh challenge nonce + the caller's signature, then the accepted-
// contact status check, then build+consume. A stranger gets a uniform reject.
func (s *Server) handleP2PPrekeyBundle(w http.ResponseWriter, r *http.Request) {
	peer := s.currentPeer()
	idn := s.currentIdentity()
	if peer == nil || idn == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req protocol.PrekeyBundleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Resolve which account (and signing key) to serve the bundle AS *before* the
	// build hook runs — the build consumes a one-time prekey, so an unresolvable
	// responder (a live alias whose key is not resident) must reject here, not after
	// burning an OTP. A client that dialed an alias verifies the bundle against that
	// alias account, so the signed prekey is re-signed under the resolved key and
	// IdentityPub set to it; on the primary the re-sign is a deterministic no-op.
	recipient, signPriv, err := s.responderForRequest(idn, r)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	recipientEd, err := identity.AccountNumberFromString(recipient)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	build := func() (crypto.PrekeyBundle, error) {
		b, err := s.buildBundleForContact()
		if err != nil {
			return crypto.PrekeyBundle{}, err
		}
		return crypto.ReSignBundleForIdentity(b, recipientEd, signPriv)
	}
	bundle, err := peer.ServePrekeyBundle(req, s.hookIsAcceptedContact, build)
	if err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

// buildBundleForContact builds+persists a prekey bundle (consuming a one-time
// prekey). Passed to ServePrekeyBundle, invoked only after the nonce+signature
// verify and the accepted-contact gate pass.
func (s *Server) buildBundleForContact() (crypto.PrekeyBundle, error) {
	idn := s.currentIdentity()
	if idn == nil {
		return crypto.PrekeyBundle{}, fmt.Errorf("locked")
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	bundle, err := s.buildBundleLocked(idn)
	if err != nil {
		return crypto.PrekeyBundle{}, err
	}
	s.persistLocked()
	return bundle, nil
}

// ratchetIdentityMatches reports whether the X25519 identity key claimed in an
// init envelope matches the DH key we already hold for that contact. If we hold
// no DH key for them yet (nothing to compare against), it accepts — the envelope
// signature still binds the key to the sender's Ed account.
func (s *Server) ratchetIdentityMatches(account string, claimedDH []byte) bool {
	if len(claimedDH) != 32 {
		return false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[account]
	if !ok || len(c.DHPub) == 0 {
		return true
	}
	return string(c.DHPub) == string(claimedDH)
}

// hookIsAcceptedContact reports whether an account is an accepted contact. Pure
// read (no trust-state mutation, unlike hookAllowMessage), so it is safe as the
// gate for serving a prekey bundle.
func (s *Server) hookIsAcceptedContact(account string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	c, ok := s.contacts[account]
	return ok && c.Status == chatstore.StatusAccepted
}

// maxRatchetPlaintext bounds a decrypted v2 payload, mirroring the v1 cap.
const maxRatchetPlaintext = 16 * 1024
