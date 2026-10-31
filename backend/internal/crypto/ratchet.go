package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Double Ratchet constants.
const (
	MaxSkip       = 1000  // maximum number of messages that can be skipped
	MaxSkipKeys   = 10000 // maximum number of skipped message keys to store
	RootKeyLen    = 32
	ChainKeyLen   = 32
	MessageKeyLen = 32
)

// MessageHeader is the unencrypted header attached to every ratchet message.
// It contains the information the receiver needs to advance the receiving chain.
// The header is authenticated as AAD but not encrypted.
type MessageHeader struct {
	ProtocolVersion uint16 `json:"v"`    // protocol version
	SessionID       []byte `json:"sid"`  // session identifier
	RatchetPub      []byte `json:"rp"`   // sender's current ratchet public key
	PrevChainLen    uint32 `json:"pcl"`  // number of messages in the previous sending chain
	MsgNum          uint32 `json:"mn"`   // message number in the current sending chain
	MessageID       []byte `json:"mid"`  // unique message identifier
}

// HeaderBytes returns the canonical byte encoding of the header for use as AAD.
func (h *MessageHeader) HeaderBytes() []byte {
	return signParts(
		u16Bytes(h.ProtocolVersion),
		h.SessionID,
		h.RatchetPub,
		u32Bytes(h.PrevChainLen),
		u32Bytes(h.MsgNum),
		h.MessageID,
	)
}

// RatchetSession holds the Double Ratchet state for a single peer-to-peer
// session. Each (account, device) pair has its own independent session.
//
// Follows the Signal Double Ratchet spec (Section 3).
type RatchetSession struct {
	mu sync.Mutex

	// Root key
	RootKey [32]byte

	// Chain keys
	SendingChain   [32]byte
	ReceivingChain [32]byte

	// Ratchet keypairs
	LocalRatchetPriv  [32]byte
	LocalRatchetPub   [32]byte
	RemoteRatchetPub  [32]byte

	// Message counters
	SendCounter   uint32
	RecvCounter   uint32
	PrevSendCount uint32 // messages in the previous sending chain

	// Skipped message keys
	SkippedKeys map[SkippedKeyID][32]byte

	// Session identifier
	SessionID []byte

	// Protocol version
	Version uint16

	// Established reports whether the session has a usable SENDING chain, i.e.
	// whether Encrypt can produce a message. The initiator (Alice) has one from
	// creation (KDF_RK during init yields CKs). The responder (Bob) has none
	// until his first receive runs a DH ratchet, which derives his sending chain
	// — so Bob can Decrypt an inbound message before he is "established" for
	// sending, but must not Encrypt until then.
	Established bool
}

// SkippedKeyID identifies a skipped message key by ratchet public key and message number.
type SkippedKeyID struct {
	RatchetPub [32]byte
	MsgNum     uint32
}

// NewRatchetSession creates a new ratchet session following the Signal Double
// Ratchet initialization (Section 3.3).
//
// For the initiator (Alice):
//   - Generates a fresh ratchet keypair
//   - Performs an initial DH ratchet: RK, CKs = KDF_RK(SK, DH(Alice_rk, Bob_static))
//   - CKr = None
//
// For the responder (Bob):
//   - Uses his static X25519 key as the ratchet key (DHs)
//   - RK = SK (no DH ratchet during init)
//   - CKs = None, CKr = None
//
// bobStaticPub and bobStaticPriv are Bob's static X25519 keypair (from BIP39
// seed at path m/0'/1'). Alice uses bobStaticPub for the initial DH. Bob uses
// bobStaticPriv as his ratchet key.
func NewRatchetSession(rootSecret []byte, sessionID []byte, isInitiator bool,
	bobStaticPub [32]byte, bobStaticPriv [32]byte) (*RatchetSession, error) {

	s := &RatchetSession{
		SkippedKeys: make(map[SkippedKeyID][32]byte),
		SessionID:   sessionID,
		Version:     2,
	}

	if isInitiator {
		// Alice (RatchetInitAlice):
		// state.DHs = GENERATE_DH()
		// state.DHr = bob_dh_public_key
		// state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
		// state.CKr = None
		priv, pub, err := generateRatchetKeypair()
		if err != nil {
			return nil, fmt.Errorf("generate ratchet keypair: %w", err)
		}
		copy(s.LocalRatchetPriv[:], priv[:])
		s.LocalRatchetPub = pub
		s.RemoteRatchetPub = bobStaticPub

		dh, err := curve25519.X25519(priv[:], bobStaticPub[:])
		if err != nil {
			return nil, fmt.Errorf("initial dh: %w", err)
		}
		rk, cks, err := kdfRK(rootSecret[:], dh)
		if err != nil {
			return nil, fmt.Errorf("initial kdf: %w", err)
		}
		copy(s.RootKey[:], rk[:])
		copy(s.SendingChain[:], cks[:])
		s.Established = true // Alice has a sending chain from init.
	} else {
		// Bob (RatchetInitBob):
		// state.DHs = bob_dh_key_pair
		// state.DHr = None
		// state.RK = SK
		// state.CKs = None
		// state.CKr = None
		copy(s.LocalRatchetPriv[:], bobStaticPriv[:])
		s.LocalRatchetPub = x25519PublicKey(bobStaticPriv[:])
		copy(s.RootKey[:], rootSecret)
	}

	return s, nil
}

// kdfRK implements the Signal Double Ratchet KDF_RK function (Section 3.1).
// KDF_RK(rk, dh_out) returns (32-byte root key, 32-byte chain key) as the
// output of applying a KDF keyed by root key rk to a DH output dh_out.
//
// Uses HKDF-SHA256 with rk as IKM and dh_out as salt, per Signal's recommendation
// (Section 7.2): KDF_RK(rk, dh_out) = HKDF(rk, dh_out).
func kdfRK(rk, dhOut []byte) (newRootKey [32]byte, chainKey [32]byte, err error) {
	r := hkdf.New(sha256.New, rk, dhOut, []byte("Molepipe-Ratchet-v1"))
	out := make([]byte, 64) // 32 root + 32 chain
	if _, err := io.ReadFull(r, out); err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("kdf_rk: %w", err)
	}
	copy(newRootKey[:], out[:32])
	copy(chainKey[:], out[32:])
	return newRootKey, chainKey, nil
}

// DHRatchet implements the Signal Double Ratchet DHratchet function (Section 3.5).
//
// DHratchet(state, header):
//
//	state.DHr = header.dh
//	state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
//	state.DHs = GENERATE_DH()
//	state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
func (s *RatchetSession) DHRatchet(remoteRatchetPub [32]byte) error {
	// Step 1: Receive ratchet — derive receiving chain
	dh1, err := curve25519.X25519(s.LocalRatchetPriv[:], remoteRatchetPub[:])
	if err != nil {
		return fmt.Errorf("ratchet dh1: %w", err)
	}
	rk, ckR, err := kdfRK(s.RootKey[:], dh1)
	if err != nil {
		return fmt.Errorf("ratchet kdf1: %w", err)
	}
	copy(s.RootKey[:], rk[:])
	copy(s.ReceivingChain[:], ckR[:])

	// Step 2: Generate new ratchet keypair and derive sending chain
	s.PrevSendCount = s.SendCounter
	s.SendCounter = 0
	s.RecvCounter = 0
	s.RemoteRatchetPub = remoteRatchetPub

	priv, pub, err := generateRatchetKeypair()
	if err != nil {
		return fmt.Errorf("generate ratchet keypair: %w", err)
	}
	dh2, err := curve25519.X25519(priv[:], remoteRatchetPub[:])
	if err != nil {
		return fmt.Errorf("ratchet dh2: %w", err)
	}
	rk2, ckS, err := kdfRK(s.RootKey[:], dh2)
	if err != nil {
		return fmt.Errorf("ratchet kdf2: %w", err)
	}
	copy(s.RootKey[:], rk2[:])
	copy(s.SendingChain[:], ckS[:])
	copy(s.LocalRatchetPriv[:], priv[:])
	s.LocalRatchetPub = pub
	s.Established = true // a DH ratchet always derives a fresh sending chain.

	return nil
}

// AdvanceSendingChain performs a symmetric ratchet step on the sending chain.
// Returns the message key for encrypting the next message.
func (s *RatchetSession) AdvanceSendingChain() ([32]byte, error) {
	ck, mk, err := kdfCK(s.SendingChain[:])
	if err != nil {
		return [32]byte{}, err
	}
	copy(s.SendingChain[:], ck[:])
	s.SendCounter++
	return mk, nil
}

// AdvanceReceivingChain performs a symmetric ratchet step on the receiving chain.
// Returns the message key for decrypting the next message.
func (s *RatchetSession) AdvanceReceivingChain(msgNum uint32) ([32]byte, error) {
	if msgNum < s.RecvCounter {
		return [32]byte{}, fmt.Errorf("message number %d already received", msgNum)
	}
	// Bound the skip. Without this a single header claiming a large MsgNum forces
	// (msgNum - RecvCounter) HMAC derivations and that many stored keys — a remote
	// CPU+memory DoS reachable by any accepted contact. MaxSkip caps the gap for
	// one message; MaxSkipKeys caps the total retained across gaps. The caller
	// (Decrypt) rolls back on this error, so a rejected header mutates nothing.
	if err := s.checkSkipBound(s.RecvCounter, msgNum); err != nil {
		return [32]byte{}, err
	}
	// Skip ahead if needed, retaining each intermediate key for out-of-order arrival.
	for i := s.RecvCounter; i < msgNum; i++ {
		ck, mk, err := kdfCK(s.ReceivingChain[:])
		if err != nil {
			return [32]byte{}, err
		}
		copy(s.ReceivingChain[:], ck[:])
		id := SkippedKeyID{RatchetPub: s.RemoteRatchetPub, MsgNum: i}
		s.SkippedKeys[id] = mk
	}
	// Derive the target message key
	ck, mk, err := kdfCK(s.ReceivingChain[:])
	if err != nil {
		return [32]byte{}, err
	}
	copy(s.ReceivingChain[:], ck[:])
	s.RecvCounter = msgNum + 1
	return mk, nil
}

// harvestReceivingChain advances the CURRENT receiving chain up to (not
// including) `until`, retaining every intermediate key as a skipped key. It is
// called just before a DH ratchet replaces the receiving chain, so messages
// still in flight from the previous chain (indices RecvCounter..until-1, where
// `until` is the sender's advertised previous-chain length PN) remain
// decryptable. Without it, a ratchet step silently drops those keys — the 5d
// message-loss bug. Bounded like AdvanceReceivingChain; the caller rolls back
// on error.
func (s *RatchetSession) harvestReceivingChain(until uint32) error {
	if until <= s.RecvCounter {
		return nil // nothing outstanding in the current chain
	}
	if err := s.checkSkipBound(s.RecvCounter, until); err != nil {
		return err
	}
	for i := s.RecvCounter; i < until; i++ {
		ck, mk, err := kdfCK(s.ReceivingChain[:])
		if err != nil {
			return err
		}
		copy(s.ReceivingChain[:], ck[:])
		s.SkippedKeys[SkippedKeyID{RatchetPub: s.RemoteRatchetPub, MsgNum: i}] = mk
	}
	s.RecvCounter = until
	return nil
}

// checkSkipBound rejects a skip whose gap exceeds MaxSkip or whose retained
// keys would exceed MaxSkipKeys.
func (s *RatchetSession) checkSkipBound(from, to uint32) error {
	if to <= from {
		return nil
	}
	gap := to - from
	if gap > MaxSkip {
		return fmt.Errorf("skip of %d exceeds MaxSkip %d", gap, MaxSkip)
	}
	if len(s.SkippedKeys)+int(gap) > MaxSkipKeys {
		return fmt.Errorf("skipped-key store would exceed MaxSkipKeys %d", MaxSkipKeys)
	}
	return nil
}

// TrySkippedKey attempts to find a skipped message key for the given header.
func (s *RatchetSession) TrySkippedKey(header MessageHeader) ([32]byte, bool) {
	var ratchetPub [32]byte
	copy(ratchetPub[:], header.RatchetPub)
	id := SkippedKeyID{RatchetPub: ratchetPub, MsgNum: header.MsgNum}
	key, ok := s.SkippedKeys[id]
	if ok {
		delete(s.SkippedKeys, id)
	}
	return key, ok
}

// Encrypt advances the sending chain and seals plaintext under the derived
// message key, returning the wire header the receiver needs. It holds the
// session mutex so concurrent sends on one session are serialized. Errors only
// if the session has no sending chain yet (a responder that hasn't received).
//
// The message number is the sending counter BEFORE the advance; the receiver
// re-derives the same key by advancing its receiving chain to that number and
// uses the same number to reconstruct the deterministic nonce.
func (s *RatchetSession) Encrypt(plaintext, aad []byte) ([]byte, MessageHeader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.Established {
		return nil, MessageHeader{}, fmt.Errorf("session not established for sending")
	}
	msgNum := s.SendCounter
	mk, err := s.AdvanceSendingChain() // increments SendCounter
	if err != nil {
		return nil, MessageHeader{}, err
	}
	box, err := SealRatchet(mk, plaintext, aad, msgNum)
	if err != nil {
		return nil, MessageHeader{}, err
	}
	hdr := MessageHeader{
		ProtocolVersion: s.Version,
		SessionID:       append([]byte(nil), s.SessionID...),
		RatchetPub:      append([]byte(nil), s.LocalRatchetPub[:]...),
		PrevChainLen:    s.PrevSendCount,
		MsgNum:          msgNum,
	}
	return box, hdr, nil
}

// Decrypt opens a ratchet message, advancing the session as needed for an
// in-order, out-of-order (skipped-key), or new-chain (DH ratchet) arrival.
//
// It is TRANSACTIONAL: every state mutation is rolled back if the AEAD open
// fails. This matters because the open runs only after the receiving chain has
// been advanced and (for a new chain) a DH ratchet performed — and anyone who
// can post a signed envelope (any accepted contact, per the sig+AllowMessage
// gate upstream) could otherwise replay a valid header with a garbage body to
// permanently desynchronize a live session. On failure the session is byte-for-
// byte what it was before the call.
func (s *RatchetSession) Decrypt(box []byte, hdr MessageHeader, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rp [32]byte
	copy(rp[:], hdr.RatchetPub)

	// Case 1: a key we already skipped (out-of-order arrival). Open BEFORE
	// deleting, so a bad body leaves the skipped-key store intact.
	id := SkippedKeyID{RatchetPub: rp, MsgNum: hdr.MsgNum}
	if mk, ok := s.SkippedKeys[id]; ok {
		pt, err := OpenRatchet(mk, box, aad, hdr.MsgNum)
		if err != nil {
			return nil, err
		}
		delete(s.SkippedKeys, id)
		return pt, nil
	}

	// Case 2/3: advance the live chain(s). Snapshot first so any failure — a
	// skip-bound rejection, a DH error, or a failed open — rolls back cleanly.
	snap := s.snapshot()

	if rp != s.RemoteRatchetPub {
		// New sending chain from the peer: first harvest the outstanding keys of
		// the current receiving chain (up to the peer's previous-chain length),
		// THEN ratchet. Order matters — DHRatchet replaces the receiving chain.
		if err := s.harvestReceivingChain(hdr.PrevChainLen); err != nil {
			s.restore(snap)
			return nil, err
		}
		if err := s.DHRatchet(rp); err != nil {
			s.restore(snap)
			return nil, err
		}
	}

	mk, err := s.AdvanceReceivingChain(hdr.MsgNum)
	if err != nil {
		s.restore(snap)
		return nil, err
	}
	pt, err := OpenRatchet(mk, box, aad, hdr.MsgNum)
	if err != nil {
		s.restore(snap)
		return nil, err
	}
	return pt, nil
}

// IsEstablished reports whether the session can encrypt (has a sending chain).
func (s *RatchetSession) IsEstablished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Established
}

// ratchetSnapshot holds a rollback copy of every field Decrypt may mutate.
// The mutex is deliberately excluded (it is held across the transaction).
type ratchetSnapshot struct {
	rootKey, sendingChain, receivingChain             [32]byte
	localRatchetPriv, localRatchetPub, remoteRatchetPub [32]byte
	sendCounter, recvCounter, prevSendCount           uint32
	established                                       bool
	skipped                                           map[SkippedKeyID][32]byte
}

func (s *RatchetSession) snapshot() ratchetSnapshot {
	sk := make(map[SkippedKeyID][32]byte, len(s.SkippedKeys))
	for k, v := range s.SkippedKeys {
		sk[k] = v
	}
	return ratchetSnapshot{
		rootKey:          s.RootKey,
		sendingChain:     s.SendingChain,
		receivingChain:   s.ReceivingChain,
		localRatchetPriv: s.LocalRatchetPriv,
		localRatchetPub:  s.LocalRatchetPub,
		remoteRatchetPub: s.RemoteRatchetPub,
		sendCounter:      s.SendCounter,
		recvCounter:      s.RecvCounter,
		prevSendCount:    s.PrevSendCount,
		established:      s.Established,
		skipped:          sk,
	}
}

func (s *RatchetSession) restore(snap ratchetSnapshot) {
	s.RootKey = snap.rootKey
	s.SendingChain = snap.sendingChain
	s.ReceivingChain = snap.receivingChain
	s.LocalRatchetPriv = snap.localRatchetPriv
	s.LocalRatchetPub = snap.localRatchetPub
	s.RemoteRatchetPub = snap.remoteRatchetPub
	s.SendCounter = snap.sendCounter
	s.RecvCounter = snap.recvCounter
	s.PrevSendCount = snap.prevSendCount
	s.Established = snap.established
	s.SkippedKeys = snap.skipped
}

// kdfCK implements the Signal Double Ratchet KDF_CK function (Section 3.1/7.2).
// KDF_CK(ck) returns (32-byte chain key, 32-byte message key) by applying
// HMAC-SHA256 keyed by chain key ck to constants 0x01 and 0x02.
func kdfCK(ck []byte) (nextChainKey [32]byte, messageKey [32]byte, err error) {
	// MessageKey[n] = HMAC-SHA256(ChainKey[n], 0x01)
	mac := hmac.New(sha256.New, ck)
	mac.Write([]byte{0x01})
	copy(messageKey[:], mac.Sum(nil))

	// ChainKey[n+1] = HMAC-SHA256(ChainKey[n], 0x02)
	mac2 := hmac.New(sha256.New, ck)
	mac2.Write([]byte{0x02})
	copy(nextChainKey[:], mac2.Sum(nil))

	return nextChainKey, messageKey, nil
}

// generateRatchetKeypair generates a fresh X25519 keypair for the ratchet.
func generateRatchetKeypair() (priv [32]byte, pub [32]byte, err error) {
	p, err := generateX25519Key()
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	copy(priv[:], p)
	pub = x25519PublicKey(p)
	return priv, pub, nil
}

// SealRatchet encrypts plaintext using a ratchet-derived message key.
// The nonce is derived deterministically from the message number.
func SealRatchet(key [32]byte, plaintext, aad []byte, msgNum uint32) ([]byte, error) {
	nonce := deriveNonce(msgNum)
	return sealWithNonce(key[:], nonce, plaintext, aad)
}

// OpenRatchet decrypts ciphertext using a ratchet-derived message key.
func OpenRatchet(key [32]byte, box, aad []byte, msgNum uint32) ([]byte, error) {
	nonce := deriveNonce(msgNum)
	return openWithNonce(key[:], nonce, box, aad)
}

// deriveNonce creates a deterministic 192-bit nonce from a message number.
func deriveNonce(msgNum uint32) []byte {
	var mnBytes [4]byte
	binary.BigEndian.PutUint32(mnBytes[:], msgNum)
	r := hkdf.New(sha256.New, mnBytes[:], nil, []byte("Molepipe-Nonce-v1"))
	nonce := make([]byte, 24)
	_, _ = io.ReadFull(r, nonce)
	return nonce
}

// sealWithNonce encrypts with a specific nonce (not random).
func sealWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// openWithNonce decrypts with a specific nonce.
func openWithNonce(key, nonce, box, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, box, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return pt, nil
}

// u16Bytes encodes a uint16 as 2 big-endian bytes.
func u16Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
