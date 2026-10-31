package api

import (
	"fmt"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/crypto"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// v2 prekey lifecycle parameters. Conservative for an asynchronous messenger:
// a signed prekey rotates weekly (limiting the damage window of a compromise)
// and retired ones survive a 30-day grace so a delayed offline message can
// still establish. The one-time pool is refilled toward a target when it runs
// low, and capped so a flood of establishments can't drive unbounded key-gen.
const (
	signedPrekeyRotationInterval = 7 * 24 * time.Hour
	signedPrekeyGracePeriod      = 30 * 24 * time.Hour
	oneTimePrekeyPoolSize        = 100
	oneTimePrekeyRefillThreshold = 20
	maxOneTimePrekeyPoolSize     = 200
)

// ensurePrekeysLocked makes the local prekey material valid for serving bundles:
// it generates the initial signed prekey + one-time pool on first v2 unlock,
// rotates the signed prekey when due, refills the one-time pool when low, and
// prunes expired/consumed keys. Caller holds sessMu; it mutates s.prekeys but
// does NOT persist — the caller persists once after unlock setup.
func (s *Server) ensurePrekeysLocked(idn *identity.Identity) {
	if s.prekeys == nil {
		s.prekeys = &chatstore.PrekeyState{}
	}
	if s.currentSignedPrekeyLocked() == nil {
		s.generateSignedPrekeyLocked(idn)
	} else {
		s.rotateSignedPrekeyIfDueLocked(idn)
	}
	s.deleteExpiredSignedPrekeysLocked()
	s.cleanupConsumedOTPsLocked()
	s.refillOneTimePrekeysLocked(idn)
}

// allocPrekeyIDLocked returns a fresh monotonic prekey ID.
func (s *Server) allocPrekeyIDLocked() uint32 {
	id := s.prekeys.NextPrekeyID
	s.prekeys.NextPrekeyID++
	return id
}

// currentSignedPrekeyLocked returns the active signed prekey, or nil.
func (s *Server) currentSignedPrekeyLocked() *chatstore.StoredSignedPrekey {
	if s.prekeys == nil {
		return nil
	}
	for i := len(s.prekeys.SignedPrekeys) - 1; i >= 0; i-- {
		if s.prekeys.SignedPrekeys[i].Status == "current" {
			return &s.prekeys.SignedPrekeys[i]
		}
	}
	return nil
}

// generateSignedPrekeyLocked allocates an ID, generates and signs a new signed
// prekey over THAT id (the signature and the stored id must agree, or a peer's
// VerifyBundle fails), retires the previous current one with a grace period, and
// appends it as current.
func (s *Server) generateSignedPrekeyLocked(idn *identity.Identity) {
	id := s.allocPrekeyIDLocked()
	now := time.Now()
	sp, priv, err := crypto.GenerateSignedPrekey(idn.Keys.Signing.Private, idn.Keys.Signing.Public, id, now)
	if err != nil {
		// Key generation only fails if the system RNG fails; nothing to do but
		// leave the (possibly empty) state as-is so we serve no bundle.
		return
	}
	for i := range s.prekeys.SignedPrekeys {
		if s.prekeys.SignedPrekeys[i].Status == "current" {
			t := now
			s.prekeys.SignedPrekeys[i].Status = "retired"
			s.prekeys.SignedPrekeys[i].RetiredAt = &t
		}
	}
	s.prekeys.SignedPrekeys = append(s.prekeys.SignedPrekeys, chatstore.StoredSignedPrekey{
		ID:         id,
		PublicKey:  sp.PublicKey[:],
		PrivateKey: priv,
		Signature:  sp.Signature,
		CreatedAt:  now,
		Status:     "current",
	})
	s.prekeys.PrekeyRotationAt = now.Add(signedPrekeyRotationInterval)
}

// rotateSignedPrekeyIfDueLocked rotates the signed prekey when its rotation time
// has passed.
func (s *Server) rotateSignedPrekeyIfDueLocked(idn *identity.Identity) {
	at := s.prekeys.PrekeyRotationAt
	if at.IsZero() || time.Now().Before(at) {
		return
	}
	s.generateSignedPrekeyLocked(idn)
}

// deleteExpiredSignedPrekeysLocked removes retired signed prekeys past the grace
// period, zeroing their private keys first.
func (s *Server) deleteExpiredSignedPrekeysLocked() {
	if s.prekeys == nil {
		return
	}
	kept := s.prekeys.SignedPrekeys[:0]
	for _, sp := range s.prekeys.SignedPrekeys {
		if sp.Status == "retired" && sp.RetiredAt != nil && time.Since(*sp.RetiredAt) > signedPrekeyGracePeriod {
			for i := range sp.PrivateKey {
				sp.PrivateKey[i] = 0
			}
			continue
		}
		kept = append(kept, sp)
	}
	s.prekeys.SignedPrekeys = kept
}

// unusedOneTimePrekeysLocked counts one-time prekeys still available to serve in
// a bundle — neither consumed nor already reserved by a handed-out bundle. This
// is what the refill threshold measures: reserved-but-not-yet-consumed keys are
// no longer servable, so a burst of bundle fetches correctly triggers a refill.
func (s *Server) unusedOneTimePrekeysLocked() int {
	if s.prekeys == nil {
		return 0
	}
	n := 0
	for _, otp := range s.prekeys.OneTimePrekeys {
		if !otp.Consumed && !otp.Reserved {
			n++
		}
	}
	return n
}

// refillOneTimePrekeysLocked tops the pool back up toward the target when it
// drops below the refill threshold, capped by the pool maximum.
func (s *Server) refillOneTimePrekeysLocked(idn *identity.Identity) {
	unused := s.unusedOneTimePrekeysLocked()
	if unused >= oneTimePrekeyRefillThreshold {
		return
	}
	need := oneTimePrekeyPoolSize - unused
	if room := maxOneTimePrekeyPoolSize - unused; need > room {
		need = room
	}
	now := time.Now()
	for i := 0; i < need; i++ {
		id := s.allocPrekeyIDLocked()
		otp, priv, err := crypto.GenerateOneTimePrekey(id)
		if err != nil {
			return
		}
		s.prekeys.OneTimePrekeys = append(s.prekeys.OneTimePrekeys, chatstore.StoredOneTimePrekey{
			ID:         id,
			PublicKey:  otp.PublicKey[:],
			PrivateKey: priv,
			CreatedAt:  now,
		})
	}
}

// cleanupConsumedOTPsLocked drops one-time prekeys the pool no longer needs to
// keep: those already consumed, and those reserved into a bundle whose handshake
// never arrived within the grace period. The latter reclamation matters because a
// reserved-but-unused OTP pins its slot and private key forever otherwise, so a
// stream of bundle fetches that never establish would grow the stored pool without
// bound — the same grace window used for retired signed prekeys applies here.
func (s *Server) cleanupConsumedOTPsLocked() {
	if s.prekeys == nil {
		return
	}
	kept := s.prekeys.OneTimePrekeys[:0]
	for _, otp := range s.prekeys.OneTimePrekeys {
		if otp.Consumed {
			continue
		}
		if otp.Reserved && time.Since(otp.CreatedAt) > signedPrekeyGracePeriod {
			for i := range otp.PrivateKey {
				otp.PrivateKey[i] = 0
			}
			continue
		}
		kept = append(kept, otp)
	}
	s.prekeys.OneTimePrekeys = kept
}

// buildBundleLocked assembles a prekey bundle to serve to a requesting contact,
// consuming one one-time prekey if the pool has one (the extra DH that gives the
// first message forward secrecy even before the responder replies). Caller holds
// sessMu; mutates s.prekeys (marks the OTP consumed) so the caller must persist.
func (s *Server) buildBundleLocked(idn *identity.Identity) (crypto.PrekeyBundle, error) {
	sp := s.currentSignedPrekeyLocked()
	if sp == nil {
		return crypto.PrekeyBundle{}, fmt.Errorf("no signed prekey available")
	}
	bundle := crypto.PrekeyBundle{
		IdentityPub:         idn.Keys.Signing.Public,
		SignedPrekeyID:      sp.ID,
		SignedPrekeyPub:     sp.PublicKey,
		SignedPrekeySig:     sp.Signature,
		SignedPrekeyCreated: sp.CreatedAt.UnixMilli(),
		Version:             crypto.PrekeyProtocolVersion,
	}
	for i := range s.prekeys.OneTimePrekeys {
		if !s.prekeys.OneTimePrekeys[i].Consumed && !s.prekeys.OneTimePrekeys[i].Reserved {
			id := s.prekeys.OneTimePrekeys[i].ID
			bundle.OneTimePrekeyID = &id
			bundle.OneTimePrekeyPub = s.prekeys.OneTimePrekeys[i].PublicKey
			// Reserve it — do NOT mark Consumed or delete the private here. The
			// private is needed to complete X3DH when the handshake that names
			// this prekey arrives; consumeOneTimePrekeyLocked deletes it then.
			s.prekeys.OneTimePrekeys[i].Reserved = true
			break
		}
	}
	return bundle, nil
}

// signedPrekeyPrivByIDLocked returns the private key of the signed prekey with
// the given id (current or still-retired), or nil if unknown/deleted.
func (s *Server) signedPrekeyPrivByIDLocked(id uint32) []byte {
	if s.prekeys == nil {
		return nil
	}
	for i := range s.prekeys.SignedPrekeys {
		if s.prekeys.SignedPrekeys[i].ID == id {
			return s.prekeys.SignedPrekeys[i].PrivateKey
		}
	}
	return nil
}

// consumeOneTimePrekeyLocked marks the one-time prekey with the given id consumed
// and returns its private key, or nil if unknown/already consumed. Single-use:
// the responder calls it exactly once per incoming handshake that named an OTP.
func (s *Server) consumeOneTimePrekeyLocked(id uint32) []byte {
	if s.prekeys == nil {
		return nil
	}
	for i := range s.prekeys.OneTimePrekeys {
		if s.prekeys.OneTimePrekeys[i].ID == id && !s.prekeys.OneTimePrekeys[i].Consumed {
			priv := s.prekeys.OneTimePrekeys[i].PrivateKey
			s.prekeys.OneTimePrekeys[i].Consumed = true
			s.prekeys.OneTimePrekeys[i].PrivateKey = nil
			return priv
		}
	}
	return nil
}
