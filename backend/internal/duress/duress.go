// Package duress implements the panic-code side of the duress wipe: a second
// code that, instead of unlocking, destroys the local data and opens a decoy
// account in its place.
//
// Two design points carry the whole feature, and both are about deniability
// rather than secrecy:
//
// The decoy is PRE-GENERATED at setup, not created when the code is entered.
// Generating it on the coercion path would cost a second Argon2id derivation
// and an identity generation, making a duress unlock measurably slower than a
// real one; and it would hand back a different account every time, so a
// coercer who made you unlock twice would see it. Pre-generating makes a duress
// unlock cost exactly what a real unlock costs, and produces a stable account.
//
// The file ALWAYS exists, even when no duress code has been set. An installed
// duress.enc that appears only for users who configured one would announce, to
// anyone who images the disk, that a panic code exists — which is precisely the
// fact the feature needs to hide. When unconfigured it holds a real decoy
// identity sealed under a random 32-byte code that nobody knows and nothing
// stores, so it is inert and indistinguishable from a configured one.
//
// It is written through identity.Store, in the identical envelope format as
// identity.enc, so the two files cannot be told apart by shape either.
package duress

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// FileName is the decoy blob inside the data dir.
const FileName = "duress.enc"

// MinLength is the shortest accepted duress code. It matches the PIN's floor:
// this code is typed at the same prompt, under the same threat model.
const MinLength = 6

// ErrTooShort means the requested code is below MinLength.
var ErrTooShort = fmt.Errorf("duress code must be at least %d characters", MinLength)

func store(dir string) (*identity.Store, error) { return identity.NewStoreFile(dir, FileName) }

// Ensure creates the blob if it is absent, sealed under a code nobody holds.
// Safe and cheap to call on every unlock; it does nothing once the file exists.
func Ensure(dir string) error {
	s, err := store(dir)
	if err != nil {
		return err
	}
	if s.Exists() {
		return nil
	}
	return reset(s)
}

// Set arms the duress code, generating a fresh decoy identity to go with it.
func Set(dir string, code []byte) error {
	if len(code) < MinLength {
		return ErrTooShort
	}
	s, err := store(dir)
	if err != nil {
		return err
	}
	decoy, err := identity.New()
	if err != nil {
		return err
	}
	return replace(s, decoy, code)
}

// Clear disarms the duress code by replacing the blob with an inert one. The
// file still exists afterwards — removing it would leak that a code had once
// been set, and that a user who had one has now given it up.
func Clear(dir string) error {
	s, err := store(dir)
	if err != nil {
		return err
	}
	return reset(s)
}

// Check reports whether code opens the decoy, returning the decoy identity if
// it does. A non-match is indistinguishable from any other failed unlock.
func Check(dir string, code []byte) (*identity.Identity, bool) {
	s, err := store(dir)
	if err != nil || !s.Exists() {
		return nil, false
	}
	decoy, err := s.Load(code)
	if err != nil {
		return nil, false
	}
	return decoy, true
}

// reset installs a fresh decoy under an unguessable code.
func reset(s *identity.Store) error {
	decoy, err := identity.New()
	if err != nil {
		return err
	}
	code := make([]byte, 32)
	if _, err := rand.Read(code); err != nil {
		return fmt.Errorf("generate inert duress code: %w", err)
	}
	return replace(s, decoy, code)
}

// replace scrubs any existing blob in place before writing the new one, so a
// previously-armed code's decoy cannot be recovered from the old blocks, and
// writes via the store's atomic rename so the file is never absent.
func replace(s *identity.Store, decoy *identity.Identity, code []byte) error {
	if err := wipe.Scrub(s.Path()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return s.Save(decoy, code)
}
