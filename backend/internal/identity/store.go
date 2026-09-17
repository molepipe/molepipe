package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// envelopeVersion is the on-disk format version of identity.enc.
const envelopeVersion = 1

// ErrNewerVersion is returned by Load when the identity file was written by a
// newer build than this one (env.Version > envelopeVersion). It is decided at
// the version check, BEFORE any decryption, so callers can distinguish it from a
// wrong password and must treat it NON-DESTRUCTIVELY: never wipe, never count it
// as a failed unlock. The backstop for a genuine downgrade is "install the newer
// build"; the data on disk is intact and must stay that way.
var ErrNewerVersion = errors.New("identity file was written by a newer app version")

// identityFile is the file name inside the data dir.
const identityFile = "identity.enc"

// envelope is the JSON structure written to disk. It is NOT secret: it carries
// the KDF parameters and salt in the clear so the file can always be reopened,
// plus the AES-GCM nonce and ciphertext. Only the mnemonic inside the
// ciphertext is sensitive.
type envelope struct {
	Version    int                 `json:"version"`
	KDF        string              `json:"kdf"`
	Argon2     crypto.Argon2Params `json:"argon2"`
	Salt       string              `json:"salt"`       // base64
	Nonce      string              `json:"nonce"`      // base64
	Ciphertext string              `json:"ciphertext"` // base64
}

// sealed is the plaintext structure that gets encrypted. The mnemonic is the
// single root of truth; keys are re-derived from it on unlock.
// Fields are []byte (not string) so crypto.Zero can clear them after use.
type sealed struct {
	Mnemonic   []byte `json:"mnemonic"`
	Passphrase []byte `json:"passphrase"`
}

// Store is encrypted identity storage rooted at a data directory. The directory
// is configurable (not hardcoded) so the same code works under Android's
// sandboxed storage later.
type Store struct {
	Dir string
	// file is the name inside Dir. Empty means identityFile. It exists so the
	// duress decoy can be stored through this exact code path: the decoy file
	// must be indistinguishable in format from a real identity file, and the
	// only way to guarantee that is to not have a second implementation.
	file string
}

// DefaultDataDir resolves the data directory: TORMSG_DATA_DIR if set, otherwise
// a "molepipe" folder under the OS user config dir. Never a hardcoded path.
func DefaultDataDir() (string, error) {
	if dir := os.Getenv("TORMSG_DATA_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(base, "molepipe"), nil
}

// NewStore returns a store at dir, falling back to DefaultDataDir if dir is "".
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		var err error
		dir, err = DefaultDataDir()
		if err != nil {
			return nil, err
		}
	}
	return &Store{Dir: dir}, nil
}

// NewStoreFile returns a store rooted at dir that reads and writes name instead
// of identity.enc, in the identical envelope format.
func NewStoreFile(dir, name string) (*Store, error) {
	s, err := NewStore(dir)
	if err != nil {
		return nil, err
	}
	s.file = name
	return s, nil
}

// Path is the full path to the identity file.
func (s *Store) Path() string {
	name := s.file
	if name == "" {
		name = identityFile
	}
	return filepath.Join(s.Dir, name)
}

// Exists reports whether an identity file is present.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.Path())
	return err == nil
}

// aad binds the ciphertext to a specific format version so an envelope can't be
// substituted across format changes. It is parameterized by version (byte-identical
// to the old hardcoded form at v=1) so that Load can reconstruct the AAD an OLDER
// file was sealed under — see openEnvelope. Contrast chatstore's aad, which is a
// frozen constant: identity's AAD legitimately tracks the version because the
// mnemonic is re-derivable, but that made a version bump un-migratable until Load
// began decrypting under aad(env.Version) rather than aad(envelopeVersion).
func aad(v int) []byte { return []byte(fmt.Sprintf("tormsg-identity-v%d", v)) }

// Save encrypts the identity's recovery phrase under the password and writes it
// atomically to disk with owner-only permissions.
func (s *Store) Save(id *Identity, password []byte) error {
	params := crypto.DefaultArgon2Params()
	salt, err := crypto.NewSalt(params)
	if err != nil {
		return err
	}
	key := crypto.DeriveKeyArgon2id(password, salt, params)
	defer crypto.Zero(key)

	plaintext, err := json.Marshal(sealed{Mnemonic: id.Mnemonic, Passphrase: id.Passphrase})
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	nonce, ciphertext, err := crypto.Seal(key, plaintext, aad(envelopeVersion))
	defer crypto.Zero(plaintext)
	if err != nil {
		return err
	}

	env := envelope{
		Version:    envelopeVersion,
		KDF:        "argon2id",
		Argon2:     params,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return atomicWrite(s.Path(), data, 0o600)
}

// Load reads and decrypts the identity file using the password. A wrong
// password fails GCM authentication and returns an error. A file written by a
// newer build returns ErrNewerVersion (before any decryption) so the caller can
// refuse non-destructively rather than treat it as a wrong password.
func (s *Store) Load(password []byte) (*Identity, error) {
	data, err := os.ReadFile(s.Path())
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	if env.Version > envelopeVersion {
		return nil, fmt.Errorf("%w: file is version %d, this build supports up to %d", ErrNewerVersion, env.Version, envelopeVersion)
	}
	s2, err := openEnvelope(env, password)
	if err != nil {
		return nil, err
	}
	// migrateSealed runs on the decrypted payload, before FromMnemonic. It is a
	// no-op at v1; the seam exists so a future format bump has one ordered place
	// to transform old plaintext, and so an unknown lower version fails closed. The
	// ceiling is envelopeVersion (the shipped window); a test can pass a higher one
	// to exercise a reserved step without this build writing it.
	if err := migrateSealed(env.Version, envelopeVersion, &s2); err != nil {
		return nil, err
	}
	id, err := FromMnemonic(string(s2.Mnemonic), string(s2.Passphrase))
	// Zero the deserialized plaintext so the mnemonic/passphrase don't persist
	// in the JSON-decoded buffers.
	crypto.Zero(s2.Mnemonic)
	crypto.Zero(s2.Passphrase)
	return id, err
}

// openEnvelope decrypts the sealed payload. It binds the AAD to the envelope's
// OWN version — aad(env.Version), NOT aad(envelopeVersion) — which is the fix
// that lets a newer build open a file written under an earlier format version.
// Were it to use the current const, a version bump would make every existing
// identity.enc permanently undecryptable, because the migrating build could no
// longer reconstruct the AAD the old file was sealed under. It is a package
// function (not a method) so a white-box test can drive it with an env.Version
// that differs from what the bytes were sealed under, proving the AAD actually
// tracks the field rather than the const.
func openEnvelope(env envelope, password []byte) (sealed, error) {
	var s2 sealed
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return s2, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return s2, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return s2, fmt.Errorf("decode ciphertext: %w", err)
	}
	key := crypto.DeriveKeyArgon2id(password, salt, env.Argon2)
	defer crypto.Zero(key)
	plaintext, err := crypto.Open(key, nonce, ciphertext, aad(env.Version))
	if err != nil {
		return s2, err
	}
	defer crypto.Zero(plaintext)
	if err := json.Unmarshal(plaintext, &s2); err != nil {
		return s2, fmt.Errorf("parse decrypted identity: %w", err)
	}
	return s2, nil
}

// migrateSealed walks an older identity payload from format version `from` up to
// `to`, applying one step per version. Production passes to=envelopeVersion (the
// shipped window), so at v1 the loop body never runs. `to` is a parameter — not the
// const — so a test can drive the reserved step (case 1) up to a version this build
// does not yet ship, mirroring protocol's version dry-run. Any lower/unknown version
// has no step and fails CLOSED — it must never load unrecognized bytes as a valid
// identity. A newer version never reaches here (Load returns ErrNewerVersion first).
func migrateSealed(from, to int, s *sealed) error {
	for v := from; v < to; v++ {
		switch v {
		case 1:
			identity1to2(s)
		default:
			return fmt.Errorf("no identity migration from format version %d", v)
		}
	}
	return nil
}

// identity1to2 is the RESERVED v1->v2 identity migration, locked in now though
// envelopeVersion is still 1 (so it is unreachable in production — migrateSealed's
// ceiling is envelopeVersion). The identity payload is only a mnemonic and an
// optional passphrase, both the irreducible root of the account, so there is nothing
// to reshape: a v1->v2 identity bump is a pure format re-stamp that must preserve the
// secret byte-for-byte. The step is intentionally empty; its presence (vs the
// fail-closed default) is what the dry-run asserts, along with the payload surviving
// untouched. The commit that ships a real v2 raises envelopeVersion to make this
// reachable and adds any real transform here.
func identity1to2(_ *sealed) {}

// atomicWrite writes data to a temp file in the same dir then renames it into
// place, so a crash mid-write can't corrupt an existing identity file.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpName, path)
}
