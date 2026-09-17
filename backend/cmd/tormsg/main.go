// Command tormsg is the Phase 1 CLI test harness for the messenger identity
// core. It has no networking. Subcommands:
//
//	create    generate a new identity and store it encrypted
//	unlock    decrypt the stored identity and show the account number
//	recover   rebuild an identity from a recovery phrase and re-encrypt it
//	selftest  prove create → lock → unlock → recover reproduces the same keys
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/molepipe/molepipe/backend/internal/datalock"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "create":
		err = cmdCreate(args)
	case "unlock":
		err = cmdUnlock(args)
	case "recover":
		err = cmdRecover(args)
	case "selftest":
		err = cmdSelftest(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tormsg — Molepipe identity core (Phase 1)

usage:
  tormsg create     generate a new identity, store it encrypted
  tormsg unlock     decrypt the stored identity, show the account number
  tormsg recover    rebuild an identity from a recovery phrase
  tormsg selftest   prove recovery reproduces the same keys

data dir: $TORMSG_DATA_DIR (default: <user config dir>/molepipe)
`)
}

// dataDir parses an optional "--data-dir X" from args and returns the remaining
// args and the chosen directory ("" means use the default).
func dataDir(args []string) (rest []string, dir string) {
	for i := 0; i < len(args); i++ {
		if args[i] == "--data-dir" && i+1 < len(args) {
			dir = args[i+1]
			args = append(args[:i:i], args[i+2:]...)
			break
		}
	}
	return args, dir
}

// lockDataDir guards the WRITING subcommands against a running server (or a
// second CLI) sharing the directory. Two writers on one data dir do not
// conflict loudly — they produce the same silent corruption the server guards
// against: a clobbered identity, or an onion key two processes both believe
// they own.
//
// The reading subcommands deliberately do not take the lock. Reads are safe
// against the atomic renames every writer here uses, and refusing to let
// someone check their account number while the app is open would be friction
// for no gain.
func lockDataDir(dir string) (func() error, error) {
	release, err := datalock.Acquire(dir)
	if err != nil {
		return nil, err
	}
	return release, nil
}

func cmdCreate(args []string) error {
	_, dir := dataDir(args)
	store, err := identity.NewStore(dir)
	if err != nil {
		return err
	}
	// Lock the RESOLVED path: dataDir returns "" when the flag is absent and
	// the default is only applied inside NewStore, so locking before this would
	// fail on exactly the common case of running with no flags.
	release, err := lockDataDir(store.Dir)
	if err != nil {
		return err
	}
	defer release()
	if store.Exists() {
		return fmt.Errorf("an identity already exists at %s (refusing to overwrite)", store.Path())
	}

	pw, err := readNewPassword()
	if err != nil {
		return err
	}
	defer zero(pw)

	id, err := identity.New()
	if err != nil {
		return err
	}
	if err := store.Save(id, pw); err != nil {
		return err
	}

	fmt.Println("Identity created.")
	fmt.Println("Account number:", id.AccountNumber())
	fmt.Println()
	fmt.Println("RECOVERY PHRASE — write this down and store it offline.")
	fmt.Println("It is the ONLY way to recover this identity. We cannot recover it for you.")
	fmt.Println()
	fmt.Println("  " + id.MnemonicString())
	fmt.Println()
	fmt.Println("Stored (encrypted) at:", store.Path())
	return nil
}

func cmdUnlock(args []string) error {
	_, dir := dataDir(args)
	store, err := identity.NewStore(dir)
	if err != nil {
		return err
	}
	if !store.Exists() {
		return fmt.Errorf("no identity at %s — run 'tormsg create' first", store.Path())
	}

	pw, err := readSecret("Password: ")
	if err != nil {
		return err
	}
	defer zero(pw)

	id, err := store.Load(pw)
	if err != nil {
		return err
	}
	fmt.Println("Unlocked.")
	fmt.Println("Account number:", id.AccountNumber())
	return nil
}

func cmdRecover(args []string) error {
	_, dir := dataDir(args)
	store, err := identity.NewStore(dir)
	if err != nil {
		return err
	}
	// Lock the RESOLVED path: dataDir returns "" when the flag is absent and
	// the default is only applied inside NewStore, so locking before this would
	// fail on exactly the common case of running with no flags.
	release, err := lockDataDir(store.Dir)
	if err != nil {
		return err
	}
	defer release()
	if store.Exists() {
		return fmt.Errorf("an identity already exists at %s (refusing to overwrite)", store.Path())
	}

	fmt.Fprint(os.Stderr, "Enter recovery phrase: ")
	mnemonic, err := readLine()
	if err != nil {
		return err
	}
	id, err := identity.FromMnemonic(strings.TrimSpace(mnemonic), "")
	if err != nil {
		return err
	}

	pw, err := readNewPassword()
	if err != nil {
		return err
	}
	defer zero(pw)

	if err := store.Save(id, pw); err != nil {
		return err
	}
	fmt.Println("Identity recovered.")
	fmt.Println("Account number:", id.AccountNumber())
	fmt.Println("Stored (encrypted) at:", store.Path())
	return nil
}

// cmdSelftest proves the core end to end in a throwaway data dir, then deletes
// the encrypted file and recovers purely from the phrase — proving recovery is
// independent of the stored Argon2 params. It asserts byte-equality of the keys
// along each path.
func cmdSelftest(args []string) error {
	tmp, err := os.MkdirTemp("", "tormsg-selftest-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	store, err := identity.NewStore(tmp)
	if err != nil {
		return err
	}
	pw := []byte("correct horse battery staple")

	// 1. create
	orig, err := identity.New()
	if err != nil {
		return err
	}
	if err := store.Save(orig, pw); err != nil {
		return err
	}
	fmt.Println("✓ created identity:", orig.AccountNumber())

	// 2. wrong password must fail
	if _, err := store.Load([]byte("wrong password")); err == nil {
		return fmt.Errorf("SELFTEST FAILED: wrong password unlocked the identity")
	}
	fmt.Println("✓ wrong password rejected")

	// 3. unlock with correct password, keys must match byte-for-byte
	unlocked, err := store.Load(pw)
	if err != nil {
		return fmt.Errorf("unlock failed: %w", err)
	}
	if err := assertSameKeys(orig, unlocked); err != nil {
		return fmt.Errorf("SELFTEST FAILED: unlock: %w", err)
	}
	fmt.Println("✓ unlock reproduced identical keys")

	// 4. delete the encrypted file, recover from the phrase alone
	if err := os.Remove(store.Path()); err != nil {
		return err
	}
	recovered, err := identity.FromMnemonic(orig.MnemonicString(), orig.PassphraseString())
	if err != nil {
		return fmt.Errorf("recover failed: %w", err)
	}
	if err := assertSameKeys(orig, recovered); err != nil {
		return fmt.Errorf("SELFTEST FAILED: recover: %w", err)
	}
	fmt.Println("✓ recovery from phrase (file deleted) reproduced identical keys")

	fmt.Println()
	fmt.Println("SELFTEST PASSED")
	return nil
}

func assertSameKeys(a, b *identity.Identity) error {
	if a.AccountNumber() != b.AccountNumber() {
		return fmt.Errorf("account numbers differ")
	}
	if !bytes.Equal(a.Keys.Signing.Private, b.Keys.Signing.Private) {
		return fmt.Errorf("signing private keys differ")
	}
	if !a.Keys.Signing.Public.Equal(ed25519.PublicKey(b.Keys.Signing.Public)) {
		return fmt.Errorf("signing public keys differ")
	}
	if a.Keys.DH.Private != b.Keys.DH.Private {
		return fmt.Errorf("dh private keys differ")
	}
	if a.Keys.DH.Public != b.Keys.DH.Public {
		return fmt.Errorf("dh public keys differ")
	}
	return nil
}

// readNewPassword reads a password and a confirmation and checks they match.
func readNewPassword() ([]byte, error) {
	pw, err := readSecret("Choose a password: ")
	if err != nil {
		return nil, err
	}
	confirm, err := readSecret("Confirm password: ")
	if err != nil {
		zero(pw)
		return nil, err
	}
	defer zero(confirm)
	if !bytes.Equal(pw, confirm) {
		zero(pw)
		return nil, fmt.Errorf("passwords do not match")
	}
	if len(pw) == 0 {
		zero(pw)
		return nil, fmt.Errorf("password must not be empty")
	}
	return pw, nil
}

// readSecret reads a secret without echo from an interactive terminal. When
// stdin is not a terminal (piped input for automation/testing) it reads a
// single line instead. A password is never accepted from a command-line flag,
// which would leak it into the process list and shell history.
func readSecret(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		return b, nil
	}
	line, err := readLine()
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

var stdin = bufio.NewReader(os.Stdin)

func readLine() (string, error) {
	line, err := stdin.ReadString('\n')
	if err != nil {
		if line == "" {
			return "", fmt.Errorf("read input: %w", err)
		}
		// Partial line with an error (e.g. EOF without newline): return the
		// data but also surface the error so callers know the input was
		// incomplete — critical for recovery phrases where truncation means
		// a wrong identity.
		return line, fmt.Errorf("read input: %w", err)
	}
	return line, nil
}

// zero overwrites sensitive bytes in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
