package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/molepipe/molepipe/backend/internal/desktop"
	"github.com/molepipe/molepipe/backend/internal/device"
	"github.com/molepipe/molepipe/backend/internal/duress"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/pin"
	"github.com/molepipe/molepipe/backend/internal/unlockguard"
	"github.com/molepipe/molepipe/backend/internal/wipe"
)

// Removing an account from a device, for someone who has lost the way back in.
//
// It requires no ACCOUNT credential — no password, no recovery phrase, no
// session — because the people who need it are by definition unable to produce
// one; that absence of s.auth is the feature, not a gap. It is NOT open to the
// world, though: like every /api route it sits behind controlGuard, so only the
// first-party UI (which holds the per-process control token) can reach it. On
// desktop loopback that is a small concession — anyone who can click the button
// can also delete the data directory, so it adds convenience rather than
// capability. On Android, where 127.0.0.1 is shared with every co-installed app,
// the control token is the whole boundary: without it a neighbouring app could
// forge Host/Origin like a native client, and this endpoint would be an
// unauthenticated account-wipe. The typed confirmation is the last bit of
// friction that stops even a legitimately-tokened call being a drive-by.

// forgetConfirmation is the word the user must type. It exists so the request
// cannot be a stray click or a mis-aimed tap on a locked device.
const forgetConfirmation = "DELETE"

// haltForWipe stops everything holding the current identity's keys, before any
// of its files are removed. Idempotent, and safe whether or not a session
// exists: the lock-screen path usually has none, but nothing prevents another
// tab holding an unlocked one, and leaving that live would keep the background
// loops dialling contacts for an account whose files are gone.
func (s *Server) haltForWipe() {
	// Cancel any pending lock-grace first: without this a grace timer armed by an
	// earlier Log out could fire minutes later and stop the FRESH onion this wipe
	// then starts for the decoy/replacement account.
	s.cancelGrace()
	s.stopOnion()
	s.clearSession()
	s.vault.lock()
	// Sweep only clears identity-linked key material; the Tor consensus cache
	// is public data and stays, so the next session starts fast.
	if s.onion != nil {
		_ = s.onion.Sweep()
	}
}

// wipeAccountFiles removes the per-account data in the data dir, ordered by how
// much a snapshot taken half-way would give away.
//
// It deliberately does NOT touch identity.enc or duress.enc: the callers differ
// there, and getting it wrong is the difference between a decoy that holds up
// and one that does not. The duress path replaces identity.enc with the decoy
// and re-arms an inert duress blob; the removal paths scrub and unlink both.
// It never touches the datalock .lock file, whose flock this process holds —
// removing it would silently disable the single-instance guard.
func (s *Server) wipeAccountFiles() {
	dir := s.store.Dir
	for _, name := range []string{
		"messages.enc",       // contacts + message history: the content that hurts
		"pin.enc",            // the PIN shortcut's own copy of the mnemonic
		unlockguard.FileName, // failed-attempt counter + erase policy: only exists on a used device
		"device.json",        // sync-linking state: proves other devices hold copies
		// The desktop shell's "already shown this notice" flag. It holds
		// nothing about the account, but it only exists once the window has
		// been closed at least once — so leaving it behind marks the directory
		// as one that has been *used*, which a fresh install is not.
		desktop.StateFile,
	} {
		_ = wipe.File(filepath.Join(dir, name))
	}
	// The run log names accounts ("outbox: <id> to <account> still
	// undelivered", "friend-accept to <account> delivered"), so a wipe that
	// left it behind would hand over the contact list it just destroyed. It is
	// emptied rather than removed: this process still holds the file open, and
	// a fresh install has one too.
	_ = wipe.Truncate(filepath.Join(dir, LogFileName))
	// Blobs held for friends. The directory goes back empty because a fresh
	// install has one, and a missing directory is a difference someone can see.
	relayDir := filepath.Join(dir, "relay")
	_ = wipe.Dir(relayDir)
	_ = os.MkdirAll(relayDir, 0o700)
	// Our own received/sent image attachments. Each is a multi-MB file that would
	// be a far worse leak than a message row if it survived a wipe. Removed
	// entirely (no fresh install has one, so unlike relay it isn't recreated).
	_ = wipe.Dir(filepath.Join(dir, "attachments"))
	// Profile-picture bytes (own avatar + cached contact avatars). Same reasoning
	// as attachments: image files that must not outlive the account. Removed
	// entirely; no fresh install has one.
	_ = wipe.Dir(filepath.Join(dir, "avatars"))
	// The start-at-login entry is the one piece of this app's state that lives
	// OUTSIDE the data directory (~/.config/autostart), so nothing above would
	// reach it. Left behind, it is a file named "Molepipe" pointing at a
	// data directory that no longer holds an account — after a duress wipe,
	// that is the wipe announcing itself to exactly the person it hides from.
	// Unconditional, and not routed through the desktop hook: an entry written
	// by the desktop build must also be removed when the wipe is triggered from
	// a plain cmd/server run against the same data directory.
	if err := desktop.RemoveEntry(); err != nil {
		log.Printf("removing the start-at-login entry: %v", err)
	}
}

// reloadDeviceState rebuilds the per-device identity the wipe removed, so
// whatever runs next does so on a fresh device key rather than the old one.
func (s *Server) reloadDeviceState() {
	dev, err := device.Load(s.store.Dir)
	if err != nil {
		return
	}
	// Swap all three per-device pointers under devMu: request handlers read them
	// concurrently (see currentDevice/currentPin/currentGuard).
	s.devMu.Lock()
	s.device = dev
	if len(dev.Seed) > 0 {
		s.pin = pin.New(s.store.Dir, dev.LocalSecret())
		s.guard = unlockguard.New(s.store.Dir, dev.LocalSecret())
	}
	s.devMu.Unlock()
}

// removeAccountFromDevice destroys the account and every local trace of it,
// leaving the data directory as it would be on a fresh install. Unlike the
// duress path there is no decoy: identity.enc and duress.enc are scrubbed and
// unlinked, and the app returns to onboarding.
func (s *Server) removeAccountFromDevice() {
	s.haltForWipe()
	// Sensitivity order. There is no replacement identity to install here, so
	// unlike the duress path nothing needs identity.enc handled up front.
	s.wipeAccountFiles()
	_ = wipe.File(s.store.Path())
	// A fresh install carries no duress blob until its first unlock, so leaving
	// one behind would make this directory distinguishable from a new one.
	_ = wipe.File(filepath.Join(s.store.Dir, duress.FileName))
	s.reloadDeviceState()
}

// handleForgetIdentity removes the account from the lock screen, for a user who
// has lost both their password and their recovery phrase. Session-less by
// necessity (no s.auth — the caller has no unlocked session), but control-token
// gated by controlGuard and origin-guarded like every other state-changing route.
func (s *Server) handleForgetIdentity(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.Confirm), forgetConfirmation) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "type " + forgetConfirmation + " to confirm",
		})
		return
	}
	s.removeAccountFromDevice()
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// handleDeleteIdentity is the same removal from inside an unlocked session (the
// "remove account from this device" control in the You tab). Requires password
// re-entry to prevent accidental or XSS-triggered account destruction.
func (s *Server) handleDeleteIdentity(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Verify the password re-enters correctly before destroying the account.
	if _, err := s.store.Load([]byte(req.Password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "incorrect password"})
		return
	}
	s.removeAccountFromDevice()
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// LogFileName is the run log inside the data directory. A packaged app has no
// terminal, so without a file on disk every diagnostic this project has relied
// on would be invisible to the person running it.
const LogFileName = "tormsg.log"
