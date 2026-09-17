package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// StateFile records what the desktop shell has already told the user, so
// one-time notices stay one-time across restarts.
//
// It holds nothing about the account. It is still removed by the wipe paths in
// internal/api, because it is only created once the window has been closed at
// least once: left behind, its mere existence marks the directory as one that
// has been used, and a directory the duress wipe is meant to pass off as a
// fresh install has never been used. Anything added here must stay
// account-independent, and must stay in that wipe list.
const StateFile = "desktop.json"

type state struct {
	// BackgroundNoticeShown records that the user has been told, once, that
	// closing the window leaves the app running.
	BackgroundNoticeShown bool `json:"background_notice_shown"`
}

// State is the persisted desktop-shell state for one data directory.
type State struct {
	path string
	mu   sync.Mutex
	st   state
}

// LoadState reads the state for dir, treating a missing or corrupt file as
// empty — a notice shown twice is a far better failure than a launch that
// aborts over a cosmetic file.
func LoadState(dir string) *State {
	s := &State{path: filepath.Join(dir, StateFile)}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.st)
	}
	return s
}

// NeedsBackgroundNotice reports whether the user still has to be told that
// closing the window does not stop the app, and records that they have been.
// It returns true at most once per data directory.
func (s *State) NeedsBackgroundNotice() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.BackgroundNoticeShown {
		return false
	}
	s.st.BackgroundNoticeShown = true
	s.save()
	return true
}

// save persists the state. Failures are ignored: the only cost is showing a
// one-time notice again next launch.
func (s *State) save() {
	if b, err := json.Marshal(s.st); err == nil {
		_ = os.WriteFile(s.path, b, 0o600)
	}
}
