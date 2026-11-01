package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// seedNicknamed installs one accepted contact whose published name and the
// user's private nickname DIFFER, which is the only arrangement that can tell a
// surface honouring the nickname apart from one that silently fell back to the
// peer's own name for themselves.
func seedNicknamed(t *testing.T, s *Server) string {
	t.Helper()
	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{
		Account: acct, Status: chatstore.StatusAccepted,
		Name: "ProfileName", Nickname: "MyNickname",
	}
	s.sessMu.Unlock()
	return acct
}

// TestNicknameWinsOnEveryGoSideNameSurface is the test that makes "the nickname
// shows up everywhere" a checked claim instead of a hope. It enumerates the
// SURFACES rather than exercising the resolver: a test that only called
// DisplayName() would pass with every one of these call sites still reading
// .Name directly. Each of these labels is produced in Go and never passes
// through app.js, so none of them is covered by the UI tests.
func TestNicknameWinsOnEveryGoSideNameSurface(t *testing.T) {
	// --- surface 1: the inbound text-message system notification -------------
	t.Run("inbound message notification", func(t *testing.T) {
		s, _ := unlocked(t)
		got := make(chan string, 4)
		s.SetInboundHook(func(_, name, _ string, _ int64, _ string) { got <- name })
		acct := seedNicknamed(t, s)
		s.sessMu.Lock()
		s.deliverInboundLocked(acct, "", "hi", time.Now(), protocol.Reply{})
		s.sessMu.Unlock()
		select {
		case name := <-got:
			if name != "MyNickname" {
				t.Fatalf("notification title = %q, want %q — the shade would show the peer's own name", name, "MyNickname")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no notification fired")
		}
	})

	// --- surface 2: the friend-request-accepted notification -----------------
	t.Run("friend accept notification", func(t *testing.T) {
		s, _ := unlocked(t)
		got := make(chan string, 4)
		s.SetFriendAcceptHook(func(name string) { got <- name })
		peer, _ := identity.New()
		acct := peer.AccountNumber()
		s.sessMu.Lock()
		s.contacts[acct] = chatstore.Contact{
			Account: acct, Status: chatstore.StatusPendingOut, ReqID: "r1",
			Name: "ProfileName", Nickname: "MyNickname",
		}
		s.sessMu.Unlock()
		if err := s.hookOnFriendAccept(acct, "ProfileName", "r1"); err != nil {
			t.Fatalf("hookOnFriendAccept: %v", err)
		}
		select {
		case name := <-got:
			if name != "MyNickname" {
				t.Fatalf("accept notification = %q, want %q", name, "MyNickname")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no accept notification fired")
		}
	})

	// --- surface 3: the author label on a group message ----------------------
	t.Run("group message author", func(t *testing.T) {
		s, _ := unlocked(t)
		acct := seedNicknamed(t, s)
		s.sessMu.Lock()
		s.groups["g1"] = chatstore.Group{
			ID: "g1", Name: "Crew", Epoch: 1,
			Members: []chatstore.GroupMember{{Account: acct, Role: chatstore.GroupRoleMember, Name: "RosterName"}},
		}
		got := s.groupAuthorNameLocked("g1", acct)
		s.sessMu.Unlock()
		if got != "MyNickname" {
			t.Fatalf("group author label = %q, want %q", got, "MyNickname")
		}
	})

	// --- surface 4: the group member roster shown in the UI ------------------
	t.Run("group member list", func(t *testing.T) {
		s, tok := unlocked(t)
		acct := seedNicknamed(t, s)
		s.sessMu.Lock()
		s.groups["g1"] = chatstore.Group{
			ID: "g1", Name: "Crew", Epoch: 1,
			Members: []chatstore.GroupMember{
				{Account: s.myAccount, Role: chatstore.GroupRoleAdmin},
				{Account: acct, Role: chatstore.GroupRoleMember, Name: "RosterName"},
			},
		}
		s.sessMu.Unlock()
		rr := s.do(t, "GET", "/api/groups/members?group=g1", "", authHdr(s, tok))
		if rr.Code != 200 {
			t.Fatalf("members: %d %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "MyNickname") {
			t.Fatalf("member list has no nickname: %s", rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "RosterName") {
			t.Fatalf("member list showed the roster name over our nickname: %s", rr.Body.String())
		}
	})

	// --- surface 7: the pending friend-request list -------------------------
	// Easy to miss, because a request is usually from a stranger with no nickname
	// to show. But someone you removed can request you again, and their nickname
	// is still on the Contact record — so this payload has to carry it, or the
	// request row and the desktop notification disagree with every other screen.
	t.Run("pending request list carries the nickname", func(t *testing.T) {
		s, tok := unlocked(t)
		peer, _ := identity.New()
		acct := peer.AccountNumber()
		s.sessMu.Lock()
		s.contacts[acct] = chatstore.Contact{
			Account: acct, Status: chatstore.StatusPendingIn,
			Name: "ProfileName", Nickname: "MyNickname",
		}
		s.sessMu.Unlock()
		rr := s.do(t, "GET", "/api/friend-requests", "", authHdr(s, tok))
		if rr.Code != 200 {
			t.Fatalf("requests: %d", rr.Code)
		}
		var out struct {
			Requests []struct {
				Account  string `json:"account"`
				Nickname string `json:"nickname"`
			} `json:"requests"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v — body %s", err, rr.Body.String())
		}
		var found bool
		for _, r := range out.Requests {
			if r.Account == acct {
				found = true
				if r.Nickname != "MyNickname" {
					t.Fatalf("request nickname = %q, want %q — the page cannot resolve a "+
						"nickname the payload omits", r.Nickname, "MyNickname")
				}
			}
		}
		if !found {
			t.Fatalf("pending request missing from /api/requests: %s", rr.Body.String())
		}
	})

	// --- surface 5: the contacts list the whole UI renders from --------------
	t.Run("contacts list carries the nickname", func(t *testing.T) {
		s, tok := unlocked(t)
		acct := seedNicknamed(t, s)
		rr := s.do(t, "GET", "/api/contacts", "", authHdr(s, tok))
		if rr.Code != 200 {
			t.Fatalf("contacts: %d", rr.Code)
		}
		var out struct {
			Contacts []struct {
				Account  string `json:"account"`
				Name     string `json:"name"`
				Nickname string `json:"nickname"`
			} `json:"contacts"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v — body %s", err, rr.Body.String())
		}
		var found bool
		for _, c := range out.Contacts {
			if c.Account != acct {
				continue
			}
			found = true
			if c.Nickname != "MyNickname" {
				t.Fatalf("contact nickname = %q, want %q", c.Nickname, "MyNickname")
			}
			// The profile name must ALSO still be served: the contact pane shows it
			// as a secondary line so the user can see who they actually renamed.
			if c.Name != "ProfileName" {
				t.Fatalf("contact name = %q, want the peer's own %q alongside the nickname", c.Name, "ProfileName")
			}
		}
		if !found {
			t.Fatalf("contact %s missing from the list", acct)
		}
	})

	// --- surface 6: the inbound group-invite notification --------------------
	t.Run("group invite notification", func(t *testing.T) {
		s, _ := unlocked(t)
		got := make(chan string, 4)
		s.SetGroupInviteHook(func(inviter, _ string) { got <- inviter })
		acct := seedNicknamed(t, s)
		if err := s.hookOnGroupInvite("g9", "Crew", acct, "ProfileName", "r9"); err != nil {
			t.Fatalf("hookOnGroupInvite: %v", err)
		}
		select {
		case name := <-got:
			if name != "MyNickname" {
				t.Fatalf("invite notification inviter = %q, want %q", name, "MyNickname")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no invite notification fired")
		}
	})
}

// TestNicknameSurvivesPeerRenaming is the durability half of the feature. The
// peer's signed profile is the source of truth for Contact.Name and overwrites
// it on every presence sweep, so a nickname stored in the same field — or
// cleared by the same code path — would quietly evaporate the next time the
// contact edited their own display name.
func TestNicknameSurvivesPeerRenaming(t *testing.T) {
	s, _ := unlocked(t)

	// The accept path writes .Name when it is empty; it must never touch .Nickname.
	peer, _ := identity.New()
	acct := peer.AccountNumber()
	s.sessMu.Lock()
	s.contacts[acct] = chatstore.Contact{
		Account: acct, Status: chatstore.StatusPendingOut, ReqID: "r1", Nickname: "MyNickname",
	}
	s.sessMu.Unlock()
	if err := s.hookOnFriendAccept(acct, "TheirNewName", "r1"); err != nil {
		t.Fatalf("hookOnFriendAccept: %v", err)
	}
	s.sessMu.Lock()
	c := s.contacts[acct]
	s.sessMu.Unlock()
	if c.Nickname != "MyNickname" {
		t.Fatalf("accept clobbered the nickname: %q", c.Nickname)
	}
	if c.Name != "TheirNewName" {
		t.Fatalf("accept failed to record the peer's name: %q", c.Name)
	}
	if c.DisplayName() != "MyNickname" {
		t.Fatalf("DisplayName = %q, want the nickname to win over the peer's name", c.DisplayName())
	}

	// A cross friend-request (both sides requested each other) also fills .Name.
	other, _ := identity.New()
	oacct := other.AccountNumber()
	s.sessMu.Lock()
	s.contacts[oacct] = chatstore.Contact{
		Account: oacct, Status: chatstore.StatusPendingOut, Nickname: "Nick2",
	}
	s.sessMu.Unlock()
	if err := s.hookOnFriendRequest(oacct, "TheirName", "r2", "", ""); err != nil {
		t.Fatalf("hookOnFriendRequest: %v", err)
	}
	s.sessMu.Lock()
	c = s.contacts[oacct]
	s.sessMu.Unlock()
	if c.Nickname != "Nick2" {
		t.Fatalf("cross-request clobbered the nickname: %q", c.Nickname)
	}
}

// TestNicknameNeverLeavesTheDevice guards the privacy half. A nickname is a
// private label the user pinned on someone — "Landlord", "Dealer", a joke — and
// leaking it to that person or to a group would be a real harm, not a cosmetic
// bug. The roster is the one structure built from member names AND published to
// other members, so it is the place a nickname could escape.
func TestNicknameNeverLeavesTheDevice(t *testing.T) {
	s, _ := unlocked(t)
	acct := seedNicknamed(t, s)
	s.sessMu.Lock()
	s.groups["g1"] = chatstore.Group{
		ID: "g1", Name: "Crew", Epoch: 1,
		Members: []chatstore.GroupMember{
			{Account: s.myAccount, Role: chatstore.GroupRoleAdmin},
			{Account: acct, Role: chatstore.GroupRoleMember, Name: "RosterName"},
		},
	}
	members := groupMembersToRoster(s.groups["g1"].Members)
	s.sessMu.Unlock()
	for _, m := range members {
		if m.Name == "MyNickname" {
			t.Fatalf("the nickname reached the published roster for %s — a private label leaked to the group", m.Account)
		}
	}

	// And nothing may serialise the nickname into a profile we hand to a peer.
	s.sessMu.Lock()
	blob, err := json.Marshal(s.contacts[acct])
	s.sessMu.Unlock()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// This is a local-storage shape, so the nickname IS expected here; the test
	// documents that fact so a future change that starts sending Contact to a
	// peer has to come past this comment.
	if !strings.Contains(string(blob), "MyNickname") {
		t.Fatal("nickname missing from the stored contact — it must persist locally and sync to the user's own devices")
	}
}

// TestNicknameEndpoint covers the write path: setting, clearing, the rune cap,
// and that one field in the shared settings body cannot clobber another.
func TestNicknameEndpoint(t *testing.T) {
	s, tok := unlocked(t)
	acct := seedNicknamed(t, s)
	org := authHdr(s, tok)
	org["Origin"] = s.origin()

	get := func() chatstore.Contact {
		s.sessMu.Lock()
		defer s.sessMu.Unlock()
		return s.contacts[acct]
	}

	// Set, with surrounding whitespace trimmed.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","nickname":"  Bestie  "}`, org); rr.Code != 200 {
		t.Fatalf("set nickname: %d %s", rr.Code, rr.Body.String())
	}
	if n := get().Nickname; n != "Bestie" {
		t.Fatalf("nickname = %q, want %q (trimmed)", n, "Bestie")
	}

	// Muting must not disturb the nickname — the pane sends one field at a time.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","muted":true}`, org); rr.Code != 200 {
		t.Fatalf("mute: %d", rr.Code)
	}
	if n := get().Nickname; n != "Bestie" {
		t.Fatalf("an omitted nickname was clobbered by a mute update: %q", n)
	}

	// An empty string clears it — that is the whole "remove nickname" path.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","nickname":""}`, org); rr.Code != 200 {
		t.Fatalf("clear nickname: %d", rr.Code)
	}
	if n := get().Nickname; n != "" {
		t.Fatalf("nickname = %q, want cleared", n)
	}
	// Cleared means the peer's own name takes over again, not a blank label.
	if d := get().DisplayName(); d != "ProfileName" {
		t.Fatalf("DisplayName after clearing = %q, want the peer's %q", d, "ProfileName")
	}

	// Whitespace-only clears too, rather than storing a nameless-looking blank.
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","nickname":"   "}`, org); rr.Code != 200 {
		t.Fatalf("blank nickname: %d", rr.Code)
	}
	if n := get().Nickname; n != "" {
		t.Fatalf("whitespace nickname stored as %q, want cleared", n)
	}

	// The cap is counted in RUNES: 64 CJK characters fit, 65 do not. A byte cap
	// would wrongly reject the first (192 bytes).
	ok64 := strings.Repeat("好", maxNicknameRunes)
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","nickname":"`+ok64+`"}`, org); rr.Code != 200 {
		t.Fatalf("64 multi-byte runes rejected (%d) — the cap is counting bytes, not runes", rr.Code)
	}
	if got := []rune(get().Nickname); len(got) != maxNicknameRunes {
		t.Fatalf("stored %d runes, want %d", len(got), maxNicknameRunes)
	}
	// Astral characters (emoji, outside the BMP) are the case where the page and
	// the server can silently disagree: one rune, but TWO UTF-16 units, so a
	// browser-side check on String.length would block 33 emoji that the server
	// accepts happily. The 好 case above cannot catch that — it is a BMP
	// character, 1 unit per rune, where both ways of counting agree. app.js
	// spreads the string for exactly this reason.
	okAstral := strings.Repeat("\U0001F642", maxNicknameRunes)
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","nickname":"`+okAstral+`"}`, org); rr.Code != 200 {
		t.Fatalf("64 astral runes rejected (%d) — the cap is counting UTF-16 units, not runes", rr.Code)
	}
	if got := []rune(get().Nickname); len(got) != maxNicknameRunes {
		t.Fatalf("stored %d astral runes, want %d", len(got), maxNicknameRunes)
	}

	tooLong := strings.Repeat("a", maxNicknameRunes+1)
	if rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+acct+`","nickname":"`+tooLong+`"}`, org); rr.Code != 400 {
		t.Fatalf("over-long nickname: %d, want 400 (reject, never silently truncate)", rr.Code)
	}
	if got := []rune(get().Nickname); len(got) != maxNicknameRunes {
		t.Fatalf("a rejected nickname still changed the stored value (%d runes)", len(got))
	}

	// Settings for an unknown account must not create a contact.
	stranger, _ := identity.New()
	rr := s.do(t, "POST", "/api/contacts/settings", `{"account":"`+stranger.AccountNumber()+`","nickname":"Ghost"}`, org)
	if rr.Code != 404 {
		t.Fatalf("nickname for an unknown contact: %d, want 404", rr.Code)
	}
	s.sessMu.Lock()
	_, grew := s.contacts[stranger.AccountNumber()]
	s.sessMu.Unlock()
	if grew {
		t.Fatal("a nickname call created a contact that did not exist")
	}
}
