package api

import "testing"

func TestPresenceState(t *testing.T) {
	cases := []struct {
		reachable bool
		mailbox   string
		want      string
	}{
		{true, "", presenceOnline},
		{true, "abc.onion", presenceOnline}, // reachable wins over mailbox
		{false, "abc.onion", presenceMailbox},
		{false, "", presenceOffline},
	}
	for _, c := range cases {
		if got := presenceState(c.reachable, c.mailbox); got != c.want {
			t.Errorf("presenceState(%v,%q)=%q want %q", c.reachable, c.mailbox, got, c.want)
		}
	}
}

func TestNormalizeMailboxURL(t *testing.T) {
	onion56 := "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid" // 56 chars
	ok := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{onion56 + ".onion", onion56 + ".onion"},
		{"http://" + onion56 + ".onion/", onion56 + ".onion"},
		{onion56 + ".onion:8080", onion56 + ".onion:8080"},
		{"HTTP://" + onion56 + ".ONION/path", onion56 + ".onion"},
	}
	for _, c := range ok {
		got, err := normalizeMailboxURL(c.in)
		if err != nil {
			t.Errorf("normalizeMailboxURL(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeMailboxURL(%q)=%q want %q", c.in, got, c.want)
		}
	}

	bad := []string{
		"has space.onion",
		"nodothost",              // no dot, not .onion
		"shortlabel.onion",       // wrong onion length
		"mail.example.com",       // clearnet not supported yet
		"1.2.3.4:25",             // clearnet not supported yet
		onion56 + ".onion:0",     // bad port
		onion56 + ".onion:99999", // bad port
	}
	for _, in := range bad {
		if _, err := normalizeMailboxURL(in); err == nil {
			t.Errorf("normalizeMailboxURL(%q) expected error, got none", in)
		}
	}
}
