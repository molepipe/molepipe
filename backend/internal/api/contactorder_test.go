package api

import (
	"reflect"
	"sort"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/identity"
)

// TestContactsStableOrder guards the fix for the flickering contact list:
// s.contacts is a map, whose iteration order is randomised per call, so
// /api/contacts must impose a deterministic order or the UI reshuffles on every
// poll. The response must be account-sorted and identical across repeated calls.
func TestContactsStableOrder(t *testing.T) {
	s, tok := unlocked(t)
	auth := map[string]string{"Authorization": "Bearer " + tok, "Origin": s.origin()}

	for i := 0; i < 8; i++ {
		id, _ := identity.New()
		s.sessMu.Lock()
		s.contacts[id.AccountNumber()] = chatstore.Contact{Account: id.AccountNumber(), Status: chatstore.StatusAccepted}
		s.sessMu.Unlock()
	}

	order := func() []string {
		body := decode(t, s.do(t, "GET", "/api/contacts", "", auth).Body)
		var out []string
		for _, raw := range body["contacts"].([]any) {
			out = append(out, raw.(map[string]any)["account"].(string))
		}
		return out
	}

	first := order()
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i] < first[j] }) {
		t.Fatalf("contacts not returned in a stable sorted order: %v", first)
	}
	// Repeated calls must be byte-for-byte identical; with the raw map order they
	// would vary, which is exactly the reshuffle the user saw.
	for k := 0; k < 8; k++ {
		if got := order(); !reflect.DeepEqual(got, first) {
			t.Fatalf("contact order changed between calls:\n first=%v\n got  =%v", first, got)
		}
	}
}
