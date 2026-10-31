package api

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

func dh(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// The DHPub reverse lookup must find the single accepted contact whose cached
// DHPub matches — the mailbox rotation path's way of turning a static-DH seal
// back into a contact identity.
func TestLookupContactByDHPub(t *testing.T) {
	s := &Server{contacts: map[string]chatstore.Contact{
		"acctA": {Account: "acctA", Status: chatstore.StatusAccepted, DHPub: dh(0xAA)},
		"acctB": {Account: "acctB", Status: chatstore.StatusAccepted, DHPub: dh(0xBB)},
	}}
	if got, ok := s.lookupContactByDHPubLocked(dh(0xAA)); !ok || got != "acctA" {
		t.Fatalf("lookup(0xAA) = %q,%v; want acctA,true", got, ok)
	}
	if got, ok := s.lookupContactByDHPubLocked(dh(0xBB)); !ok || got != "acctB" {
		t.Fatalf("lookup(0xBB) = %q,%v; want acctB,true", got, ok)
	}
}

// An unknown DHPub, a non-accepted contact, and a wrong-length key must all miss.
func TestLookupContactByDHPubMiss(t *testing.T) {
	s := &Server{contacts: map[string]chatstore.Contact{
		"pending": {Account: "pending", Status: chatstore.StatusPendingIn, DHPub: dh(0xCC)},
	}}
	if _, ok := s.lookupContactByDHPubLocked(dh(0x11)); ok {
		t.Error("unknown DHPub should miss")
	}
	if _, ok := s.lookupContactByDHPubLocked(dh(0xCC)); ok {
		t.Error("a non-accepted contact must not resolve a rotation")
	}
	if _, ok := s.lookupContactByDHPubLocked(dh(0xAA)[:16]); ok {
		t.Error("wrong-length DHPub should miss")
	}
}

// Two accepted contacts sharing a DHPub must FAIL CLOSED — never guess which one
// a rotation is meant to migrate.
func TestLookupContactByDHPubAmbiguous(t *testing.T) {
	s := &Server{contacts: map[string]chatstore.Contact{
		"acctA": {Account: "acctA", Status: chatstore.StatusAccepted, DHPub: dh(0xEE)},
		"acctB": {Account: "acctB", Status: chatstore.StatusAccepted, DHPub: dh(0xEE)},
	}}
	if got, ok := s.lookupContactByDHPubLocked(dh(0xEE)); ok {
		t.Errorf("ambiguous DHPub must fail closed, got %q", got)
	}
}
