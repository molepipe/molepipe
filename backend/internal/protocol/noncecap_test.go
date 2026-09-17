package protocol

import (
	"testing"

	"github.com/molepipe/molepipe/backend/internal/identity"
)

// A challenge flood must not grow the nonce jar without bound: the jar is
// capped at maxNonces and evicts the oldest outstanding nonce to make room.
func TestChallengeJarIsBounded(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	p := NewPeer(id, Hooks{DisplayName: func() string { return "" }})
	for i := 0; i < maxNonces*4; i++ {
		p.Challenge()
	}
	p.mu.Lock()
	n := len(p.nonces)
	p.mu.Unlock()
	if n > maxNonces {
		t.Fatalf("jar grew past the cap: %d > %d", n, maxNonces)
	}
}

// A freshly issued challenge must remain valid even while the jar is full — the
// eviction targets the OLDEST nonce, never the one just handed out.
func TestFreshChallengeSurvivesFloodEviction(t *testing.T) {
	id, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	p := NewPeer(id, Hooks{DisplayName: func() string { return "" }})
	for i := 0; i < maxNonces; i++ {
		p.Challenge() // fill to the cap
	}
	ch := p.Challenge() // the newest nonce, issued while the jar is full
	if !p.consumeNonce(ch.Nonce) {
		t.Fatal("a just-issued challenge was evicted before it could be used")
	}
}
