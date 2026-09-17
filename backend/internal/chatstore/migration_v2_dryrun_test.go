package chatstore

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/molepipe/molepipe/backend/internal/crypto"
)

// Commit-3 dry-run: a DURABLE proof that the migration pipeline actually transforms
// an older on-disk payload correctly, exercised end-to-end while the shipped window
// stays [1,1] (fileVersion is still 1). It is the disk analog of protocol's
// version_crossver_test: production never reaches format v2 (migrate's ceiling is
// fileVersion), but the tests drive migrate up to 2 through the parameterized
// ceiling, exactly as the production Load would once fileVersion is raised. The
// reserved migrate1to2 (sort Deleted) is locked here so its shape cannot drift
// before the first real v2 lands.
//
// This does NOT close the aad(env.Version)-vs-const question — that is already
// caught by identity's TestOpenEnvelopeBindsAADToVersion, and full closure only
// arrives when a version const actually becomes 2 (chatstore's AAD is frozen, so it
// was never at risk). What commit 3 adds is fidelity: proof the migrate SEAM, which
// was an untested empty case, carries every field forward and drops nothing.

// decodeFixtureRaw decrypts the frozen v1 fixture and returns the raw Data BEFORE
// migrate/normalize, mirroring the first half of Store.Load. White-box: it uses the
// package's own aad()/goldKey, so it decrypts exactly what Load would.
func decodeFixtureRaw(t *testing.T) Data {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture (regenerate with CHATSTORE_REGEN_FIXTURE=1): %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("parse fixture envelope: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	pt, err := crypto.Open(goldKey, nonce, ct, aad())
	if err != nil {
		t.Fatalf("decrypt fixture: %v", err)
	}
	var d Data
	if err := json.Unmarshal(pt, &d); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return d
}

// fidelityDiffs returns the names of the Data fields that differ between want and
// got. It is the shared, non-vacuous comparison both the fidelity assertion and its
// negative control run through: the real migration must produce an empty list, a
// migration that loses a field must name that field. Deleted is the field the dry-run
// migration touches (it canonicalizes order), so both sides are sorted before
// comparison — the check is about the SET surviving, not its incidental order.
func fidelityDiffs(want, got *Data) []string {
	w, g := *want, *got
	// Copy before sorting: w/g are struct copies but Deleted still aliases the
	// callers' backing arrays, so sorting in place would mutate the inputs (and make
	// a second call on the same Data compare against an already-reordered baseline).
	w.Deleted = append([]string(nil), w.Deleted...)
	g.Deleted = append([]string(nil), g.Deleted...)
	sort.Strings(w.Deleted)
	sort.Strings(g.Deleted)
	var diffs []string
	cmp := func(name string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			diffs = append(diffs, name)
		}
	}
	cmp("Profile", w.Profile, g.Profile)
	cmp("Contacts", w.Contacts, g.Contacts)
	cmp("Messages", w.Messages, g.Messages)
	cmp("Groups", w.Groups, g.Groups)
	cmp("GroupInvites", w.GroupInvites, g.GroupInvites)
	cmp("SentGroupInvites", w.SentGroupInvites, g.SentGroupInvites)
	cmp("Reads", w.Reads, g.Reads)
	cmp("Devices", w.Devices, g.Devices)
	cmp("PendingAccepts", w.PendingAccepts, g.PendingAccepts)
	cmp("Outbox", w.Outbox, g.Outbox)
	cmp("Deleted", w.Deleted, g.Deleted)
	return diffs
}

// TestStoreMigrateV1ToV2Fidelity is the centerpiece: the frozen v1 fixture, driven
// through the reserved v1->v2 step exactly as Load would (decrypt -> migrate ->
// normalize) but with the ceiling raised to 2, must come out with every field intact
// against the direct v1 load. migrate returning nil is itself proof the reserved
// case 1 is wired (an unwired version would hit the fail-closed default and error).
func TestStoreMigrateV1ToV2Fidelity(t *testing.T) {
	// Baseline: the v1 fixture loaded the production way (ceiling fileVersion=1).
	tmp := t.TempDir()
	rawBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, fileName), rawBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := New(tmp, goldKey).Load()
	if err != nil {
		t.Fatalf("baseline v1 load failed: %v", err)
	}

	// Dry-run: same bytes, mirror Load's order but migrate up to v2.
	got := decodeFixtureRaw(t)
	if err := migrate(1, 2, &got); err != nil {
		t.Fatalf("reserved v1->v2 migration must exist and succeed: %v", err)
	}
	got.normalize()

	if diffs := fidelityDiffs(want, &got); len(diffs) != 0 {
		t.Fatalf("v1->v2 migration lost/changed fields %v — an upgrade would corrupt the account", diffs)
	}
}

// TestStoreMigrate1To2Transforms proves the reserved step actually does its declared
// work (and does it losslessly), separate from the fixture — whose Deleted list is
// already canonical, so the sort is invisible there. A deliberately UNSORTED, DUPLICATE-
// free tombstone set must come out sorted with the same members, no drops.
func TestStoreMigrate1To2Transforms(t *testing.T) {
	d := Data{Deleted: []string{"m-9", "m-1", "m-5", "m-3"}}
	migrate1to2(&d)
	want := []string{"m-1", "m-3", "m-5", "m-9"}
	if !reflect.DeepEqual(d.Deleted, want) {
		t.Fatalf("migrate1to2 did not canonicalize tombstones: got %v want %v", d.Deleted, want)
	}
}

// TestStoreFidelityCatchesDroppedTombstone is the head-on non-vacuity guard: the
// fidelity comparison must FAIL when a migration drops even a single tombstone. A
// broken migrator that sorts then loses one element (the realistic tombstone-loss
// bug — a dropped tombstone silently resurrects a deleted message on the next sync)
// must produce a "Deleted" diff. Without this, a fidelity test that never fails
// proves nothing.
func TestStoreFidelityCatchesDroppedTombstone(t *testing.T) {
	base := decodeFixtureRaw(t)

	// The real migration leaves the set intact -> no diff.
	good := base
	good.Deleted = append([]string(nil), base.Deleted...)
	migrate1to2(&good)
	if diffs := fidelityDiffs(&base, &good); len(diffs) != 0 {
		t.Fatalf("real migration reported spurious diffs %v", diffs)
	}

	// A broken migration that drops one tombstone MUST be caught.
	broken := base
	broken.Deleted = append([]string(nil), base.Deleted...)
	sort.Strings(broken.Deleted)
	broken.Deleted = broken.Deleted[1:] // lose one element
	diffs := fidelityDiffs(&base, &broken)
	found := false
	for _, d := range diffs {
		if d == "Deleted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fidelity check did not catch a dropped tombstone (diffs=%v) — the fidelity assertion is vacuous", diffs)
	}
}
