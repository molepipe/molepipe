package protocol

import (
	"encoding/hex"
	"testing"
	"time"
)

// Golden vectors that pin the ABSOLUTE bytes of the v1 signature domain and the
// blobs built by the shared sign+verify helpers. A symmetric drift — e.g.
// sigContextFor(1) changing, or a field dropped from a helper that both signing
// AND verifying call — stays invisible to every sign→verify round-trip test
// (both sides drift together and still agree). These assertions catch it because
// they compare against literals frozen when v1 was known-correct. If one fails
// after an intentional wire change, that change is NOT backward compatible with
// v1 and must ship as a negotiated v2, not by editing these constants.

// Fixed, deterministic inputs (no keys/nonces: we pin the pre-signature blob).
var goldGroupAt = time.Unix(0, 1700000000000000000).UTC()

func goldGroupText() GroupMessage {
	return GroupMessage{GroupID: "G-fixed-123", At: goldGroupAt, Text: "hello golden"}
}
func goldGroupReply() GroupMessage {
	return GroupMessage{GroupID: "G-fixed-123", At: goldGroupAt, Text: "re: hi", ReplyID: "msg-42"}
}
func goldMail() MailEnvelope {
	dh := make([]byte, 32)
	for i := range dh {
		dh[i] = 0x01
	}
	return MailEnvelope{
		Recipient: "recipient-acct", Sender: "sender-acct",
		SenderDHPub: dh, SentAt: 1700000000, Box: []byte("golden-box-bytes"),
	}
}

func TestSigContextForV1IsFrozen(t *testing.T) {
	want := "onion-chat/v1"
	if got := string(sigContextFor(1)); got != want {
		t.Fatalf("sigContextFor(1) = %q, want %q — v1 signature domain drifted; v>=2 builds can no longer verify v1 peers", got, want)
	}
	if got := string(sigContextFor(protoVerCurrent)); got != want {
		t.Fatalf("sigContextFor(protoVerCurrent) = %q, want %q", got, want)
	}
}

// TestSigContextForV2IsReserved freezes the RESERVED v2 domain. protoVerCurrent
// is still 1, so v2 is never negotiated in production — but the cross-version
// test signs under this domain to prove a v2 blob is genuinely distinct from a
// v1 one. Pin it so the reserved string cannot drift silently before real v2
// ships, and assert distinctness so a copy-paste that made sigContextFor(2)
// return the v1 bytes (which would make the cross-version test pass vacuously)
// is caught here.
func TestSigContextForV2IsReserved(t *testing.T) {
	if got, want := string(sigContextFor(2)), "onion-chat/v2"; got != want {
		t.Fatalf("sigContextFor(2) = %q, want %q — reserved v2 domain drifted", got, want)
	}
	if string(sigContextFor(2)) == string(sigContextFor(1)) {
		t.Fatal("sigContextFor(2) == sigContextFor(1): v2 domain is not distinct, cross-version proof would be vacuous")
	}
}

func TestGoldenBlobsFrozen(t *testing.T) {
	cases := []struct {
		name string
		blob []byte
		want string // frozen hex; "" means "print, don't assert" (generation pass)
	}{
		{"group-text", goldGroupText().signingBlob(), goldGroupTextHex},
		{"group-reply", goldGroupReply().signingBlob(), goldGroupReplyHex},
		{"mail-signing", goldMail().signingBlob(), goldMailSigningHex},
		{"mail-id", goldMail().idBlob(), goldMailIDHex},
	}
	for _, c := range cases {
		got := hex.EncodeToString(c.blob)
		if c.want == "" {
			t.Logf("GOLDEN %s = %q", c.name, got)
			continue
		}
		if got != c.want {
			t.Errorf("%s blob drifted:\n got  %s\n want %s\n(intentional wire change must ship as negotiated v2, not by editing this constant)", c.name, got, c.want)
		}
	}
}

// Frozen 2026-08-31 against known-correct v1 (existing round-trip tests green).
const (
	goldGroupTextHex   = "0000000d6f6e696f6e2d636861742f76310000000d67726f75702d6d6573736167650000000b472d66697865642d3132330000000817979cfe362a00000000000c68656c6c6f20676f6c64656e"
	goldGroupReplyHex  = "0000000d6f6e696f6e2d636861742f76310000001367726f75702d7265706c792d6d6573736167650000000b472d66697865642d3132330000000817979cfe362a00000000000672653a206869000000066d73672d3432"
	goldMailSigningHex = "0000000d6f6e696f6e2d636861742f76310000000f6d61696c626f782d6d6573736167650000000e726563697069656e742d6163637400000020010101010101010101010101010101010101010101010101010101010101010100000008000000006553f10000000010676f6c64656e2d626f782d6279746573"
	goldMailIDHex      = "0000000d6f6e696f6e2d636861742f76310000000f6d61696c626f782d6d6573736167650000000e726563697069656e742d616363740000000b73656e6465722d6163637400000020010101010101010101010101010101010101010101010101010101010101010100000008000000006553f10000000010676f6c64656e2d626f782d6279746573"
)
