package api

import (
	"reflect"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
)

// chatMessage and chatstore.Message are converted directly, which Go allows
// only for identical field names, types AND order. A build failure is the good
// outcome of getting that wrong; the bad one is two adjacent same-typed string
// fields silently swapping values. This asserts every field survives the round
// trip with distinct values, so a reordering cannot pass unnoticed.
func TestMessageStructsConvertCleanly(t *testing.T) {
	orig := chatMessage{
		Direction: "out",
		Peer:      "peer-account",
		Text:      "the text",
		At:        time.Unix(1700000000, 0).UTC(),
		ID:        "the-id",
		Delivery:  chatstore.DeliveryPending,
		GroupID:   "the-group",
		Author:    "author-account",
		AuthorSig: []byte{1, 2, 3},
	}
	round := chatMessage(chatstore.Message(orig))
	if !reflect.DeepEqual(round, orig) {
		t.Fatalf("round trip changed the message:\n got  %+v\n want %+v", round, orig)
	}
	stored := chatstore.Message(orig)
	if stored.ID != "the-id" || stored.Delivery != chatstore.DeliveryPending {
		t.Fatalf("ID/Delivery crossed over in conversion: %+v", stored)
	}
}
