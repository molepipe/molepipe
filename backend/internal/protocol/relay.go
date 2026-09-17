package protocol

import (
	"context"
	"fmt"

	"github.com/molepipe/molepipe/backend/internal/tor"
)

// Friend-relay (push model). When Alice can reach neither Carol directly nor a
// mailbox for her, Alice hands a sealed MailEnvelope to an approved relay-holder
// (Bob). Bob's device then keeps dialing Carol and delivering the blob until it
// gets through — Carol needs no relationship with Bob and never has to discover
// or poll him. Bob is untrusted transport: the envelope stays E2E-encrypted for
// Carol, and Carol authenticates Alice's signature herself on delivery.

// RelayDropOff hands a sealed envelope to a relay-holder (relayHolder = Bob's
// account). Bob accepts it only if he has approved Alice (the envelope's sender)
// as a relay-grantee.
func RelayDropOff(ctx context.Context, dialer tor.Dialer, env MailEnvelope, relayHolder string) error {
	client, base := onionClient(dialer, relayHolder)
	if err := postJSONInto(ctx, client, base+"/relay/dropoff", map[string]any{"envelope": env}, nil); err != nil {
		return fmt.Errorf("relay drop-off: %w", err)
	}
	return nil
}

// RelayDeliver pushes a held envelope to its recipient (Bob → Carol). Called by
// the relay-holder's forward loop once the recipient is reachable.
func RelayDeliver(ctx context.Context, dialer tor.Dialer, env MailEnvelope, recipient string) error {
	client, base := onionClient(dialer, recipient)
	if err := postJSONInto(ctx, client, base+"/relay/deliver", map[string]any{"envelope": env}, nil); err != nil {
		return fmt.Errorf("relay deliver: %w", err)
	}
	return nil
}
