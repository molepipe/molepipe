package api

import (
	"fmt"
	"strconv"
	"strings"
)

// normalizeMailboxURL validates and canonicalizes a mailbox address entered by
// the user (or, when caching, advertised by a peer). A mailbox is reached as a
// bare host[:port] — either a v3 .onion or an ordinary domain/IP — and the
// client always connects to it via Tor, so we deliberately store no scheme.
// Empty input clears the mailbox and is allowed.
func normalizeMailboxURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if len(s) > 256 {
		return "", fmt.Errorf("mailbox address is too long")
	}
	// Accept and strip an optional scheme and trailing path for convenience.
	for _, p := range []string{"http://", "https://"} {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			s = s[len(p):]
			break
		}
	}
	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i] // drop any path/query — a mailbox is just a host
	}
	s = strings.ToLower(s)
	if s == "" {
		return "", fmt.Errorf("mailbox address is empty")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return "", fmt.Errorf("mailbox address must not contain spaces")
	}

	host := s
	// Split an optional :port (bracketless; onion hosts have no colons).
	if i := strings.LastIndex(s, ":"); i >= 0 {
		var port string
		host, port = s[:i], s[i+1:]
		if host == "" {
			return "", fmt.Errorf("mailbox address is missing a host")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("mailbox port must be 1-65535")
		}
	}
	// Onion-only for now: the client always reaches a mailbox over Tor, and only
	// .onion dialing is wired up. Clearnet-via-exit is a later increment; accepting
	// a clearnet address here would let mail silently go nowhere.
	if !strings.HasSuffix(host, ".onion") {
		return "", fmt.Errorf("only .onion mailboxes are supported yet")
	}
	if label := strings.TrimSuffix(host, ".onion"); len(label) != 56 { // v3 = 56 base32 chars
		return "", fmt.Errorf("that doesn't look like a valid v3 .onion address")
	}
	return s, nil
}
