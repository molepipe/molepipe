package protocol

import "strings"

// A shareable "friend code" is normally just the bare account number (a 56-char
// base32 onion), which is what QR codes and pasted codes have always been. The
// one-time-invite feature layers a single-use token onto that same code so the
// receiver can burn it after one redemption. To stay backward-compatible — old
// screenshots, written-down account numbers, and not-yet-rebuilt peers all keep
// working — a code that carries a token gets an explicit, versioned prefix, and
// anything without that prefix is treated as a bare account (token "").
//
// The version prefix is a deliberate seam: a richer future code format (bootstrap
// prekey pointers, checksums) bumps "mp1" rather than colliding with the bare
// form. Account numbers and the base64url token alphabet contain no ':', so the
// colon is an unambiguous delimiter.
const inviteCodeV1Prefix = "mp1"

// EncodeInviteCode renders a shareable friend code. With an empty token it
// returns the bare account (unchanged, backward-compatible); with a token it
// returns the versioned "mp1:<account>:<token>" form.
func EncodeInviteCode(account, token string) string {
	if token == "" {
		return account
	}
	return inviteCodeV1Prefix + ":" + account + ":" + token
}

// ParseInviteCode splits a shareable friend code into its account and optional
// one-time token. A bare account (no version prefix) parses to (account, "") so
// the historical add-by-account path is unaffected. Whitespace is trimmed so a
// pasted code with stray spaces still resolves.
func ParseInviteCode(code string) (account, token string) {
	code = strings.TrimSpace(code)
	rest, ok := strings.CutPrefix(code, inviteCodeV1Prefix+":")
	if !ok {
		return code, ""
	}
	account, token, _ = strings.Cut(rest, ":")
	return account, token
}
