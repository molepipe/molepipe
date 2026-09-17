//go:build !linux

package desktop

import "errors"

// Notify is unimplemented off Linux. The caller treats any error as "the
// notification did not appear" and falls back to the in-app notice, which is
// the same path a Linux machine with no notification daemon takes — so this
// stub degrades to something that still tells the user.
func Notify(summary, body string) error {
	return errors.New("native notifications are not implemented on this platform")
}
