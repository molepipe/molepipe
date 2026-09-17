package desktop

import (
	"github.com/godbus/dbus/v5"
)

// Notify sends a native desktop notification over the session bus.
//
// It talks to org.freedesktop.Notifications directly rather than shelling out
// to notify-send, which is not installed everywhere and would put a user-facing
// string through a shell. The session bus is already open for the tray, so this
// costs nothing extra.
//
// Every failure is returned rather than logged here, and every failure is
// non-fatal to the caller: a machine with no notification daemon is a normal
// machine. This is why the same message is also delivered in-app — see the
// background notice in cmd/desktop.
func Notify(summary, body string) error {
	conn, err := dbus.SessionBus()
	if err != nil {
		return err
	}
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	call := obj.Call("org.freedesktop.Notifications.Notify", 0,
		"Molepipe", // app_name
		uint32(0),       // replaces_id: 0 = new notification
		"",              // app_icon: none, rather than a path that may not exist
		summary,         // summary
		body,            // body
		[]string{},      // actions: none, so a click does nothing surprising
		map[string]dbus.Variant{},
		int32(8000), // expire_timeout ms
	)
	return call.Err
}
