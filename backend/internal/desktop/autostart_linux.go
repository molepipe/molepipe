package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Supported reports whether start-at-login can be offered here. The UI hides
// the toggle when it cannot, rather than showing one that fails on use.
func Supported() bool { return true }

// defaultDir is the XDG autostart directory. os.UserConfigDir already honours
// $XDG_CONFIG_HOME, which is also what makes this testable.
func defaultDir() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate the config directory: %w", err)
	}
	return filepath.Join(cfg, "autostart"), nil
}

// Enabled reports whether the entry exists AND still points at this binary.
//
// The second half matters: the entry names an absolute path into wherever the
// tarball was unpacked, so moving that folder leaves a file that would launch
// nothing. Reporting such an entry as "on" would be a lie the user cannot see,
// so a stale entry reads as off — and Set repairs it.
func (a *Autostart) Enabled() (bool, error) {
	b, err := os.ReadFile(a.Path())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.Contains(string(b), "\nExec="+a.command()+"\n"), nil
}

// Set turns start-at-login on or off. It is idempotent, and writing over a
// stale entry is how a moved installation repairs itself.
func (a *Autostart) Set(on bool) error {
	if !on {
		if err := os.Remove(a.Path()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return err
	}
	// X-GNOME-Autostart-Delay gives the network a moment before Arti starts
	// reaching for the Tor directory authorities; without it the first bootstrap
	// at login routinely fails and silently retries for a minute.
	entry := "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=Molepipe\n" +
		"Comment=Private messaging over Tor\n" +
		"Exec=" + a.command() + "\n" +
		"Terminal=false\n" +
		"Categories=Network;InstantMessaging;\n" +
		"X-GNOME-Autostart-enabled=true\n" +
		"X-GNOME-Autostart-Delay=10\n"
	// 0600: the entry names the data directory, which can name the user.
	return writeFileAtomic(a.Path(), []byte(entry), 0o600)
}

// writeFileAtomic avoids a half-written entry surviving a crash — a truncated
// desktop file is silently ignored at login, which would look like the toggle
// simply not working.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".autostart-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
