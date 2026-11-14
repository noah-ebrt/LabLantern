//go:build !windows

package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// SystemConfigPath ist die Konfiguration, die der Dienst liest.
func SystemConfigPath() string { return "/etc/lablantern/agent.json" }

func DefaultConfigPath() string {
	if os.Geteuid() == 0 {
		return "/etc/lablantern/agent.json"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "agent.json"
	}
	return filepath.Join(home, ".config", "lablantern", "agent.json")
}

// prepareDir: Unter Unix regeln Modus und Gruppe den Zugriff (shareWithDaemon).
func prepareDir(string) error { return nil }

// shareWithDaemon gibt dem Daemon (Gruppe lablantern) Lesezugriff auf Token und CA, wenn das Paket
// installiert ist. Schreiben darf weiter nur root.
func shareWithDaemon(dir, path string) {
	if os.Geteuid() != 0 {
		return
	}
	g, err := user.LookupGroup("lablantern")
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	if os.Chown(dir, 0, gid) == nil {
		_ = os.Chmod(dir, 0o750)
	}
	if os.Chown(path, 0, gid) == nil {
		_ = os.Chmod(path, 0o640)
	}
}
