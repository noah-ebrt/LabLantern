//go:build windows

package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SystemConfigPath ist die Konfiguration, die der Dienst liest: %ProgramData%\LabLantern\agent.json.
func SystemConfigPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "LabLantern", "agent.json")
}

// DefaultConfigPath: Unter Windows gibt es nur die Konfiguration des Dienstes.
func DefaultConfigPath() string { return SystemConfigPath() }

func icacls(args ...string) error {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	if out, err := exec.Command(exe, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("icacls %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// adoptChildren lässt alles unterhalb von dir wieder nur von dir erben und macht die Administratoren zum Besitzer.
// Erst der Besitz, mit takeown: Das gelingt Administratoren auch an Dateien, deren Rechte ihnen nichts mehr
// erlauben (icacls /setowner scheitert dort). Danach darf der Besitzer die Rechte zurücksetzen. Die Muster
// treffen nur die Einträge direkt in dir; tiefer legt der Agent nichts Dauerhaftes ab.
func adoptChildren(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return nil
	}
	takeown := filepath.Join(os.Getenv("SystemRoot"), "System32", "takeown.exe")
	_ = exec.Command(takeown, "/F", filepath.Join(dir, "*"), "/A").Run()
	return icacls(filepath.Join(dir, "*"), "/reset", "/T", "/C", "/Q")
}

// Restrict lässt an ein Verzeichnis samt Inhalt nur noch SYSTEM (der Dienst) und Administratoren. Die Rechte stehen
// nur am Verzeichnis selbst; der Inhalt erbt sie. Vererbbare Rechte mit /T direkt auf Dateien zu setzen, wie es
// 0.20.1 tat, ließ Dateien zurück, auf die niemand mehr zugreifen durfte (gemessen: agent.json und die
// Programmdatei, "Zugriff verweigert" auch für Administratoren). Das Zurücksetzen des Inhalts repariert auch die.
// Die Konten stehen als SID da, weil ihre Namen je nach Sprache des Windows anders lauten; S-1-5-19 ist
// LocalService, unter dem 0.20.0 lief.
func Restrict(dir string) error {
	if err := icacls(dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
		"/remove:g", "*S-1-5-19", "/Q"); err != nil {
		return err
	}
	return adoptChildren(dir)
}

// Inherit setzt ein Verzeichnis samt Inhalt auf die Rechte zurück, die es von oben erbt (unter %ProgramFiles%:
// schreiben dürfen nur Administratoren und SYSTEM).
func Inherit(dir string) error {
	if err := icacls(dir, "/reset", "/Q"); err != nil {
		return err
	}
	return adoptChildren(dir)
}

// prepareDir schützt das Verzeichnis des Dienstes, bevor das Token hineingeschrieben wird. Unter %ProgramData%
// darf jeder Benutzer Verzeichnisse anlegen: Ein vorab angelegtes gehörte ihm, samt dem Recht, das Token später zu
// lesen. Deshalb wird es neu angelegt, abgeschottet und muss danach leer sein. Ein mit --config gewähltes anderes
// Verzeichnis bleibt, wie es ist.
func prepareDir(dir string) error {
	if !strings.EqualFold(filepath.Clean(dir), filepath.Dir(SystemConfigPath())) {
		return nil
	}
	_ = adoptChildren(dir) // sonst lassen sich Dateien, die 0.20.1 unzugänglich gemacht hat, nicht löschen
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := Restrict(dir); err != nil {
		return err
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		return fmt.Errorf("%s is not empty right after it was created; someone else writes there", dir)
	}
	return nil
}

// shareWithDaemon: Der Dienst läuft als SYSTEM und darf das Verzeichnis ohnehin lesen (prepareDir).
func shareWithDaemon(string, string) {}
