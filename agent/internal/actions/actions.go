// Package actions führt die gefährlichen Befehle aus (Neustart, Agent-Update) und pflegt die Liste der
// vertrauten Passkeys. Es läuft als root ohne Netz (lablantern-action.service) und glaubt dem Daemon nichts:
// Jeder Befehl braucht eine gültige Passkey-Signatur über genau diesen Umschlag, passend zu diesem Host,
// noch nicht abgelaufen und noch nie benutzt. Updates müssen zusätzlich mit dem Release-Schlüssel signiert sein.
package actions

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"lablantern/agent/internal/jobs"
	"lablantern/agent/internal/passkey"
	"lablantern/agent/internal/release"
)

const (
	maxRequest    = 64 * 1024
	maxPackage    = 300 << 20
	rebootSpacing = 30 * time.Minute
	clockSkew     = 120 // Sekunden, die die Uhr des Masters vorgehen darf
)

type Request struct {
	Nonce     string `json:"nonce"`     // ordnet das Ergebnis dem Auftrag zu
	Kind      string `json:"kind"`      // passkeys | command
	Envelope  string `json:"envelope"`  // genau die Bytes, über die signiert wurde
	Assertion string `json:"assertion"` // JSON; leer nur bei der allerersten Passkey-Liste
}

type Result struct {
	Nonce  string `json:"nonce"`
	Status string `json:"status"` // done, failed, rejected
	Output string `json:"output"`
}

type Paths struct {
	RequestFile string // Daemon schreibt (/run/lablantern)
	ResultFile  string // nur root schreibt (/run/lablantern-out)
	TrustFile   string // nur root schreibt (/etc/lablantern)
	StateDir    string // nur root (/var/lib/lablantern-action)
	StageDir    string // Daemon legt hier heruntergeladene Update-Dateien ab
}

func DefaultPaths() Paths {
	return Paths{RequestFile: "/run/lablantern/action.request", ResultFile: "/run/lablantern-out/action-result.json",
		TrustFile: "/etc/lablantern/passkeys.json", StateDir: "/var/lib/lablantern-action", StageDir: "/run/lablantern/update"}
}

// Env ist die Umgebung der root-Seite; austauschbar für Tests.
type Env struct {
	Paths
	SystemID     int
	AgentVersion string
	Now          func() time.Time
	Run          func(name string, args ...string) (string, error)
	PkgType      string // deb oder rpm
	Arch         string
	ReleaseKey   ed25519.PublicKey
	// FirstTrustSHA256 kommt aus dem Einrichtungsbefehl (agent.json). Gesetzt, wird als erste Passkey-Liste nur genau
	// diese übernommen; sonst gilt Vertrauen beim ersten Kontakt.
	FirstTrustSHA256 string
}

func DefaultEnv(systemID int, agentVersion string) Env {
	pkg := "rpm"
	if _, err := os.Stat("/usr/bin/dpkg"); err == nil {
		pkg = "deb"
	}
	return Env{Paths: DefaultPaths(), SystemID: systemID, AgentVersion: agentVersion, Now: time.Now, PkgType: pkg,
		Arch: runtime.GOARCH, ReleaseKey: release.PublicKey(), Run: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
			return string(out), err
		}}
}

// PackageName ist der Dateiname des passenden Pakets im Release.
func PackageName(arch, pkg string) string {
	return fmt.Sprintf("lablantern-agent-linux-%s.%s", arch, pkg)
}

// --- Daemon-Seite ---

func (p Paths) Submit(req Request) error {
	data, _ := json.Marshal(req)
	tmp := p.RequestFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("cannot write action request: %w", err)
	}
	return os.Rename(tmp, p.RequestFile)
}

func (p Paths) Wait(nonce string, timeout, interval time.Duration) (*Result, error) {
	deadline := time.Now().Add(timeout)
	for {
		if data, err := os.ReadFile(p.ResultFile); err == nil {
			var r Result
			if json.Unmarshal(data, &r) == nil && r.Nonce == nonce {
				return &r, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("action handler did not answer within %s (journalctl -u lablantern-action.service)", timeout)
		}
		time.Sleep(interval)
	}
}

// TrustRev liefert die Revision der lokal vertrauten Passkey-Liste (0 = noch keine).
func (p Paths) TrustRev() int {
	data, err := os.ReadFile(p.TrustFile)
	if err != nil {
		return 0
	}
	t, err := passkey.ParseTrust(string(data))
	if err != nil {
		return 0
	}
	return t.Rev
}

// --- root-Seite ---

// Handle arbeitet einen Auftrag ab und schreibt das Ergebnis.
func (e Env) Handle() error {
	data, err := jobs.TakeFile(e.RequestFile, maxRequest)
	if err != nil {
		return fmt.Errorf("action request: %w", err)
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return fmt.Errorf("action request invalid")
	}
	res := e.handle(&req)
	res.Nonce = req.Nonce
	out, _ := json.Marshal(res)
	return jobs.WriteAtomic(e.ResultFile, out)
}

func rejected(format string, a ...any) Result {
	return Result{Status: "rejected", Output: fmt.Sprintf(format, a...)}
}

func (e Env) handle(req *Request) Result {
	switch req.Kind {
	case "passkeys":
		return e.trust(req)
	case "command":
		return e.command(req)
	}
	return rejected("unknown action %q", req.Kind)
}

func (e Env) loadTrust() (*passkey.TrustSet, error) {
	data, err := jobs.ReadNoFollow(e.TrustFile, maxRequest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return passkey.ParseTrust(string(data))
}

func (e Env) trust(req *Request) Result {
	next, err := passkey.ParseTrust(req.Envelope)
	if err != nil {
		return rejected("%v", err)
	}
	cur, err := e.loadTrust()
	if err != nil {
		return rejected("local passkey list unreadable: %v", err)
	}
	if cur == nil && e.FirstTrustSHA256 != "" {
		sum := sha256.Sum256([]byte(req.Envelope))
		if hex.EncodeToString(sum[:]) != strings.ToLower(e.FirstTrustSHA256) {
			return rejected("passkey list does not match the one pinned at setup (--passkeys-sha256); set the host up again")
		}
	}
	if cur != nil {
		if next.Rev <= cur.Rev {
			return rejected("passkey list revision %d is not newer than %d", next.Rev, cur.Rev)
		}
		a, err := passkey.ParseAssertion(req.Assertion)
		if err != nil {
			return rejected("a new passkey list must be signed by a passkey this agent already trusts")
		}
		if err := passkey.Verify(cur, req.Envelope, a); err != nil {
			return rejected("passkey list not accepted: %v", err)
		}
	}
	if err := jobs.WriteAtomic(e.TrustFile, []byte(req.Envelope)); err != nil {
		return Result{Status: "failed", Output: err.Error()}
	}
	how := "signed by a trusted passkey"
	switch {
	case cur == nil && e.FirstTrustSHA256 != "":
		how = "initial list, pinned at setup"
	case cur == nil:
		how = "initial list, trusted on first use"
	}
	return Result{Status: "done", Output: fmt.Sprintf("trusting %d passkey(s), revision %d (%s)", len(next.Keys), next.Rev, how)}
}

type command struct {
	Kind     string `json:"kind"`
	SystemID int    `json:"system_id"`
	// SystemIDs: ein Passkey-Touch für mehrere Hosts, nur für update_agent. Ein Update installiert ohnehin nur
	// ein von CI signiertes, neueres Paket; Neustart und Entfernen bleiben bewusst ein Host je Touch.
	SystemIDs []int          `json:"system_ids,omitempty"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params"`
	IssuedAt  int64          `json:"issued_at"`
	ExpiresAt int64          `json:"expires_at"`
	Nonce     string         `json:"nonce"`
}

func (e Env) command(req *Request) Result {
	set, err := e.loadTrust()
	if err != nil || set == nil {
		return rejected("no trusted passkeys yet: register one in the LabLantern UI first")
	}
	a, err := passkey.ParseAssertion(req.Assertion)
	if err != nil {
		return rejected("%v", err)
	}
	if err := passkey.Verify(set, req.Envelope, a); err != nil {
		return rejected("%v", err)
	}
	var c command
	if err := json.Unmarshal([]byte(req.Envelope), &c); err != nil || c.Kind != "command" || len(c.Nonce) < 16 {
		return rejected("command envelope invalid")
	}
	now := e.Now().Unix()
	switch {
	case e.SystemID == 0 || !c.isFor(e.SystemID):
		return rejected("command is for another system")
	case now > c.ExpiresAt:
		return rejected("command expired")
	case c.IssuedAt > now+clockSkew:
		return rejected("command issued in the future (check the clocks)")
	}
	if err := e.useNonce(c.Nonce, c.ExpiresAt); err != nil {
		return rejected("%v", err)
	}
	switch c.Type {
	case "reboot":
		return e.reboot(c)
	case "update_agent":
		v, _ := c.Params["version"].(string)
		return e.update(v)
	case "uninstall":
		return e.uninstall()
	}
	return rejected("unknown command type %q", c.Type)
}

func (c command) isFor(id int) bool {
	if c.SystemID != 0 {
		return c.SystemID == id && len(c.SystemIDs) == 0
	}
	if c.Type != "update_agent" {
		return false
	}
	for _, s := range c.SystemIDs {
		if s == id {
			return true
		}
	}
	return false
}

// useNonce verhindert, dass ein mitgeschnittener Befehl ein zweites Mal ausgeführt wird.
func (e Env) useNonce(nonce string, expires int64) error {
	path := filepath.Join(e.StateDir, "nonces.json")
	seen := map[string]int64{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &seen)
	}
	now := e.Now().Unix()
	for n, exp := range seen {
		if exp < now-3600 {
			delete(seen, n)
		}
	}
	if _, used := seen[nonce]; used {
		return fmt.Errorf("command was already executed (replay)")
	}
	seen[nonce] = expires
	data, _ := json.Marshal(seen)
	if err := os.MkdirAll(e.StateDir, 0o700); err != nil {
		return err
	}
	return jobs.WriteAtomic(path, data)
}

func (e Env) reboot(c command) Result {
	stamp := filepath.Join(e.StateDir, "last-reboot")
	if data, err := os.ReadFile(stamp); err == nil {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data))); err == nil && e.Now().Sub(t) < rebootSpacing {
			return rejected("rebooted less than 30 minutes ago; refusing another reboot")
		}
	}
	delay := 30
	if d, ok := c.Params["delay"].(float64); ok {
		delay = min(max(int(d), 10), 600)
	}
	out, err := e.Run("systemd-run", fmt.Sprintf("--on-active=%d", delay), "--timer-property=AccuracySec=1s", "--unit=lablantern-reboot",
		"--description=lablantern reboot (passkey confirmed)", "/usr/bin/systemctl", "reboot")
	if err != nil {
		return Result{Status: "failed", Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	_ = jobs.WriteAtomic(stamp, []byte(e.Now().UTC().Format(time.RFC3339)))
	return Result{Status: "done", Output: fmt.Sprintf("Rebooting in %d seconds.", delay)}
}

// uninstall entfernt das Paket samt Konfiguration, Token und Passkey-Liste. Es läuft in einer eigenen
// transienten Unit, weil das Entfernen die Agent-Dienste (auch diesen) beendet.
func (e Env) uninstall() Result {
	tool, args := "/usr/bin/dpkg", []string{"--purge", "lablantern-agent"}
	if e.PkgType == "rpm" {
		tool, args = "/usr/bin/rpm", []string{"-e", "lablantern-agent"}
	}
	run := append([]string{"--on-active=10", "--timer-property=AccuracySec=1s", "--unit=lablantern-uninstall",
		"--description=lablantern uninstall (passkey confirmed)", tool}, args...)
	if out, err := e.Run("systemd-run", run...); err != nil {
		return Result{Status: "failed", Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	return Result{Status: "done", Output: "Removing the agent from this host in 10 seconds."}
}

// update installiert das bereitgelegte Paket nur, wenn das Manifest mit dem Release-Schlüssel signiert ist,
// genau die freigegebene Version nennt, neuer ist als die laufende und die Prüfsumme stimmt.
func (e Env) update(version string) Result {
	if version == "" {
		return rejected("no target version")
	}
	name := PackageName(e.Arch, e.PkgType)
	work, err := os.MkdirTemp(e.StateDir, "update-")
	if err != nil {
		return Result{Status: "failed", Output: err.Error()}
	}
	defer os.RemoveAll(work)
	// erst in ein Verzeichnis kopieren, das nur root beschreiben kann; danach prüfen und genau diese Kopie installieren
	for _, f := range []string{"manifest.json", "manifest.json.sig", name} {
		data, err := jobs.ReadNoFollowIn(e.StageDir, f, maxPackage)
		if err != nil {
			return Result{Status: "failed", Output: fmt.Sprintf("%s: %v", f, err)}
		}
		if err := os.WriteFile(filepath.Join(work, f), data, 0o600); err != nil {
			return Result{Status: "failed", Output: err.Error()}
		}
	}
	manifest, _ := os.ReadFile(filepath.Join(work, "manifest.json"))
	sig, _ := os.ReadFile(filepath.Join(work, "manifest.json.sig"))
	m, err := release.Verify(manifest, sig, e.ReleaseKey)
	switch {
	case err != nil:
		return rejected("%v", err)
	case m.Version != version:
		return rejected("release %s does not match the confirmed version %s", m.Version, version)
	case !release.Newer(m.Version, e.AgentVersion):
		return rejected("release %s is not newer than the running %s", m.Version, e.AgentVersion)
	}
	pkg := filepath.Join(work, name)
	if err := m.CheckFile(name, pkg); err != nil {
		return rejected("%v", err)
	}
	args := []string{"-i", pkg}
	tool := "dpkg"
	if e.PkgType == "rpm" {
		tool, args = "rpm", []string{"-U", "--replacepkgs", pkg}
	}
	if out, err := e.Run(tool, args...); err != nil {
		return Result{Status: "failed", Output: strings.TrimSpace(out + "\n" + err.Error())}
	}
	return Result{Status: "done", Output: "Installed version " + m.Version}
}
