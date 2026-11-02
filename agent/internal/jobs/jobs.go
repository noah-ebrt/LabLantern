// Package jobs verbindet den unprivilegierten Daemon (Benutzer vulnwatch, mit Netz) mit dem Sammler
// (root, ohne Netz). Der Daemon legt einen Auftrag in sein eigenes Verzeichnis, eine systemd-Path-Unit
// startet den Sammler, der Sammler schreibt das Ergebnis in ein Verzeichnis, das nur root beschreiben darf.
// Der Auftrag gilt als nicht vertrauenswürdig: Er kann nur Image-SBOMs aus dem eigenen Inventar anfordern.
package jobs

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"vulnwatch/agent/internal/collector"
	"vulnwatch/agent/internal/queries"
)

const (
	maxRequest = 64 * 1024
	// MaxSBOMs begrenzt die Laufzeit eines Auftrags; der Rest folgt im nächsten.
	MaxSBOMs   = 10
	resultName = "result.json"
)

var (
	nonceRe   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	imageIDRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	sbomName  = regexp.MustCompile(`^sbom-[0-9]{1,2}\.json$`)
)

type Request struct {
	Nonce      string   `json:"nonce"`
	SBOMImages []string `json:"sbom_images,omitempty"`
	Query      string   `json:"query,omitempty"` // feste Abfrage statt Report (queries.Names)
}

type SBOM struct {
	ImageID string `json:"image_id"`
	File    string `json:"file,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Result struct {
	Nonce  string                `json:"nonce"`
	Report *collector.HostReport `json:"report"`
	SBOMs  []SBOM                `json:"sboms,omitempty"`
	// Antwort auf eine Abfrage (dann ohne Report)
	QueryOutput string `json:"query_output,omitempty"`
	QueryError  string `json:"query_error,omitempty"`
}

// Paths sind die beiden Verzeichnisse; austauschbar für Tests.
type Paths struct {
	RequestFile string // im Verzeichnis des Daemons
	OutDir      string // nur root darf schreiben
}

func Default() Paths {
	return Paths{RequestFile: "/run/vulnwatch/collect.request", OutDir: "/run/vulnwatch-out"}
}

func NewNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Submit legt einen Auftrag atomar ab (Daemon-Seite).
func (p Paths) Submit(req Request) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	tmp := p.RequestFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("cannot write collect request: %w", err)
	}
	return os.Rename(tmp, p.RequestFile)
}

// Wait wartet auf das Ergebnis genau dieses Auftrags (Daemon-Seite).
func (p Paths) Wait(nonce string, timeout, interval time.Duration) (*Result, error) {
	deadline := time.Now().Add(timeout)
	for {
		if data, err := os.ReadFile(filepath.Join(p.OutDir, resultName)); err == nil {
			var res Result
			if json.Unmarshal(data, &res) == nil && res.Nonce == nonce {
				return &res, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("collector did not answer within %s (journalctl -u vulnwatch-collect.service)", timeout)
		}
		time.Sleep(interval)
	}
}

// ReadSBOM liest eine vom Sammler erzeugte SBOM; nur Dateinamen im festen Muster.
func (p Paths) ReadSBOM(s SBOM) ([]byte, error) {
	if !sbomName.MatchString(s.File) {
		return nil, fmt.Errorf("invalid SBOM file name")
	}
	return os.ReadFile(filepath.Join(p.OutDir, s.File))
}

// Take liest und löscht den Auftrag (Sammler-Seite, root). Symlinks werden nicht verfolgt, damit der
// Daemon root keine fremde Datei unterschieben kann.
func (p Paths) Take() (*Request, error) {
	data, err := TakeFile(p.RequestFile, maxRequest)
	if err != nil {
		return nil, fmt.Errorf("collect request: %w", err)
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil || !nonceRe.MatchString(req.Nonce) {
		return nil, fmt.Errorf("collect request invalid")
	}
	return &req, nil
}

// TakeFile liest eine Datei aus dem Verzeichnis des Daemons und löscht sie. Symlinks werden nicht verfolgt
// und nur reguläre Dateien bis max Bytes gelesen, damit der Daemon root keine fremde Datei unterschieben kann.
func TakeFile(path string, max int64) ([]byte, error) {
	data, err := ReadNoFollow(path, max)
	_ = os.Remove(path)
	return data, err
}

// ReadNoFollow liest eine reguläre Datei ohne Symlinks zu verfolgen, höchstens max Bytes.
func ReadNoFollow(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	return readRegular(f, max)
}

// ReadNoFollowIn liest name aus dir, ohne dir oder name als Symlink zu verfolgen. Für Verzeichnisse, die dem
// Daemon gehören: Er könnte sie sonst auf eine fremde Stelle umbiegen, und root läse von dort.
func ReadNoFollowIn(dir, name string, max int64) ([]byte, error) {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	defer d.Close()
	fd, err := syscall.Openat(int(d.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	return readRegular(os.NewFile(uintptr(fd), filepath.Join(dir, name)), max)
}

func readRegular(f *os.File, max int64) ([]byte, error) {
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, fmt.Errorf("unreadable or too large")
	}
	return data, nil
}

// Execute sammelt, erzeugt angeforderte SBOMs nur für Images aus dem eigenen Inventar und schreibt
// das Ergebnis atomar (Sammler-Seite, root).
func (p Paths) Execute(req *Request, collect func() *collector.HostReport, sbom func(string) ([]byte, error)) error {
	old, _ := filepath.Glob(filepath.Join(p.OutDir, "sbom-*.json"))
	for _, f := range old {
		_ = os.Remove(f)
	}
	if req.Query != "" {
		res := Result{Nonce: req.Nonce}
		out, err := queries.Run(req.Query) // prüft die Positivliste selbst
		res.QueryOutput = out
		if err != nil {
			res.QueryError = err.Error()
		}
		data, err := json.Marshal(res)
		if err != nil {
			return err
		}
		return WriteAtomic(filepath.Join(p.OutDir, resultName), data)
	}
	res := Result{Nonce: req.Nonce, Report: collect()}
	own := map[string]bool{}
	for _, c := range res.Report.Containers {
		own[c.ImageID] = true
	}
	seen := map[string]bool{}
	for _, id := range req.SBOMImages {
		if !imageIDRe.MatchString(id) || !own[id] || seen[id] || len(res.SBOMs) >= MaxSBOMs {
			continue
		}
		seen[id] = true
		entry := SBOM{ImageID: id}
		data, err := sbom(id)
		if err == nil {
			entry.File = fmt.Sprintf("sbom-%d.json", len(res.SBOMs))
			err = WriteAtomic(filepath.Join(p.OutDir, entry.File), data)
		}
		if err != nil {
			entry.File, entry.Error = "", err.Error()
		}
		res.SBOMs = append(res.SBOMs, entry)
	}
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return WriteAtomic(filepath.Join(p.OutDir, resultName), data)
}

// WriteAtomic schreibt über eine Temp-Datei im Zielverzeichnis und benennt sie dann um (0644).
func WriteAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}
