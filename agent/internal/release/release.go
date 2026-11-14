// Package release beschreibt signierte Agent-Releases: ein Manifest mit Version und SHA-256 je Binary,
// signiert mit Ed25519. Jede Installation baut ihre Agenten selbst (deploy/compose.yaml: agent-key, agent-build,
// agent-sign); der private Schlüssel liegt nur im Volume des Signier-Containers, nie im Server. Agent und Server
// kennen nur den öffentlichen. Ein übernommener Server kann deshalb kein Agent-Binary unterschieben.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// publicKeyB64 ist der öffentliche Release-Schlüssel dieser Installation. Der Build setzt ihn
// (-ldflags "-X lablantern/agent/internal/release.publicKeyB64=…", siehe packaging/build-agent.sh); ohne ihn nimmt
// der Agent keine Updates an.
var publicKeyB64 string

type Manifest struct {
	Version string            `json:"version"`
	Created string            `json:"created"`
	Files   map[string]string `json:"files"` // Dateiname -> SHA-256 (hex)
}

func PublicKey() ed25519.PublicKey {
	k, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(k)
}

func fileSHA(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// BuildManifest erfasst alle lablantern-agent-* Dateien eines Build-Verzeichnisses.
func BuildManifest(dir, version string) (*Manifest, error) {
	m := &Manifest{Version: version, Created: time.Now().UTC().Format(time.RFC3339), Files: map[string]string{}}
	paths, _ := filepath.Glob(filepath.Join(dir, "lablantern-agent-*"))
	for _, p := range paths {
		sum, err := fileSHA(p)
		if err != nil {
			return nil, err
		}
		m.Files[filepath.Base(p)] = sum
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("no agent binaries in %s", dir)
	}
	return m, nil
}

// Sign liefert die Manifest-Bytes und die Base64-Signatur genau über diese Bytes.
func Sign(m *Manifest, key ed25519.PrivateKey) ([]byte, []byte) {
	data, _ := json.MarshalIndent(m, "", "  ")
	sig := ed25519.Sign(key, data)
	return data, []byte(base64.StdEncoding.EncodeToString(sig))
}

func Verify(data, sigB64 []byte, pub ed25519.PublicKey) (*Manifest, error) {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, sig) {
		return nil, fmt.Errorf("release signature invalid")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil || m.Version == "" || len(m.Files) == 0 {
		return nil, fmt.Errorf("release manifest invalid")
	}
	return &m, nil
}

// CheckFile prüft eine heruntergeladene Datei gegen die signierte Prüfsumme.
func (m *Manifest) CheckFile(name, path string) error {
	want, ok := m.Files[name]
	if !ok {
		return fmt.Errorf("%s is not part of release %s", name, m.Version)
	}
	got, err := fileSHA(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return nil
}

// Newer meldet, ob Version a echt neuer ist als b (keine Downgrades).
func Newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// NextVersion wählt die Version eines neuen Builds: base (agent/VERSION), wenn sie neuer ist als das letzte Release,
// sonst dessen Patch-Nummer plus eins. Geänderter Code bekommt so nie die Version eines älteren Builds.
func NextVersion(base, last string) string {
	if last == "" || Newer(base, last) {
		return base
	}
	p := strings.Split(last, ".")
	for len(p) < 3 {
		p = append(p, "0")
	}
	n, _ := strconv.Atoi(p[2])
	return fmt.Sprintf("%s.%s.%d", p[0], p[1], n+1)
}

// SourceHash ist die SHA-256 über alle Dateien unter dir (Pfad, Länge und Inhalt, in lexikalischer Reihenfolge).
// Tests ändern das Binary nicht und zählen deshalb nicht mit.
func SourceHash(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(rel), len(data))
		h.Write(data)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil)), err
}
