// ll-release verwaltet den Signierschlüssel dieser Installation und veröffentlicht signierte Agent-Releases. Es
// läuft in den Containern agent-key, agent-build und agent-sign (deploy/compose.yaml) und nutzt nur die
// Standardbibliothek: Wo der private Schlüssel liegt, läuft kein fremder Code.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lablantern/agent/internal/release"
)

// Latest beschreibt das zuletzt veröffentlichte Release (<releases>/latest.json).
type Latest struct {
	Version   string `json:"version"`
	Source    string `json:"source"`     // SourceHash des Codes plus öffentlicher Schlüssel
	PublicKey string `json:"public_key"` // Base64
	Built     string `json:"built"`
}

// Plan legt agent-build für agent-sign in <stage>/plan.json ab.
type Plan struct {
	Version string `json:"version"`
	Source  string `json:"source"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ll-release init-key <key-file> <pub-file> | plan <src-dir> <releases-dir> | "+
			"publish <stage-dir> <releases-dir> <key-file> | verify <dir> <pub-file>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init-key":
		initKey(os.Args[2], os.Args[3])
	case "plan":
		plan(os.Args[2], os.Args[3])
	case "publish":
		publish(os.Args[2], os.Args[3], os.Args[4])
	case "verify":
		pub, err := readPub(os.Args[3])
		must(err)
		m, err := verify(os.Args[2], pub)
		must(err)
		fmt.Printf("ok: %s, %d files verified\n", m.Version, len(m.Files))
	default:
		fail("unknown command")
	}
}

// initKey legt beim ersten Start den Schlüssel an und schreibt immer den öffentlichen daneben.
func initKey(keyFile, pubFile string) {
	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		must(os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600))
		fmt.Println("created a new agent signing key")
	}
	key, err := readKey(keyFile)
	must(err)
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	must(writeAtomic(pubFile, []byte(pub+"\n"), 0o644))
	fmt.Println("agent signing key:", pub)
}

// plan gibt "<version> <source>" aus, wenn der Code (oder der Schlüssel) sich seit dem letzten Release geändert hat,
// sonst "unchanged <version>".
func plan(src, releases string) {
	base, err := os.ReadFile(filepath.Join(src, "VERSION"))
	must(err)
	pub, err := os.ReadFile(filepath.Join(releases, "release.pub"))
	must(err)
	hash, err := release.SourceHash(src)
	must(err)
	source := hash + ":" + strings.TrimSpace(string(pub))
	var last Latest
	if data, err := os.ReadFile(filepath.Join(releases, "latest.json")); err == nil {
		must(json.Unmarshal(data, &last))
	}
	if last.Source == source {
		fmt.Println("unchanged", last.Version)
		return
	}
	fmt.Println(release.NextVersion(strings.TrimSpace(string(base)), last.Version), source)
}

// publish signiert, was agent-build in <stage> abgelegt hat, und macht es zum neuesten Release.
func publish(stage, releases, keyFile string) {
	data, err := os.ReadFile(filepath.Join(stage, "plan.json"))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("nothing to publish")
		return
	}
	must(err)
	var p Plan
	must(json.Unmarshal(data, &p))
	target := filepath.Join(releases, p.Version)
	if _, err := os.Stat(target); err == nil {
		fmt.Println("release", p.Version, "already published")
		return
	}
	key, err := readKey(keyFile)
	must(err)
	tmp := target + ".tmp"
	must(os.RemoveAll(tmp))
	must(os.MkdirAll(tmp, 0o755))
	dist := filepath.Join(stage, "dist")
	names, _ := filepath.Glob(filepath.Join(dist, "lablantern-agent-*"))
	for _, n := range names {
		b, err := os.ReadFile(n)
		must(err)
		must(os.WriteFile(filepath.Join(tmp, filepath.Base(n)), b, 0o644))
	}
	m, err := release.BuildManifest(tmp, p.Version)
	must(err)
	manifest, sig := release.Sign(m, key)
	must(os.WriteFile(filepath.Join(tmp, "manifest.json"), manifest, 0o644))
	must(os.WriteFile(filepath.Join(tmp, "manifest.json.sig"), sig, 0o644))
	pub := key.Public().(ed25519.PublicKey)
	_, err = verify(tmp, pub)
	must(err)
	must(os.Rename(tmp, target))
	latest, _ := json.MarshalIndent(Latest{Version: p.Version, Source: p.Source,
		PublicKey: base64.StdEncoding.EncodeToString(pub), Built: time.Now().UTC().Format(time.RFC3339)}, "", "  ")
	must(writeAtomic(filepath.Join(releases, "latest.json"), latest, 0o644))
	fmt.Printf("published agent %s (%d files)\n", p.Version, len(m.Files))
}

func verify(dir string, pub ed25519.PublicKey) (*release.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "manifest.json.sig"))
	if err != nil {
		return nil, err
	}
	m, err := release.Verify(data, sig, pub)
	if err != nil {
		return nil, err
	}
	for name := range m.Files {
		if err := m.CheckFile(name, filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing key %s is invalid", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func readPub(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s is invalid", path)
	}
	return pub, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
