// Package config speichert, wie sich dieser Host beim Server anmeldet und wem er vertraut.
package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	ServerURL     string `json:"server_url"`
	AgentToken    string `json:"agent_token"`
	CAFingerprint string `json:"ca_fingerprint"`
	CAFile        string `json:"ca_file"`
	SystemID      int    `json:"system_id,omitempty"`
	// SHA-256 der Passkey-Liste aus dem Einrichtungsbefehl: Nur genau diese Liste wird als erste übernommen.
	PasskeysSHA256 string `json:"passkeys_sha256,omitempty"`
}

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

// NormalizeFingerprint macht aus "aa:bb ..." einheitlich "AABB...".
func NormalizeFingerprint(fp string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", " ", "", "\n", "").Replace(fp))
}

// FingerprintOfDER ist der SHA-256 eines Zertifikats (DER) ohne Trennzeichen, Großbuchstaben.
func FingerprintOfDER(der []byte) string {
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%X", sum[:])
}

// CAFilePath ist der feste Ablageort des gepinnten Wurzelzertifikats neben der Konfiguration.
func CAFilePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "ca.pem")
}

// Validate stellt sicher, dass der Agent nie ohne geprüften Vertrauensanker spricht.
func (c *Config) Validate() error {
	if !strings.HasPrefix(c.ServerURL, "https://") {
		return fmt.Errorf("server_url must start with https://")
	}
	if c.AgentToken == "" {
		return fmt.Errorf("no agent token")
	}
	if c.CAFingerprint == "" || c.CAFile == "" {
		return fmt.Errorf("no pinned root certificate")
	}
	data, err := os.ReadFile(c.CAFile)
	if err != nil {
		return fmt.Errorf("root certificate not readable: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("root certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return fmt.Errorf("root certificate is not a valid CA")
	}
	if FingerprintOfDER(cert.Raw) != NormalizeFingerprint(c.CAFingerprint) {
		return fmt.Errorf("root certificate no longer matches the pinned fingerprint")
	}
	return nil
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read configuration (%s): %w – not enrolled yet? Run 'lablantern-agent enroll' first", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON in configuration (%s): %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration %s unusable (%v): please enroll again with 'lablantern-agent enroll'", path, err)
	}
	return &cfg, nil
}

// SaveConfig schreibt Konfiguration (0600) und das öffentliche CA-Zertifikat (0644).
func SaveConfig(path string, cfg *Config, caPEM []byte) error {
	if path == "" {
		path = DefaultConfigPath()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", dir, err)
	}
	cfg.CAFile = CAFilePath(path)
	if err := os.WriteFile(cfg.CAFile, caPEM, 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", cfg.CAFile, err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("cannot write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	shareWithDaemon(dir, path)
	return nil
}

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
