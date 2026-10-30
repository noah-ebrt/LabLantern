package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCA(t *testing.T) (pemBytes []byte, der []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func saved(t *testing.T) (string, *Config, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "etc", "agent.json")
	caPEM, der := newCA(t)
	cfg := &Config{ServerURL: "https://srv:8443", AgentToken: "tok", CAFingerprint: FingerprintOfDER(der), SystemID: 3}
	if err := SaveConfig(path, cfg, caPEM); err != nil {
		t.Fatal(err)
	}
	return path, cfg, caPEM
}

func TestSaveAndLoadRoundtrip(t *testing.T) {
	path, cfg, _ := saved(t)
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerURL != cfg.ServerURL || got.AgentToken != "tok" || got.SystemID != 3 {
		t.Fatalf("unerwartet: %+v", got)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	path, _, _ := saved(t)
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("Konfiguration muss 0600 sein, ist %o", st.Mode().Perm())
	}
	dir, _ := os.Stat(filepath.Dir(path))
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("Verzeichnis muss 0700 sein, ist %o", dir.Mode().Perm())
	}
}

func TestCAFileLivesNextToTheConfig(t *testing.T) {
	path, _, _ := saved(t)
	got, _ := LoadConfig(path)
	if got.CAFile != CAFilePath(path) {
		t.Fatalf("CA-Datei %q", got.CAFile)
	}
}

func TestOldConfigWithoutTrustAnchorIsRefusedWithAReEnrollHint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(path, []byte(`{"server_url":"https://srv:8443","agent_token":"tok","system_id":1}`), 0o600)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("erwartet Hinweis auf 'enroll', erhalten: %v", err)
	}
}

func TestPlainHTTPServerURLIsRefused(t *testing.T) {
	path, cfg, caPEM := saved(t)
	cfg.ServerURL = "http://srv:8000"
	if err := SaveConfig(path, cfg, caPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("http:// darf nicht akzeptiert werden")
	}
}

func TestSwappedCAFileIsDetected(t *testing.T) {
	path, _, _ := saved(t)
	other, _ := newCA(t)
	os.WriteFile(CAFilePath(path), other, 0o644)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("ausgetauschte CA muss auffallen: %v", err)
	}
}

func TestFingerprintNormalization(t *testing.T) {
	if NormalizeFingerprint("aa:bb:CC dd") != "AABBCCDD" {
		t.Fatal("Normalisierung")
	}
}
