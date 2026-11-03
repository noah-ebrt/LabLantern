package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func dist(t *testing.T) string {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "lablantern-agent-linux-amd64"), []byte("amd64-binary"), 0o755)
	os.WriteFile(filepath.Join(d, "lablantern-agent-linux-arm64"), []byte("arm64-binary"), 0o755)
	return d
}

func TestSignedManifestVerifiesAndListsChecksums(t *testing.T) {
	pub, priv := keys(t)
	m, err := BuildManifest(dist(t), "0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	data, sig := Sign(m, priv)
	got, err := Verify(data, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "0.5.0" || len(got.Files) != 2 || got.Files["lablantern-agent-linux-amd64"] == "" {
		t.Fatalf("Manifest: %+v", got)
	}
}

func TestTamperedManifestOrWrongKeyIsRejected(t *testing.T) {
	pub, priv := keys(t)
	other, _ := keys(t)
	m, _ := BuildManifest(dist(t), "0.5.0")
	data, sig := Sign(m, priv)
	if _, err := Verify(data, sig, other); err == nil {
		t.Fatal("fremder Schlüssel muss scheitern")
	}
	bad := []byte(strings.Replace(string(data), "0.5.0", "9.9.9", 1))
	if _, err := Verify(bad, sig, pub); err == nil {
		t.Fatal("verändertes Manifest muss scheitern")
	}
}

func TestBinaryMustMatchTheSignedChecksum(t *testing.T) {
	_, priv := keys(t)
	d := dist(t)
	m, _ := BuildManifest(d, "0.5.0")
	data, sig := Sign(m, priv)
	pub := priv.Public().(ed25519.PublicKey)
	got, _ := Verify(data, sig, pub)
	if err := got.CheckFile("lablantern-agent-linux-amd64", filepath.Join(d, "lablantern-agent-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "lablantern-agent-linux-amd64"), []byte("manipuliert"), 0o755)
	if err := got.CheckFile("lablantern-agent-linux-amd64", filepath.Join(d, "lablantern-agent-linux-amd64")); err == nil {
		t.Fatal("manipuliertes Binary muss scheitern")
	}
	if err := got.CheckFile("nicht-im-manifest", filepath.Join(d, "lablantern-agent-linux-amd64")); err == nil {
		t.Fatal("unbekannte Datei muss scheitern")
	}
}

func TestVersionComparisonRefusesDowngrades(t *testing.T) {
	if !Newer("0.5.1", "0.5.0") || Newer("0.5.0", "0.5.0") || Newer("0.4.9", "0.5.0") || !Newer("0.10.0", "0.9.9") {
		t.Fatal("Versionsvergleich")
	}
}

func TestPublicKeyComesFromTheBuild(t *testing.T) {
	defer func(old string) { publicKeyB64 = old }(publicKeyB64)
	publicKeyB64 = ""
	if PublicKey() != nil {
		t.Fatal("ohne Schlüssel aus dem Build darf es keinen geben")
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	publicKeyB64 = base64.StdEncoding.EncodeToString(pub)
	if !PublicKey().Equal(pub) {
		t.Fatal("Schlüssel aus dem Build nicht übernommen")
	}
}

func TestNextVersionNeverReusesAVersion(t *testing.T) {
	for _, c := range [][3]string{
		{"0.16.0", "", "0.16.0"},       // erster Build
		{"0.16.0", "0.15.0", "0.16.0"}, // VERSION angehoben
		{"0.16.0", "0.16.0", "0.16.1"}, // Code geändert, VERSION nicht
		{"0.16.0", "0.16.4", "0.16.5"},
		{"0.16.1", "0.16.3", "0.16.4"}, // VERSION hinter lokalen Builds
	} {
		if got := NextVersion(c[0], c[1]); got != c[2] {
			t.Errorf("NextVersion(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestSourceHashSeesContentAndNames(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("x"), 0o644)
	h1, _ := SourceHash(dir)
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("y"), 0o644)
	h2, _ := SourceHash(dir)
	os.Rename(filepath.Join(dir, "a.go"), filepath.Join(dir, "b.go"))
	h3, _ := SourceHash(dir)
	os.WriteFile(filepath.Join(dir, "b_test.go"), []byte("test"), 0o644)
	h4, _ := SourceHash(dir)
	if h1 == h2 || h2 == h3 || h1 == "" || h3 != h4 {
		t.Fatal("Hash folgt nicht Inhalt und Name, oder zählt Tests mit")
	}
}
