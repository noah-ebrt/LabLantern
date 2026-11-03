package jobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lablantern/agent/internal/collector"
)

const (
	imgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func paths(t *testing.T) Paths {
	in, out := t.TempDir(), t.TempDir()
	return Paths{RequestFile: filepath.Join(in, "collect.request"), OutDir: out}
}

func report() *collector.HostReport {
	return &collector.HostReport{Containers: []collector.ContainerInfo{{ImageID: imgA}}}
}

func TestRoundTripOnlyGeneratesSBOMsForOwnImages(t *testing.T) {
	p := paths(t)
	nonce := NewNonce()
	if err := p.Submit(Request{Nonce: nonce, SBOMImages: []string{imgA, imgB, imgA, "../../etc/shadow"}}); err != nil {
		t.Fatal(err)
	}
	req, err := p.Take()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.RequestFile); !os.IsNotExist(err) {
		t.Fatal("request must be consumed")
	}
	var asked []string
	err = p.Execute(req, report, func(id string) ([]byte, error) { asked = append(asked, id); return []byte(`{}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != imgA {
		t.Fatalf("generated for %v", asked)
	}
	res, err := p.Wait(nonce, time.Second, time.Millisecond)
	if err != nil || len(res.SBOMs) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	if data, err := p.ReadSBOM(res.SBOMs[0]); err != nil || string(data) != `{}` {
		t.Fatalf("%v %s", err, data)
	}
}

func TestTakeRefusesSymlinksAndGarbage(t *testing.T) {
	p := paths(t)
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte(`{"nonce":"`+strings.Repeat("a", 32)+`"}`), 0o600)
	os.Symlink(secret, p.RequestFile)
	if _, err := p.Take(); err == nil {
		t.Fatal("symlink must not be followed")
	}
	os.Remove(p.RequestFile)
	os.WriteFile(p.RequestFile, []byte(`{"nonce":"x"}`), 0o600)
	if _, err := p.Take(); err == nil {
		t.Fatal("invalid nonce accepted")
	}
}

func TestWaitIgnoresResultsOfOtherRequests(t *testing.T) {
	p := paths(t)
	if err := p.Execute(&Request{Nonce: NewNonce()}, report, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wait(NewNonce(), 20*time.Millisecond, time.Millisecond); err == nil {
		t.Fatal("stale result accepted")
	}
	if _, err := p.ReadSBOM(SBOM{File: "../result.json"}); err == nil {
		t.Fatal("path traversal accepted")
	}
}
