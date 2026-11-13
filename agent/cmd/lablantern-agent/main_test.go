package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lablantern/agent/internal/actions"
	"lablantern/agent/internal/collector"
	"lablantern/agent/internal/config"
	"lablantern/agent/internal/discover"
	"lablantern/agent/internal/jobs"
	"lablantern/agent/internal/pairing"
	"lablantern/agent/internal/passkey"
	"lablantern/agent/internal/passkey/passkeytest"
)

type serverFixture struct {
	srv      *httptest.Server
	caPEM    []byte
	fp       string
	mu       sync.Mutex
	enrolled []map[string]any
	reports  []map[string]any
	uploads  []map[string]any
	needed   []string
	due      bool
	commands []map[string]any
	trust    map[string]any
	results  map[string]map[string]any
	pairs    []map[string]any
	reveals  []map[string]any
	noNonce  bool
	pairing  string
	auth     []string
	status   int
}

func newServer(t *testing.T) *serverFixture {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "s"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)

	f := &serverFixture{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		fp: config.FingerprintOfDER(caDER), status: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) { w.Write(f.caPEM) })
	mux.HandleFunc("/api/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.enrolled = append(f.enrolled, body)
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "system_id": 5, "agent_token": "agent-geheim", "status": "pending"})
	})
	mux.HandleFunc("/api/agent/report", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.reports = append(f.reports, body)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if f.status != 200 {
			w.WriteHeader(f.status)
			w.Write([]byte(`{"detail":"System is waiting for approval by the administrator"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "needed_sboms": f.needed})
	})
	mux.HandleFunc("/api/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"report": f.due})
	})
	mux.HandleFunc("/api/agent/pair", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.pairs = append(f.pairs, body)
		f.mu.Unlock()
		if f.noNonce {
			w.Write([]byte(`{"pairing_id":3}`))
			return
		}
		w.Write([]byte(`{"pairing_id":3,"nonce":"0123456789abcdef0123456789abcdef"}`))
	})
	mux.HandleFunc("/api/agent/pair/3/reveal", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.reveals = append(f.reveals, body)
		f.mu.Unlock()
		w.Write([]byte(`{"status":"pending"}`))
	})
	mux.HandleFunc("/api/agent/pair/3/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": f.pairing, "agent_token": "paired-token", "system_id": 8})
	})
	mux.HandleFunc("/api/agent/commands/next", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		cmds := f.commands
		f.commands = nil
		f.mu.Unlock()
		if cmds == nil {
			cmds = []map[string]any{}
		}
		json.NewEncoder(w).Encode(map[string]any{"report": f.due, "commands": cmds, "passkeys": f.trust})
	})
	mux.HandleFunc("/api/agent/commands/", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		if f.results == nil {
			f.results = map[string]map[string]any{}
		}
		f.results[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/agent/commands/"), "/result")] = body
		f.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/agent/image-sbom", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.uploads = append(f.uploads, body)
		f.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	})
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func fakeEnv() collector.Env {
	return collector.Env{
		ReadFile: func(p string) ([]byte, error) {
			if p == "/etc/os-release" {
				return []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.5 LTS\"\n"), nil
			}
			return nil, errors.New("nope")
		},
		Exists: func(p string) bool { return false },
		LookPath: func(n string) (string, error) {
			if n == "dpkg-query" {
				return "/x", nil
			}
			return "", errors.New("no")
		},
		Run: func(n string, a ...string) ([]byte, error) {
			if n == "dpkg-query" {
				return []byte("curl\t8.5.0\tamd64\tcurl\t8.5.0\tinstall ok installed\n"), nil
			}
			return []byte("6.8.0\n"), nil
		},
		DockerGet: func(string) ([]byte, int, error) { return nil, 0, collector.ErrNoDocker },
	}
}

func runCmd(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e, fakeEnv())
	return code, o.String(), e.String()
}

func TestEnrollEndToEndStoresAPinnedConfig(t *testing.T) {
	s := newServer(t)
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	code, out, errOut := runCmd("enroll", "--server", s.srv.URL, "--token", "einmal", "--ca-fingerprint", s.fp,
		"--config", cfgPath, "--hostname", "host-a")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil || cfg.AgentToken != "agent-geheim" || cfg.SystemID != 5 {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	if len(s.enrolled) != 1 || s.enrolled[0]["enrollment_token"] != "einmal" || s.enrolled[0]["hostname"] != "host-a" {
		t.Fatalf("Server sah: %+v", s.enrolled)
	}
	if !strings.Contains(out, "approve") {
		t.Fatalf("Hinweis zum Freigeben fehlt:\n%s", out)
	}
}

func TestEnrollWithWrongFingerprintSendsNothingAndStoresNothing(t *testing.T) {
	s := newServer(t)
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	code, _, errOut := runCmd("enroll", "--server", s.srv.URL, "--token", "einmal",
		"--ca-fingerprint", strings.Repeat("00", 32), "--config", cfgPath)
	if code == 0 || !strings.Contains(errOut, "NOT") {
		t.Fatalf("erwartet Abbruch mit Hinweis, exit=%d err=%s", code, errOut)
	}
	if len(s.enrolled) != 0 {
		t.Fatal("das Einmal-Token darf bei falschem Fingerabdruck nie gesendet werden")
	}
	if _, err := config.LoadConfig(cfgPath); err == nil {
		t.Fatal("es darf keine Konfiguration entstehen")
	}
}

func TestEnrollRequiresTheFingerprint(t *testing.T) {
	s := newServer(t)
	code, _, errOut := runCmd("enroll", "--server", s.srv.URL, "--token", "x", "--config", filepath.Join(t.TempDir(), "a.json"))
	if code == 0 || !strings.Contains(errOut, "ca-fingerprint") || len(s.enrolled) != 0 {
		t.Fatalf("exit=%d err=%s", code, errOut)
	}
}

func enrolled(t *testing.T, s *serverFixture) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	if code, _, e := runCmd("enroll", "--server", s.srv.URL, "--token", "t", "--ca-fingerprint", s.fp, "--config", cfgPath); code != 0 {
		t.Fatal(e)
	}
	return cfgPath
}

func TestScanSendsTheCollectedReportWithTheAgentToken(t *testing.T) {
	s := newServer(t)
	s.status = 200
	cfgPath := enrolled(t, s)
	code, out, errOut := runCmd("scan", "--config", cfgPath)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if len(s.reports) != 1 || s.auth[0] != "Bearer agent-geheim" {
		t.Fatalf("Reports=%d auth=%v", len(s.reports), s.auth)
	}
	if s.reports[0]["os_id"] != "ubuntu" || s.reports[0]["agent_version"] != AgentVersion {
		t.Fatalf("Report: %+v", s.reports[0])
	}
}

func TestScanPrintsCollectionWarningsButStillReports(t *testing.T) {
	s := newServer(t)
	s.status = 200
	cfgPath := enrolled(t, s)
	var o, e bytes.Buffer
	env := fakeEnv()
	env.DockerGet = func(string) ([]byte, int, error) { return nil, 0, errors.New("permission denied") }
	if code := run([]string{"scan", "--config", cfgPath}, &o, &e, env); code != 0 {
		t.Fatalf("exit %d: %s", code, e.String())
	}
	if !strings.Contains(e.String(), "permission denied") || len(s.reports) != 1 {
		t.Fatalf("Warnung fehlt oder kein Report: %q", e.String())
	}
}

func TestScanWithoutAValidConfigFailsLoudly(t *testing.T) {
	code, _, errOut := runCmd("scan", "--config", filepath.Join(t.TempDir(), "gibts-nicht.json"))
	if code == 0 || !strings.Contains(errOut, "enroll") {
		t.Fatalf("exit=%d err=%s", code, errOut)
	}
}

func TestScanFailsWithNonZeroExitWhenTheServerRefuses(t *testing.T) {
	s := newServer(t)
	s.status = 403
	cfgPath := enrolled(t, s)
	code, _, errOut := runCmd("scan", "--config", cfgPath)
	if code == 0 || !strings.Contains(errOut, "approval") {
		t.Fatalf("exit=%d err=%s", code, errOut)
	}
}

func TestVersionAndUnknownCommand(t *testing.T) {
	if code, out, _ := runCmd("version"); code != 0 || !strings.Contains(out, AgentVersion) {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _, _ := runCmd("quatsch"); code == 0 {
		t.Fatal("unbekanntes Kommando muss scheitern")
	}
	if code, _, _ := runCmd(); code == 0 {
		t.Fatal("ohne Kommando muss Hilfe + Fehlercode kommen")
	}
}

const imgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const imgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func envWithContainers() collector.Env {
	env := fakeEnv()
	env.DockerGet = func(string) ([]byte, int, error) {
		return []byte(`[{"Id":"c1","Names":["/web"],"Image":"nginx:1.27","ImageID":"` + imgA + `","State":"running"}]`), 200, nil
	}
	return env
}

func TestScanUploadsSBOMsOnlyForRequestedImagesFromItsOwnInventory(t *testing.T) {
	s := newServer(t)
	s.needed = []string{imgA, imgB} // imgB läuft hier nicht: darf nie erzeugt werden
	cfgPath := enrolled(t, s)
	var generated []string
	imageSBOM = func(id string) ([]byte, error) {
		generated = append(generated, id)
		return []byte(`{"bomFormat":"CycloneDX"}`), nil
	}
	var o, e bytes.Buffer
	if code := run([]string{"scan", "--config", cfgPath}, &o, &e, envWithContainers()); code != 0 {
		t.Fatalf("exit %d: %s", code, e.String())
	}
	if len(generated) != 1 || generated[0] != imgA {
		t.Fatalf("erzeugt: %v", generated)
	}
	if len(s.uploads) != 1 || s.uploads[0]["image_id"] != imgA || s.uploads[0]["sbom"] == nil {
		t.Fatalf("Uploads: %+v", s.uploads)
	}
}

func TestImageSBOMFailureIsReportedToTheServer(t *testing.T) {
	s := newServer(t)
	s.needed = []string{imgA}
	cfgPath := enrolled(t, s)
	imageSBOM = func(string) ([]byte, error) { return nil, errors.New("docker save fehlgeschlagen") }
	var o, e bytes.Buffer
	run([]string{"scan", "--config", cfgPath}, &o, &e, envWithContainers())
	if len(s.uploads) != 1 || !strings.Contains(fmt.Sprint(s.uploads[0]["error"]), "docker save") {
		t.Fatalf("Uploads: %+v", s.uploads)
	}
}

// fakeCollector spielt lablantern-collect.service: nimmt den Auftrag des Daemons an und arbeitet ihn ab.
func fakeCollector(t *testing.T, p jobs.Paths, env collector.Env) (stop func()) {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if _, err := os.Stat(p.RequestFile); err == nil {
				runCollectJob(io.Discard, env, p)
			}
		}
	}()
	return func() { close(done) }
}

func daemonSetup(t *testing.T) (*serverFixture, string, jobs.Paths, *[]string) {
	s := newServer(t)
	cfgPath := enrolled(t, s)
	dir := t.TempDir()
	p := jobs.Paths{RequestFile: filepath.Join(dir, "collect.request"), OutDir: dir}
	waitTimeout, waitInterval = 5*time.Second, 5*time.Millisecond
	generated := &[]string{}
	imageSBOM = func(id string) ([]byte, error) {
		*generated = append(*generated, id)
		return []byte(`{"bomFormat":"CycloneDX"}`), nil
	}
	return s, cfgPath, p, generated
}

func TestDaemonReportsOnlyWhenDueAndViaTheCollector(t *testing.T) {
	s, cfgPath, p, generated := daemonSetup(t)
	s.needed = []string{imgA, imgB}
	defer fakeCollector(t, p, envWithContainers())()

	var o, e bytes.Buffer
	if !daemonStep(cfgPath, p, false, 0, &o, &e) || len(s.reports) != 0 {
		t.Fatalf("nicht fällig: reports=%d %s", len(s.reports), e.String())
	}
	s.due = true
	if !daemonStep(cfgPath, p, false, 0, &o, &e) || len(s.reports) != 1 {
		t.Fatalf("fällig: reports=%d %s", len(s.reports), e.String())
	}
	if len(*generated) != 1 || (*generated)[0] != imgA || len(s.uploads) != 1 || s.uploads[0]["sbom"] == nil {
		t.Fatalf("SBOMs: erzeugt=%v uploads=%+v", *generated, s.uploads)
	}
	s.due = false
	if !daemonStep(cfgPath, p, true, 0, &o, &e) || len(s.reports) != 2 {
		t.Fatalf("erzwungen nach Start: reports=%d %s", len(s.reports), e.String())
	}
}

func TestDaemonRunsOnlyAllowlistedCommands(t *testing.T) {
	s, cfgPath, p, _ := daemonSetup(t)
	defer fakeCollector(t, p, fakeEnv())()
	s.commands = []map[string]any{
		{"id": 1, "type": "report_now", "params": map[string]string{}},
		{"id": 2, "type": "query", "params": map[string]string{"name": "uptime"}},
		{"id": 3, "type": "query", "params": map[string]string{"name": "cat /etc/shadow"}},
		{"id": 4, "type": "shell", "params": map[string]string{"cmd": "id"}},
		{"id": 5, "type": "report_now", "params": map[string]string{}},
	}
	var o, e bytes.Buffer
	if !daemonStep(cfgPath, p, false, 0, &o, &e) {
		t.Fatal(e.String())
	}
	st := func(id string) string { return fmt.Sprint(s.results[id]["status"]) }
	if st("1") != "done" || len(s.reports) != 1 || st("5") != "done" {
		t.Fatalf("report_now: %+v reports=%d", s.results, len(s.reports))
	}
	if st("2") != "done" && st("2") != "failed" { // je nach Testumgebung ist /proc/uptime lesbar
		t.Fatalf("query: %+v", s.results["2"])
	}
	if st("3") != "rejected" || st("4") != "rejected" {
		t.Fatalf("nicht erlaubte Befehle: %+v", s.results)
	}
}

func TestDaemonFailsCleanlyWhenTheCollectorDoesNotAnswer(t *testing.T) {
	s, cfgPath, p, _ := daemonSetup(t)
	waitTimeout = 50 * time.Millisecond
	var o, e bytes.Buffer
	if daemonStep(cfgPath, p, true, 0, &o, &e) || len(s.reports) != 0 || !strings.Contains(e.String(), "collector") {
		t.Fatalf("reports=%d %s", len(s.reports), e.String())
	}
}

func TestDaemonSyncsPasskeysAndHandsSignedRebootToRoot(t *testing.T) {
	s, cfgPath, p, _ := daemonSetup(t)
	dir := t.TempDir()
	ran := []string{}
	env := actions.Env{
		Paths: actions.Paths{RequestFile: filepath.Join(dir, "action.request"), ResultFile: filepath.Join(dir, "result.json"),
			TrustFile: filepath.Join(dir, "passkeys.json"), StateDir: filepath.Join(dir, "state"), StageDir: filepath.Join(dir, "stage")},
		SystemID: 5, AgentVersion: AgentVersion, Now: time.Now, PkgType: "deb", Arch: "amd64",
		Run: func(name string, args ...string) (string, error) { ran = append(ran, name); return "", nil },
	}
	actionPaths, lastTrustTry = env.Paths, 0
	defer func() { actionPaths = actions.DefaultPaths() }()
	done := make(chan struct{})
	defer close(done)
	go func() { // spielt lablantern-action.service
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if _, err := os.Stat(env.RequestFile); err == nil {
				env.Handle()
			}
		}
	}()

	key := passkeytest.NewSoftKey(t)
	trust, _ := json.Marshal(passkey.TrustSet{Kind: "passkeys", Rev: 1, RPID: "lablantern.lan", Keys: []passkey.Key{key.Key()}})
	s.trust = map[string]any{"rev": 1, "envelope": string(trust), "assertion": ""}
	now := time.Now().Unix()
	cmd, _ := json.Marshal(map[string]any{"kind": "command", "system_id": 5, "type": "reboot", "params": map[string]any{"delay": 30},
		"issued_at": now, "expires_at": now + 300, "nonce": "0123456789abcdef0123456789abcdef"})
	sig, _ := json.Marshal(key.Sign(string(cmd), "lablantern.lan", "https://lablantern.lan:8443", 0x05))
	s.commands = []map[string]any{{"id": 9, "type": "reboot", "params": map[string]string{
		"delay": "30", "envelope": string(cmd), "assertion": string(sig)}}}

	var o, e bytes.Buffer
	if !daemonStep(cfgPath, p, false, 0, &o, &e) {
		t.Fatal(e.String())
	}
	if env.TrustRev() != 1 || fmt.Sprint(s.results["9"]["status"]) != "done" || len(ran) != 1 || ran[0] != "systemd-run" {
		t.Fatalf("trust=%d result=%+v ran=%v out=%s err=%s", env.TrustRev(), s.results["9"], ran, o.String(), e.String())
	}
}

func TestSetupDiscoversPairsShowsTheCodeAndPinsTheCA(t *testing.T) {
	s := newServer(t)
	s.pairing = "approved"
	discoverMasters = func(time.Duration) ([]string, error) { return []string{s.srv.URL}, nil }
	defer func() { discoverMasters = discover.Masters }()
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	code, out, errOut := runCmd("setup", "--config", cfgPath, "--hostname", "newhost")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	// erst nur das Commitment, das Geheimnis kommt im zweiten Schritt und muss dazu passen
	if _, sent := s.pairs[0]["secret"]; sent {
		t.Fatalf("secret sent with the first request: %+v", s.pairs[0])
	}
	secret := fmt.Sprint(s.reveals[0]["secret"])
	if s.pairs[0]["hostname"] != "newhost" || len(secret) != 64 || s.pairs[0]["commitment"] != pairing.Commitment(secret) ||
		!strings.Contains(out, pairing.Code(s.fp, secret, "0123456789abcdef0123456789abcdef")) {
		t.Fatalf("pair request %+v %+v, output %s", s.pairs, s.reveals, out)
	}
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil || cfg.AgentToken != "paired-token" || cfg.SystemID != 8 || cfg.CAFingerprint != s.fp {
		t.Fatalf("config %+v %v", cfg, err)
	}
	if code, _, e := runCmd("setup", "--config", cfgPath); code == 0 || !strings.Contains(e, "already set up") {
		t.Fatalf("second setup: %d %s", code, e)
	}
}

func TestSetupWithAFingerprintRefusesAnotherMasterBeforeSendingAnything(t *testing.T) {
	s := newServer(t)
	s.pairing = "approved"
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	wrong := strings.Repeat("AB", 32)
	code, _, e := runCmd("setup", "--config", cfgPath, "--master", s.srv.URL, "--ca-fingerprint", wrong)
	if code == 0 || !strings.Contains(e, "does NOT match") || len(s.pairs) != 0 {
		t.Fatalf("%d %s pairs=%v", code, e, s.pairs)
	}
	pin := strings.Repeat("ab", 32)
	code, out, e := runCmd("setup", "--config", cfgPath, "--master", s.srv.URL, "--ca-fingerprint", s.fp, "--passkeys-sha256", pin)
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, e)
	}
	if cfg, err := config.LoadConfig(cfgPath); err != nil || cfg.PasskeysSHA256 != pin || cfg.CAFingerprint != s.fp {
		t.Fatalf("config %+v %v", cfg, err)
	}
}

func TestSetupRefusesAMasterWithoutNonce(t *testing.T) {
	// Ein Master der alten Art (ohne Zufallszahl) bekommt das Geheimnis gar nicht erst
	s := newServer(t)
	s.noNonce = true
	code, _, e := runCmd("setup", "--config", filepath.Join(t.TempDir(), "agent.json"), "--master", s.srv.URL)
	if code == 0 || !strings.Contains(e, "nonce") || len(s.reveals) != 0 {
		t.Fatalf("%d %s reveals=%v", code, e, s.reveals)
	}
}

func TestSetupStopsWhenRejected(t *testing.T) {
	s := newServer(t)
	s.pairing = "rejected"
	cfgPath := filepath.Join(t.TempDir(), "agent.json")
	code, _, e := runCmd("setup", "--config", cfgPath, "--master", s.srv.URL)
	if code == 0 || !strings.Contains(e, "rejected") {
		t.Fatalf("%d %s", code, e)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatal("config written although rejected")
	}
}

func TestPackageChangesTriggerOneReportOnceTheDatabaseIsQuiet(t *testing.T) {
	db := filepath.Join(t.TempDir(), "status")
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	touch := func(when time.Time) {
		if err := os.WriteFile(db, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(db, when, when); err != nil {
			t.Fatal(err)
		}
	}
	touch(at)
	paths := []string{db, filepath.Join(t.TempDir(), "missing")}
	w := pkgWatch{paths: paths, seen: pkgStamp(paths)}
	if w.changed(at.Add(time.Hour)) {
		t.Fatal("unverändert: kein Report")
	}
	touch(at.Add(2 * time.Hour)) // apt hat Pakete geändert
	if w.changed(at.Add(2*time.Hour + pkgSettle/2)) {
		t.Fatal("noch in Bewegung: erst melden, wenn apt fertig ist")
	}
	if !w.changed(at.Add(2*time.Hour + pkgSettle)) {
		t.Fatal("geändert und ruhig: Report fällig")
	}
	if w.changed(at.Add(3 * time.Hour)) {
		t.Fatal("dieselbe Änderung nur einmal melden")
	}
}
