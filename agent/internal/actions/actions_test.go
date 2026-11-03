package actions

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lablantern/agent/internal/passkey"
	"lablantern/agent/internal/passkey/passkeytest"
	"lablantern/agent/internal/release"
)

const origin = "https://lablantern.lan:8443"

type fixture struct {
	env  Env
	key  *passkeytest.SoftKey
	ran  []string
	relK ed25519.PrivateKey
	now  time.Time
}

func setup(t *testing.T) *fixture {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fixture{key: passkeytest.NewSoftKey(t), relK: priv, now: time.Unix(1_800_000_000, 0)}
	os.MkdirAll(filepath.Join(dir, "stage"), 0o755)
	f.env = Env{
		Paths: Paths{RequestFile: filepath.Join(dir, "action.request"), ResultFile: filepath.Join(dir, "result.json"),
			TrustFile: filepath.Join(dir, "passkeys.json"), StateDir: filepath.Join(dir, "state"), StageDir: filepath.Join(dir, "stage")},
		SystemID: 7, AgentVersion: "0.7.0", Now: func() time.Time { return f.now }, PkgType: "deb", Arch: "amd64", ReleaseKey: pub,
		Run: func(name string, args ...string) (string, error) {
			f.ran = append(f.ran, name+" "+strings.Join(args, " "))
			return "", nil
		},
	}
	return f
}

func (f *fixture) trustEnvelope(rev int, keys ...*passkeytest.SoftKey) string {
	ks := []passkey.Key{}
	for _, k := range keys {
		ks = append(ks, k.Key())
	}
	b, _ := json.Marshal(passkey.TrustSet{Kind: "passkeys", Rev: rev, RPID: "lablantern.lan", Keys: ks})
	return string(b)
}

func (f *fixture) run(t *testing.T, req Request) Result {
	t.Helper()
	req.Nonce = "n"
	if err := f.env.Submit(req); err != nil {
		t.Fatal(err)
	}
	if err := f.env.Handle(); err != nil {
		t.Fatal(err)
	}
	res, err := f.env.Wait("n", time.Second, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return *res
}

func sign(k *passkeytest.SoftKey, envelope string) string {
	b, _ := json.Marshal(k.Sign(envelope, "lablantern.lan", origin, 0x05))
	return string(b)
}

func (f *fixture) cmd(typ string, params map[string]any, nonce string) string {
	b, _ := json.Marshal(map[string]any{"kind": "command", "system_id": 7, "type": typ, "params": params,
		"issued_at": f.now.Unix(), "expires_at": f.now.Unix() + 300, "nonce": nonce})
	return string(b)
}

func TestPinnedFirstListRefusesAnyOtherList(t *testing.T) {
	// Einrichtungsbefehl mit --passkeys-sha256: Ein übernommener Master kann keine eigene erste Liste unterschieben
	f := setup(t)
	mine := f.trustEnvelope(1, f.key)
	sum := sha256.Sum256([]byte(mine))
	f.env.FirstTrustSHA256 = hex.EncodeToString(sum[:])
	attacker := passkeytest.NewSoftKey(t)
	attacker.ID = "attacker"
	if r := f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, attacker)}); r.Status != "rejected" {
		t.Fatalf("foreign first list accepted: %+v", r)
	}
	if r := f.run(t, Request{Kind: "passkeys", Envelope: mine}); r.Status != "done" || !strings.Contains(r.Output, "pinned") {
		t.Fatalf("pinned list refused: %+v", r)
	}
}

func TestTrustOnFirstUseThenOnlySignedUpdates(t *testing.T) {
	f := setup(t)
	second := passkeytest.NewSoftKey(t)
	second.ID = "second"
	if r := f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, f.key)}); r.Status != "done" {
		t.Fatalf("initial list: %+v", r)
	}
	evil := f.trustEnvelope(2, second)
	if r := f.run(t, Request{Kind: "passkeys", Envelope: evil}); r.Status != "rejected" {
		t.Fatalf("unsigned replacement accepted: %+v", r)
	}
	if r := f.run(t, Request{Kind: "passkeys", Envelope: evil, Assertion: sign(second, evil)}); r.Status != "rejected" {
		t.Fatalf("self-signed replacement accepted: %+v", r)
	}
	good := f.trustEnvelope(2, f.key, second)
	if r := f.run(t, Request{Kind: "passkeys", Envelope: good, Assertion: sign(f.key, good)}); r.Status != "done" {
		t.Fatalf("signed update refused: %+v", r)
	}
	if r := f.run(t, Request{Kind: "passkeys", Envelope: good, Assertion: sign(f.key, good)}); r.Status != "rejected" {
		t.Fatalf("same revision accepted twice: %+v", r)
	}
	if f.env.TrustRev() != 2 {
		t.Fatalf("rev %d", f.env.TrustRev())
	}
}

func TestRebootOnlyWithValidFreshUniqueCommandAndRateLimited(t *testing.T) {
	f := setup(t)
	f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, f.key)})
	env := f.cmd("reboot", map[string]any{"delay": 30}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	if r := f.run(t, Request{Kind: "command", Envelope: env}); r.Status != "rejected" {
		t.Fatalf("unsigned reboot accepted: %+v", r)
	}
	if r := f.run(t, Request{Kind: "command", Envelope: env, Assertion: sign(f.key, env)}); r.Status != "done" || len(f.ran) != 1 ||
		!strings.Contains(f.ran[0], "systemd-run --on-active=30") {
		t.Fatalf("valid reboot: %+v ran=%v", r, f.ran)
	}
	if r := f.run(t, Request{Kind: "command", Envelope: env, Assertion: sign(f.key, env)}); !strings.Contains(r.Output, "replay") {
		t.Fatalf("replay: %+v", r)
	}
	f.now = f.now.Add(10 * time.Minute)
	env2 := f.cmd("reboot", nil, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if r := f.run(t, Request{Kind: "command", Envelope: env2, Assertion: sign(f.key, env2)}); !strings.Contains(r.Output, "30 minutes") {
		t.Fatalf("rate limit: %+v", r)
	}
	other := strings.Replace(f.cmd("reboot", nil, "cccccccccccccccccccccccccccccccc"), `"system_id":7`, `"system_id":8`, 1)
	if r := f.run(t, Request{Kind: "command", Envelope: other, Assertion: sign(f.key, other)}); !strings.Contains(r.Output, "another system") {
		t.Fatalf("other system: %+v", r)
	}
	old := f.cmd("reboot", nil, "dddddddddddddddddddddddddddddddd")
	f.now = f.now.Add(time.Hour)
	if r := f.run(t, Request{Kind: "command", Envelope: old, Assertion: sign(f.key, old)}); !strings.Contains(r.Output, "expired") {
		t.Fatalf("expired: %+v", r)
	}
	if len(f.ran) != 1 {
		t.Fatalf("ran %v", f.ran)
	}
}

func (f *fixture) stage(t *testing.T, version string, pkg []byte, tamper bool) {
	dir := t.TempDir()
	name := PackageName("amd64", "deb")
	os.WriteFile(filepath.Join(dir, "lablantern-agent-linux-amd64.deb"), pkg, 0o644)
	m, _ := release.BuildManifest(dir, version)
	data, sig := release.Sign(m, f.relK)
	os.WriteFile(filepath.Join(f.env.StageDir, "manifest.json"), data, 0o644)
	os.WriteFile(filepath.Join(f.env.StageDir, "manifest.json.sig"), sig, 0o644)
	if tamper {
		pkg = append(pkg, '!')
	}
	os.WriteFile(filepath.Join(f.env.StageDir, name), pkg, 0o644)
}

func TestUpdateInstallsOnlyTheSignedConfirmedNewerPackage(t *testing.T) {
	f := setup(t)
	f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, f.key)})
	n := 0
	try := func(confirmed, staged string, tamper bool) Result {
		n++
		f.stage(t, staged, []byte("deb-"+staged), tamper)
		env := f.cmd("update_agent", map[string]any{"version": confirmed}, fmt.Sprintf("%032d", n))
		return f.run(t, Request{Kind: "command", Envelope: env, Assertion: sign(f.key, env)})
	}
	if r := try("0.8.0", "0.9.0", false); r.Status != "rejected" {
		t.Fatalf("other version installed: %+v", r)
	}
	if r := try("0.6.0", "0.6.0", false); r.Status != "rejected" {
		t.Fatalf("downgrade installed: %+v", r)
	}
	if r := try("0.8.0", "0.8.0", true); r.Status != "rejected" {
		t.Fatalf("tampered package installed: %+v", r)
	}
	if len(f.ran) != 0 {
		t.Fatalf("installer ran: %v", f.ran)
	}
	if r := try("0.8.0", "0.8.0", false); r.Status != "done" || len(f.ran) != 1 || !strings.HasPrefix(f.ran[0], "dpkg -i ") {
		t.Fatalf("valid update: %+v ran=%v", r, f.ran)
	}
}

func TestUpdateRefusesASymlinkedStageDir(t *testing.T) {
	f := setup(t)
	f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, f.key)})
	f.stage(t, "0.8.0", []byte("deb-0.8.0"), false)
	// Der Daemon besitzt das Verzeichnis und biegt es auf eine andere Stelle um
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Rename(f.env.StageDir, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, f.env.StageDir); err != nil {
		t.Fatal(err)
	}
	env := f.cmd("update_agent", map[string]any{"version": "0.8.0"}, fmt.Sprintf("%032d", 1))
	if r := f.run(t, Request{Kind: "command", Envelope: env, Assertion: sign(f.key, env)}); r.Status == "done" || len(f.ran) != 0 {
		t.Fatalf("installed from a symlinked stage directory: %+v ran=%v", r, f.ran)
	}
}

func TestOneTouchUpdatesListedHostsButNeverReboots(t *testing.T) {
	f := setup(t)
	f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, f.key)})
	batch := func(typ string, ids []int, nonce string, params map[string]any) Result {
		b, _ := json.Marshal(map[string]any{"kind": "command", "system_id": 0, "system_ids": ids, "type": typ,
			"params": params, "issued_at": f.now.Unix(), "expires_at": f.now.Unix() + 300, "nonce": nonce})
		return f.run(t, Request{Kind: "command", Envelope: string(b), Assertion: sign(f.key, string(b))})
	}
	if r := batch("reboot", []int{7, 8}, fmt.Sprintf("%032d", 1), map[string]any{"delay": 30}); r.Status != "rejected" {
		t.Fatalf("reboot for several hosts accepted: %+v", r)
	}
	if r := batch("update_agent", []int{8, 9}, fmt.Sprintf("%032d", 2), map[string]any{"version": "0.8.0"}); r.Status != "rejected" {
		t.Fatalf("update for other hosts accepted: %+v", r)
	}
	// system_id und system_ids zugleich: nicht eindeutig, abgelehnt
	b, _ := json.Marshal(map[string]any{"kind": "command", "system_id": 7, "system_ids": []int{7}, "type": "update_agent",
		"params": map[string]any{"version": "0.8.0"}, "issued_at": f.now.Unix(), "expires_at": f.now.Unix() + 300, "nonce": fmt.Sprintf("%032d", 3)})
	if r := f.run(t, Request{Kind: "command", Envelope: string(b), Assertion: sign(f.key, string(b))}); r.Status != "rejected" {
		t.Fatalf("ambiguous envelope accepted: %+v", r)
	}
	f.stage(t, "0.8.0", []byte("deb-0.8.0"), false)
	if r := batch("update_agent", []int{6, 7, 8}, fmt.Sprintf("%032d", 4), map[string]any{"version": "0.8.0"}); r.Status != "done" || len(f.ran) != 1 {
		t.Fatalf("listed host not updated: %+v ran=%v", r, f.ran)
	}
}

func TestUninstallNeedsAPasskeyAndRunsDetached(t *testing.T) {
	f := setup(t)
	f.run(t, Request{Kind: "passkeys", Envelope: f.trustEnvelope(1, f.key)})
	env := f.cmd("uninstall", nil, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	if r := f.run(t, Request{Kind: "command", Envelope: env}); r.Status != "rejected" || len(f.ran) != 0 {
		t.Fatalf("unsigned uninstall: %+v %v", r, f.ran)
	}
	if r := f.run(t, Request{Kind: "command", Envelope: env, Assertion: sign(f.key, env)}); r.Status != "done" ||
		len(f.ran) != 1 || !strings.Contains(f.ran[0], "systemd-run --on-active=10") || !strings.HasSuffix(f.ran[0], "dpkg --purge lablantern-agent") {
		t.Fatalf("uninstall: %+v %v", r, f.ran)
	}
}
