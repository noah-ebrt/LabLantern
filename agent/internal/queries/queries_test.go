package queries

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnknownQueriesAreRefused(t *testing.T) {
	for _, n := range []string{"", "shell", "disk_usage; id", "../uptime"} {
		if _, err := Run(n); err == nil {
			t.Fatalf("%q accepted", n)
		}
	}
}

func TestParseAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F:0016":                         "127.0.0.1:22",
		"00000000:1F90":                         "0.0.0.0:8080",
		"00000000000000000000000000000000:01BB": "[::]:443",
		"00000000000000000000000001000000:0035": "[::1]:53",
	}
	for in, want := range cases {
		if got, ok := parseAddr(in); !ok || got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestListeningPortsAndUptimeFromProc(t *testing.T) {
	root := t.TempDir()
	ProcRoot = root
	defer func() { ProcRoot = "/proc" }()
	os.MkdirAll(filepath.Join(root, "1", "net"), 0o755)
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1\n" +
		"   1: 0100007F:1F90 0100007F:D000 01 00000000:00000000 00:00000000 00000000     0        0 4343 1\n"
	os.WriteFile(filepath.Join(root, "1", "net", "tcp"), []byte(tcp), 0o644)
	os.MkdirAll(filepath.Join(root, "77", "fd"), 0o755)
	os.WriteFile(filepath.Join(root, "77", "comm"), []byte("sshd\n"), 0o644)
	os.Symlink("socket:[4242]", filepath.Join(root, "77", "fd", "3"))
	out, err := Run("listening_ports")
	if err != nil || !strings.Contains(out, "0.0.0.0:22") || !strings.Contains(out, "sshd") || strings.Contains(out, "8080") {
		t.Fatalf("%v\n%s", err, out)
	}
	os.WriteFile(filepath.Join(root, "uptime"), []byte("273600.5 100.0\n"), 0o644)
	os.WriteFile(filepath.Join(root, "loadavg"), []byte("0.10 0.20 0.30 1/200 999\n"), 0o644)
	if out, err := Run("uptime"); err != nil || out != "up 3d 4h 0m, load 0.10 0.20 0.30" {
		t.Fatalf("%v %q", err, out)
	}
}

func TestTCPListenersMapContainersByCgroup(t *testing.T) {
	root := t.TempDir()
	ProcRoot = root
	defer func() { ProcRoot = "/proc" }()
	id := strings.Repeat("ab", 32)
	os.MkdirAll(filepath.Join(root, "1", "net"), 0o755)
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:1FA3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5001 1\n" +
		"   1: 00000000:22D2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5002 1\n" +
		"   2: 0100007F:1F90 0100007F:D000 01 00000000:00000000 00:00000000 00000000     0        0 5003 1\n"
	os.WriteFile(filepath.Join(root, "1", "net", "tcp"), []byte(tcp), 0o644)
	for pid, c := range map[string]struct{ inode, cgroup string }{
		"40": {"5001", "0::/system.slice/docker-" + id + ".scope\n"},
		"41": {"5002", "0::/system.slice/ffbooker.service\n"},
	} {
		os.MkdirAll(filepath.Join(root, pid, "fd"), 0o755)
		os.WriteFile(filepath.Join(root, pid, "cgroup"), []byte(c.cgroup), 0o644)
		os.Symlink("socket:["+c.inode+"]", filepath.Join(root, pid, "fd", "3"))
	}
	got := TCPListeners()
	want := []Listener{{Port: 8099, Container: id}, {Port: 8914}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v want %+v", got, want)
	}
}
