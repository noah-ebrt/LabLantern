// Package queries beantwortet die festen Abfragen des Masters. Es gibt keine Argumente und keine Shell:
// Jeder Name führt genau eine fest verdrahtete, nur lesende Aktion aus. Läuft im Sammler (root, ohne Netz).
package queries

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxOutput = 60 * 1024

// Names ist die Positivliste; der Master kennt dieselbe.
var Names = map[string]bool{"disk_usage": true, "failed_units": true, "listening_ports": true, "uptime": true}

// ProcRoot ist austauschbar für Tests.
var ProcRoot = "/proc"

func Run(name string) (string, error) {
	var out string
	var err error
	switch name {
	case "disk_usage":
		out, err = command("df", "-hP", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs")
	case "failed_units":
		out, err = command("systemctl", "list-units", "--failed", "--no-legend", "--plain", "--no-pager")
		if err == nil && strings.TrimSpace(out) == "" {
			out = "No failed units."
		}
	case "listening_ports":
		out, err = listeningPorts()
	case "uptime":
		out, err = uptime()
	default:
		return "", fmt.Errorf("unknown query %q", name)
	}
	if len(out) > maxOutput {
		out = out[:maxOutput] + "\n… (truncated)"
	}
	return out, err
}

func command(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s failed: %w", name, err)
	}
	return string(out), nil
}

func uptime() (string, error) {
	up, err := os.ReadFile(filepath.Join(ProcRoot, "uptime"))
	if err != nil {
		return "", err
	}
	load, _ := os.ReadFile(filepath.Join(ProcRoot, "loadavg"))
	secs, _ := strconv.ParseFloat(strings.Fields(string(up) + " 0")[0], 64)
	d := time.Duration(secs) * time.Second
	l := strings.Fields(string(load) + " - - -")
	return fmt.Sprintf("up %dd %dh %dm, load %s %s %s", int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60,
		l[0], l[1], l[2]), nil
}

// listeningPorts liest die Sockets aus dem Netz-Namespace von PID 1 (der Sammler selbst hat kein Netz)
// und ordnet sie, wo lesbar, dem Prozess zu.
func listeningPorts() (string, error) {
	owners := socketOwners()
	type row struct{ proto, addr, proc string }
	var rows []row
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := os.ReadFile(filepath.Join(ProcRoot, "1", "net", proto))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			listening := (strings.HasPrefix(proto, "tcp") && f[3] == "0A") ||
				(strings.HasPrefix(proto, "udp") && f[3] == "07" && strings.HasSuffix(f[2], ":0000"))
			if !listening {
				continue
			}
			addr, ok := parseAddr(f[1])
			if !ok {
				continue
			}
			proc := owners[f[9]].name
			if proc == "" {
				proc = "-"
			}
			rows = append(rows, row{strings.TrimSuffix(proto, "6"), addr, proc})
		}
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("no socket table readable")
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].proto != rows[j].proto {
			return rows[i].proto < rows[j].proto
		}
		return rows[i].addr < rows[j].addr
	})
	var b strings.Builder
	seen := map[row]bool{}
	for _, r := range rows {
		if !seen[r] {
			seen[r] = true
			fmt.Fprintf(&b, "%-4s %-46s %s\n", r.proto, r.addr, r.proc)
		}
	}
	return b.String(), nil
}

// parseAddr wandelt "0100007F:0016" bzw. die 32-stellige IPv6-Form in "127.0.0.1:22" um.
func parseAddr(s string) (string, bool) {
	hostHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return "", false
	}
	raw, err := hex.DecodeString(hostHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", false
	}
	for i := 0; i < len(raw); i += 4 { // jedes 32-Bit-Wort steht in Host-Byte-Reihenfolge (little endian)
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", false
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.FormatUint(port, 10)), true
}

type owner struct{ pid, name string }

// socketOwners: Socket-Inode -> Prozess (PID-Verzeichnis und Name), soweit die fd-Verzeichnisse lesbar sind.
func socketOwners() map[string]owner {
	out := map[string]owner{}
	pids, _ := filepath.Glob(filepath.Join(ProcRoot, "[0-9]*"))
	for _, p := range pids {
		fds, err := os.ReadDir(filepath.Join(p, "fd"))
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(p, "comm"))
		name := strings.TrimSpace(string(comm))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(p, "fd", fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = owner{p, name}
			}
		}
	}
	return out
}

// Listener ist ein lauschender TCP-Port im Netz des Hosts. Container ist die volle Docker-ID, wenn der Prozess
// in einem Container läuft (Host-Netz-Container), sonst leer (Dienst des Hosts oder docker-proxy).
type Listener struct {
	Port      int
	Container string
}

var dockerCgroup = regexp.MustCompile(`docker[-/]([0-9a-f]{64})`)

// TCPListeners: lauschende TCP-Ports im Netz-Namespace von PID 1 mit Container-Zuordnung über die cgroup.
// Damit ordnet der Master Proxy- und Router-Ziele auch Containern ohne veröffentlichte Ports zu.
func TCPListeners() []Listener {
	owners := socketOwners()
	var out []Listener
	seen := map[Listener]bool{}
	for _, proto := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(ProcRoot, "1", "net", proto))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" {
				continue
			}
			_, portHex, _ := strings.Cut(f[1], ":")
			port, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil {
				continue
			}
			l := Listener{Port: int(port)}
			if o, ok := owners[f[9]]; ok {
				cg, _ := os.ReadFile(filepath.Join(o.pid, "cgroup"))
				if m := dockerCgroup.FindSubmatch(cg); m != nil {
					l.Container = string(m[1])
				}
			}
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}
