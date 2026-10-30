// Package collector sammelt Inventar eines Linux-Hosts. Jeder Fehler beim Sammeln wird als Fehler gemeldet:
// "kein Paket" oder "kein Container" ist nie das Ergebnis eines stillen Scheiterns.
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnwatch/agent/internal/queries"
)

const aptCheck = "/usr/lib/update-notifier/apt-check"

// ErrNoDocker bedeutet: Auf diesem Host gibt es keinen Docker-Socket (kein Fehler, nur kein Docker).
var ErrNoDocker = errors.New("no Docker socket")

// Env kapselt alles, was der Collector vom System liest, damit Tests ohne echten Host auskommen.
type Env struct {
	ReadFile  func(path string) ([]byte, error)
	Exists    func(path string) bool
	LookPath  func(name string) (string, error)
	Run       func(name string, args ...string) ([]byte, error)
	DockerGet func(path string) (body []byte, status int, err error)
	// SocketGet fragt einen Podman-Socket (Docker-kompatible API); nil = kein Podman (Tests ohne Podman).
	SocketGet func(socket, path string) (body []byte, status int, err error)
	Glob      func(pattern string) ([]string, error)
	Listeners func() []queries.Listener
}

type ContainerInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	ImageID     string            `json:"image_id"`
	RepoDigests []string          `json:"repo_digests,omitempty"`
	Ports       []int             `json:"ports,omitempty"` // veröffentlichte Host-Ports (für die Zuordnung von Proxy-Zielen)
	Labels      map[string]string `json:"labels,omitempty"`
	Created     string            `json:"created,omitempty"`
	State       string            `json:"state,omitempty"`
	Runtime     string            `json:"runtime,omitempty"` // docker | podman (ab 0.17)
	Socket      string            `json:"-"`                 // für die SBOM: welcher Socket das Image hat
}

type PackageInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Type          string `json:"type"`
}

// Ein ausstehendes Sicherheitsupdate: Paket, installierte und neue Version
type UpdateInfo struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
	To   string `json:"to"`
}

type HostReport struct {
	AgentVersion         string            `json:"agent_version"`
	OSName               string            `json:"os_name"`
	OSID                 string            `json:"os_id"`
	OSVersionID          string            `json:"os_version_id"`
	Kernel               string            `json:"kernel"`
	Arch                 string            `json:"arch"`
	SecurityUpdatesCount int               `json:"security_updates_count"`
	SecurityUpdatesKnown bool              `json:"security_updates_known"`
	SecurityUpdates      []UpdateInfo      `json:"security_updates,omitempty"` // welche, soweit apt sie nennt (ab 0.15)
	RebootRequired       bool              `json:"reboot_required"`
	Containers           []ContainerInfo   `json:"containers"`
	HostPorts            []int             `json:"host_ports,omitempty"` // TCP-Ports von Diensten des Hosts selbst
	Packages             []PackageInfo     `json:"packages"`
	CollectionErrors     map[string]string `json:"collection_errors"`
}

func unixGet(socket, path string) ([]byte, int, error) {
	hc := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	resp, err := hc.Get("http://unix" + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return body, resp.StatusCode, err
}

func DefaultEnv() Env {
	return Env{
		ReadFile:  os.ReadFile,
		Exists:    func(p string) bool { _, err := os.Stat(p); return err == nil },
		LookPath:  exec.LookPath,
		Listeners: queries.TCPListeners,
		Glob:      filepath.Glob,
		Run: func(name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).Output()
		},
		DockerGet: func(path string) ([]byte, int, error) {
			if _, err := os.Stat(dockerSocket); err != nil {
				return nil, 0, ErrNoDocker
			}
			return unixGet(dockerSocket, path)
		},
		SocketGet: unixGet,
	}
}

func Collect(env Env, agentVersion string) *HostReport {
	r := &HostReport{
		AgentVersion:         agentVersion,
		Arch:                 runtime.GOARCH,
		SecurityUpdatesKnown: true,
		Containers:           []ContainerInfo{},
		Packages:             []PackageInfo{},
		CollectionErrors:     map[string]string{},
	}
	osInfo(env, r)
	r.Kernel = kernel(env)
	r.RebootRequired = env.Exists("/var/run/reboot-required")
	collectPackages(env, r)
	collectSecurityUpdates(env, r)
	collectContainers(env, r)
	return r
}

func osInfo(env Env, r *HostReport) {
	data, err := env.ReadFile("/etc/os-release")
	if err != nil {
		r.CollectionErrors["packages"] = "operating system not detectable (/etc/os-release unreadable)"
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"'")
		switch k {
		case "ID":
			r.OSID = strings.ToLower(v)
		case "VERSION_ID":
			r.OSVersionID = v
		case "PRETTY_NAME":
			r.OSName = v
		}
	}
	if r.OSID == "" {
		r.CollectionErrors["packages"] = "operating system not detectable (ID missing in /etc/os-release)"
	}
}

func kernel(env Env) string {
	if out, err := env.Run("uname", "-r"); err == nil {
		return strings.TrimSpace(string(out))
	}
	if data, err := env.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "unknown"
}

func setPackageError(r *HostReport, msg string) {
	if r.CollectionErrors["packages"] == "" {
		r.CollectionErrors["packages"] = msg
	}
}

func collectPackages(env Env, r *HostReport) {
	switch {
	case lookPath(env, "dpkg-query"):
		out, err := env.Run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Status}\n")
		if err != nil {
			setPackageError(r, "dpkg-query failed: "+err.Error())
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Split(line, "\t")
			if len(f) < 6 || !strings.HasSuffix(f[5], " installed") {
				continue
			}
			r.Packages = append(r.Packages, PackageInfo{Name: f[0], Version: f[1], Arch: f[2],
				Source: f[3], SourceVersion: f[4], Type: "deb"})
		}
	case lookPath(env, "rpm"):
		out, err := env.Run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n")
		if err != nil {
			setPackageError(r, "rpm failed: "+err.Error())
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Split(line, "\t")
			if len(f) < 4 || f[0] == "gpg-pubkey" {
				continue
			}
			src := f[3]
			if src == "(none)" {
				src = ""
			}
			r.Packages = append(r.Packages, PackageInfo{Name: f[0], Version: f[1], Arch: f[2], Source: src, Type: "rpm"})
		}
	default:
		setPackageError(r, "no supported package manager found (dpkg or rpm)")
		return
	}
	if len(r.Packages) == 0 {
		setPackageError(r, "package manager returned no installed packages")
	}
}

func lookPath(env Env, name string) bool {
	_, err := env.LookPath(name)
	return err == nil
}

// "Inst <Paket> [<installiert>] (<neu> <Quellen> [<arch>])" aus der apt-Simulation
var aptInst = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) ([^)]*)\)`)

const maxUpdates = 500

// aptSecurityUpdates: Sicherheitsupdates laut apt-Simulation (Liste gekürzt, Anzahl vollständig)
func aptSecurityUpdates(env Env) (list []UpdateInfo, n int, ok bool) {
	if !lookPath(env, "apt-get") {
		return nil, 0, false
	}
	out, err := env.Run("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil {
		return nil, 0, false
	}
	list = []UpdateInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		m := aptInst.FindStringSubmatch(line)
		if m == nil || !strings.Contains(strings.ToLower(m[4]), "security") {
			continue
		}
		n++
		if len(list) < maxUpdates {
			list = append(list, UpdateInfo{Name: m[1], From: m[2], To: m[3]})
		}
	}
	return list, n, true
}

func collectSecurityUpdates(env Env, r *HostReport) {
	list, n, listed := aptSecurityUpdates(env)
	r.SecurityUpdates = list
	if env.Exists(aptCheck) {
		if out, err := env.Run(aptCheck); err == nil {
			// apt-check schreibt "<alle>;<sicherheit>"; die Zahl zählt auch ESM mit und bleibt daher maßgeblich
			parts := strings.Split(strings.TrimSpace(string(out)), ";")
			if len(parts) >= 2 {
				if n, err := strconv.Atoi(parts[1]); err == nil {
					r.SecurityUpdatesCount = n
					return
				}
			}
		}
	}
	if listed {
		r.SecurityUpdatesCount = n
		return
	}
	r.SecurityUpdatesKnown = false
	r.CollectionErrors["security_updates"] = "security updates could not be determined (neither apt-check nor apt-get usable)"
}

type dockerContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Created int64             `json:"Created"`
	Ports   []struct {
		PublicPort int `json:"PublicPort"`
	} `json:"Ports"`
}

type dockerImage struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

// imageDigests: Registry-Digests je Image-ID (docker image inspect .RepoDigests). Der Master vergleicht sie mit
// der Registry (Image veraltet?). Fehlt die Liste, fragt er langsamer selbst nach; deshalb ist ein Fehler hier
// kein Sammelfehler.
func imageDigests(get func(string) ([]byte, int, error)) map[string][]string {
	out := map[string][]string{}
	body, status, err := get("/images/json")
	if err != nil || status != http.StatusOK {
		return out
	}
	var raw []dockerImage
	if json.Unmarshal(body, &raw) != nil {
		return out
	}
	for _, img := range raw {
		if len(img.RepoDigests) > 0 {
			out[img.ID] = img.RepoDigests
		}
	}
	return out
}

// publishedPorts: veröffentlichte Host-Ports, dazu die Ports, auf denen der Container selbst im Host-Netz lauscht
// (network_mode: host veröffentlicht nichts, ist aber genauso erreichbar).
func publishedPorts(c dockerContainer, listeners []queries.Listener) []int {
	var out []int
	seen := map[int]bool{}
	add := func(p int) {
		if p > 0 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range c.Ports {
		add(p.PublicPort)
	}
	for _, l := range listeners {
		if l.Container != "" && l.Container == c.ID {
			add(l.Port)
		}
	}
	return out
}

// queryContainers: Container und Image-Digests eines Sockets.
func queryContainers(get func(string) ([]byte, int, error), label string) ([]dockerContainer, map[string][]string, error) {
	body, status, err := get("/containers/json?all=1")
	if err != nil {
		return nil, nil, fmt.Errorf("%s query failed: %w", label, err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("%s query failed: HTTP %d", label, status)
	}
	var raw []dockerContainer
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, fmt.Errorf("invalid %s response: %v", label, err)
	}
	return raw, imageDigests(get), nil
}

func collectContainers(env Env, r *HostReport) {
	var listeners []queries.Listener
	if env.Listeners != nil {
		listeners = env.Listeners()
	}
	published := map[int]bool{}
	seen := map[string]bool{}  // Container-IDs: der podman-docker-Shim zeigt dieselben Container zweimal
	names := map[string]bool{} // Docker-Namen bleiben, Podman weicht bei Gleichheit auf "podman:<name>" aus
	var errs []string
	add := func(raw []dockerContainer, digests map[string][]string, rt, socket string) {
		for _, c := range raw {
			if seen[c.ID] {
				continue
			}
			seen[c.ID] = true
			name := ""
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			if rt == "podman" && names[name] {
				name = "podman:" + name
			}
			names[name] = true
			id := c.ID
			if len(id) > 12 {
				id = id[:12]
			}
			ports := publishedPorts(c, listeners)
			for _, p := range ports {
				published[p] = true
			}
			r.Containers = append(r.Containers, ContainerInfo{
				ID: id, Name: name, Image: c.Image, ImageID: c.ImageID, RepoDigests: digests[c.ImageID],
				Ports: ports, Labels: safeLabels(c.Labels), State: c.State, Runtime: rt, Socket: socket,
				Created: time.Unix(c.Created, 0).UTC().Format(time.RFC3339),
			})
		}
	}

	if raw, digests, err := queryContainers(env.DockerGet, "Docker"); err == nil {
		add(raw, digests, "docker", dockerSocket)
	} else if !errors.Is(err, ErrNoDocker) {
		errs = append(errs, err.Error())
	}
	if env.SocketGet != nil {
		podman := 0
		for _, s := range findSockets(env.Glob, env.Exists) {
			if s.Runtime != "podman" {
				continue
			}
			podman++
			sock := s.Path
			get := func(path string) ([]byte, int, error) { return env.SocketGet(sock, path) }
			raw, digests, err := queryContainers(get, "Podman ("+sock+")")
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			add(raw, digests, "podman", sock)
		}
		if podman == 0 && podmanInstalled(env.Exists) {
			errs = append(errs, podmanNoSocket)
		}
	}
	if len(errs) > 0 {
		r.CollectionErrors["containers"] = strings.Join(errs, "; ")
	}
	r.HostPorts = hostPorts(listeners, published)
}

// hostPorts: lauschende Ports ohne Container, abzüglich der veröffentlichten (docker-proxy hält sie im Host).
func hostPorts(listeners []queries.Listener, published map[int]bool) []int {
	var out []int
	seen := map[int]bool{}
	for _, l := range listeners {
		if l.Container == "" && !published[l.Port] && !seen[l.Port] {
			seen[l.Port] = true
			out = append(out, l.Port)
		}
	}
	sort.Ints(out)
	return out
}

// safeLabelPrefixes: Nur diese Labels verlassen den Host. Andere tragen oft Zugangsdaten (Traefik-Basic-Auth,
// OAuth-Client-IDs …). Traefik-Router (Regel, Entrypoints) ja, Middlewares und Services nie.
// Gleiche Liste im Master (agent_api.SAFE_LABEL_PREFIXES, SAFE_LABEL_KEYS).
var safeLabelPrefixes = []string{"com.docker.compose.", "org.opencontainers.", "traefik.http.routers.", "traefik.tcp.routers."}
var safeLabelKeys = map[string]bool{"traefik.enable": true}

func safeLabels(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if safeLabelKeys[k] {
			out[k] = v
			continue
		}
		for _, p := range safeLabelPrefixes {
			if strings.HasPrefix(k, p) {
				out[k] = v
				break
			}
		}
	}
	return out
}
