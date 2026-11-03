package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"lablantern/agent/internal/queries"
)

type result struct {
	out string
	err error
}

type fake struct {
	files  map[string]string
	exists map[string]bool
	bins   map[string]bool
	cmds   map[string]result
	docker func(path string) ([]byte, int, error)
	podman func(socket, path string) ([]byte, int, error)
	globs  map[string][]string
}

func newFake() *fake {
	return &fake{files: map[string]string{}, exists: map[string]bool{}, bins: map[string]bool{}, cmds: map[string]result{}}
}

func (f *fake) env() Env {
	return Env{
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := f.files[p]; ok {
				return []byte(s), nil
			}
			return nil, errors.New("open " + p + ": no such file or directory")
		},
		Exists: func(p string) bool { return f.exists[p] },
		LookPath: func(n string) (string, error) {
			if f.bins[n] {
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("not found")
		},
		Run: func(name string, args ...string) ([]byte, error) {
			r, ok := f.cmds[name+" "+strings.Join(args, " ")] // genauer Aufruf vor dem bloßen Namen
			if !ok {
				r, ok = f.cmds[name]
			}
			if !ok {
				return nil, fmt.Errorf("unerwarteter Aufruf %s", name)
			}
			return []byte(r.out), r.err
		},
		DockerGet: f.docker,
		SocketGet: f.podman,
		Glob:      func(p string) ([]string, error) { return f.globs[p], nil },
	}
}

const osRelease = `PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
`

// Echte Zeilen von einem Ubuntu-24.04-Host: Paket, Version, Architektur, Quellpaket, Quellversion, Status.
const dpkgOut = "libssl3t64\t3.0.13-0ubuntu3.16\tamd64\topenssl\t3.0.13-0ubuntu3.16\tinstall ok installed\n" +
	"android-libbase\t1:34.0.4-1build3\tamd64\tandroid-platform-tools\t34.0.4-1build3\tinstall ok installed\n" +
	"curl\t8.5.0-2ubuntu10.6\tamd64\tcurl\t8.5.0-2ubuntu10.6\tinstall ok installed\n" +
	"alt-held\t1.0\tall\talt-held\t1.0\thold ok installed\n" +
	"entfernt\t2.0\tall\tentfernt\t2.0\tdeinstall ok config-files\n" +
	"nie\t3.0\tall\tnie\t3.0\tinstall ok not-installed\n"

func ubuntu() *fake {
	f := newFake()
	f.files["/etc/os-release"] = osRelease
	f.bins["dpkg-query"] = true
	f.cmds["dpkg-query"] = result{out: dpkgOut}
	f.cmds["uname"] = result{out: "6.8.0-45-generic\n"}
	f.bins["apt-check"] = false
	f.exists["/usr/lib/update-notifier/apt-check"] = true
	f.cmds["/usr/lib/update-notifier/apt-check"] = result{out: "7;2"}
	f.docker = func(string) ([]byte, int, error) { return nil, 0, ErrNoDocker }
	return f
}

func TestOSInfoFromOSRelease(t *testing.T) {
	r := Collect(ubuntu().env(), "0.3.0")
	if r.OSID != "ubuntu" || r.OSVersionID != "24.04" || r.OSName != "Ubuntu 24.04.5 LTS" {
		t.Fatalf("OS: %q %q %q", r.OSID, r.OSVersionID, r.OSName)
	}
	if r.Kernel != "6.8.0-45-generic" || r.AgentVersion != "0.3.0" {
		t.Fatalf("Kernel/Version: %q %q", r.Kernel, r.AgentVersion)
	}
}

func TestMissingOSReleaseIsReportedAsPackageError(t *testing.T) {
	f := ubuntu()
	delete(f.files, "/etc/os-release")
	r := Collect(f.env(), "0.3.0")
	if r.CollectionErrors["packages"] == "" || r.OSID != "" {
		t.Fatalf("erwartet Paketfehler, erhalten %v", r.CollectionErrors)
	}
}

func TestDpkgPackagesIncludeSourceAndArchitecture(t *testing.T) {
	r := Collect(ubuntu().env(), "0.3.0")
	if len(r.Packages) != 4 { // libssl3t64, android-libbase, curl, alt-held
		t.Fatalf("erwartet 4 installierte Pakete, erhalten %d: %+v", len(r.Packages), r.Packages)
	}
	p := r.Packages[1]
	want := PackageInfo{Name: "android-libbase", Version: "1:34.0.4-1build3", Arch: "amd64",
		Source: "android-platform-tools", SourceVersion: "34.0.4-1build3", Type: "deb"}
	if p != want {
		t.Fatalf("erwartet %+v, erhalten %+v", want, p)
	}
	for _, pk := range r.Packages {
		if pk.Name == "entfernt" || pk.Name == "nie" {
			t.Fatalf("nicht installiertes Paket %q gemeldet", pk.Name)
		}
	}
}

func TestDpkgFailureIsAnErrorNotAnEmptyCleanSystem(t *testing.T) {
	f := ubuntu()
	f.cmds["dpkg-query"] = result{err: errors.New("exit status 2")}
	r := Collect(f.env(), "0.3.0")
	if len(r.Packages) != 0 || !strings.Contains(r.CollectionErrors["packages"], "dpkg-query") {
		t.Fatalf("erwartet dpkg-Fehler, erhalten %v", r.CollectionErrors)
	}
}

func TestEmptyDpkgOutputIsAnError(t *testing.T) {
	f := ubuntu()
	f.cmds["dpkg-query"] = result{out: ""}
	if Collect(f.env(), "x").CollectionErrors["packages"] == "" {
		t.Fatal("leere Paketliste muss ein Fehler sein")
	}
}

func TestNoSupportedPackageManagerIsAnError(t *testing.T) {
	f := ubuntu()
	f.bins["dpkg-query"] = false
	r := Collect(f.env(), "x")
	if !strings.Contains(r.CollectionErrors["packages"], "package manager") {
		t.Fatalf("erwartet Paketmanager-Fehler: %v", r.CollectionErrors)
	}
}

func TestRpmPackages(t *testing.T) {
	f := newFake()
	f.files["/etc/os-release"] = "ID=fedora\nVERSION_ID=40\nPRETTY_NAME=\"Fedora Linux 40\"\n"
	f.bins["rpm"] = true
	f.cmds["rpm"] = result{out: "bash\t5.2.26-3.fc40\tx86_64\tbash-5.2.26-3.fc40.src.rpm\ngpg-pubkey\t1-2\t(none)\t(none)\n"}
	f.cmds["uname"] = result{out: "6.8.0\n"}
	f.docker = func(string) ([]byte, int, error) { return nil, 0, ErrNoDocker }
	r := Collect(f.env(), "x")
	if len(r.Packages) != 1 || r.Packages[0] != (PackageInfo{Name: "bash", Version: "5.2.26-3.fc40", Arch: "x86_64",
		Source: "bash-5.2.26-3.fc40.src.rpm", Type: "rpm"}) {
		t.Fatalf("rpm: %+v", r.Packages)
	}
}

func TestSecurityUpdatesFromAptCheck(t *testing.T) {
	r := Collect(ubuntu().env(), "x")
	if r.SecurityUpdatesCount != 2 || !r.SecurityUpdatesKnown {
		t.Fatalf("apt-check: %d known=%v", r.SecurityUpdatesCount, r.SecurityUpdatesKnown)
	}
}

const aptSim = `Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst vim [2:9.1.0016-1ubuntu7.1] (2:9.1.0016-1ubuntu7.2 Ubuntu:24.04/noble-updates [amd64])
Inst curl [8.5.0-2ubuntu10.1] (8.5.0-2ubuntu10.2 Ubuntu:24.04/noble-security [amd64])
Conf libssl3t64 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])
`

func TestSecurityUpdatesFallBackToAptSimulationAndCountOnlySecurityInstLines(t *testing.T) {
	f := ubuntu()
	f.cmds["/usr/lib/update-notifier/apt-check"] = result{err: errors.New("kaputt")}
	f.bins["apt-get"] = true
	f.cmds["apt-get"] = result{out: aptSim}
	r := Collect(f.env(), "x")
	if r.SecurityUpdatesCount != 2 || !r.SecurityUpdatesKnown {
		t.Fatalf("apt-get: %d known=%v", r.SecurityUpdatesCount, r.SecurityUpdatesKnown)
	}
}

func TestSecurityUpdatesAreListedWhileAptCheckKeepsTheCount(t *testing.T) {
	f := ubuntu()
	f.cmds["/usr/lib/update-notifier/apt-check"] = result{out: "9;3"}
	f.bins["apt-get"] = true
	f.cmds["apt-get"] = result{out: aptSim}
	r := Collect(f.env(), "x")
	want := []UpdateInfo{{Name: "libssl3t64", From: "3.0.13-0ubuntu3.4", To: "3.0.13-0ubuntu3.5"},
		{Name: "curl", From: "8.5.0-2ubuntu10.1", To: "8.5.0-2ubuntu10.2"}}
	if r.SecurityUpdatesCount != 3 || !reflect.DeepEqual(r.SecurityUpdates, want) {
		t.Fatalf("count=%d list=%+v", r.SecurityUpdatesCount, r.SecurityUpdates)
	}
}

func TestUnknownSecurityUpdateStateIsNotReportedAsZero(t *testing.T) {
	f := ubuntu()
	f.exists["/usr/lib/update-notifier/apt-check"] = false
	r := Collect(f.env(), "x")
	if r.SecurityUpdatesKnown || r.CollectionErrors["security_updates"] == "" {
		t.Fatalf("erwartet 'unbekannt', erhalten known=%v errs=%v", r.SecurityUpdatesKnown, r.CollectionErrors)
	}
}

func TestRebootRequired(t *testing.T) {
	f := ubuntu()
	if Collect(f.env(), "x").RebootRequired {
		t.Fatal("ohne Datei kein Neustart")
	}
	f.exists["/var/run/reboot-required"] = true
	if !Collect(f.env(), "x").RebootRequired {
		t.Fatal("Datei vorhanden: Neustart nötig")
	}
}

const dockerJSON = `[{"Id":"0123456789abcdef0123","Names":["/caddy"],"Image":"caddy:2.9.1-alpine","ImageID":"sha256:1","State":"running","Labels":{"a":"b"},"Created":1700000000,"Ports":[{"PrivatePort":443,"PublicPort":8443,"Type":"tcp"},{"PrivatePort":443,"PublicPort":8443,"Type":"tcp","IP":"::"}]},
{"Id":"fedcba9876543210ffff","Names":["/server"],"Image":"lablantern-server:dev","ImageID":"sha256:2","State":"exited","Labels":null,"Created":1700000100}]`

func TestDockerContainersIncludingStoppedOnes(t *testing.T) {
	f := ubuntu()
	var asked string
	f.docker = func(path string) ([]byte, int, error) {
		if path == "/images/json" {
			return []byte(`[{"Id":"sha256:1","RepoDigests":["caddy@sha256:aa"]}]`), 200, nil
		}
		asked = path
		return []byte(dockerJSON), 200, nil
	}
	r := Collect(f.env(), "x")
	if asked != "/containers/json?all=1" {
		t.Fatalf("muss auch gestoppte Container abfragen (docker ps -a), fragte %q", asked)
	}
	if len(r.Containers) != 2 || r.Containers[0].Name != "caddy" || r.Containers[0].ID != "0123456789ab" || r.Containers[1].State != "exited" {
		t.Fatalf("Container: %+v", r.Containers)
	}
	if _, bad := r.CollectionErrors["containers"]; bad {
		t.Fatal("kein Fehler erwartet")
	}
	if len(r.Containers[0].RepoDigests) != 1 || r.Containers[0].RepoDigests[0] != "caddy@sha256:aa" || r.Containers[1].RepoDigests != nil {
		t.Fatalf("RepoDigests je Image-ID erwartet: %+v", r.Containers)
	}
	if len(r.Containers[0].Ports) != 1 || r.Containers[0].Ports[0] != 8443 {
		t.Fatalf("veröffentlichte Ports ohne Doppelte erwartet: %v", r.Containers[0].Ports)
	}
}

func TestHostNetworkContainerPortsAndHostPorts(t *testing.T) {
	f := ubuntu()
	f.docker = func(path string) ([]byte, int, error) {
		if path == "/images/json" {
			return []byte(`[]`), 200, nil
		}
		return []byte(dockerJSON), 200, nil
	}
	env := f.env()
	env.Listeners = func() []queries.Listener {
		return []queries.Listener{
			{Port: 8443}, // docker-proxy des veröffentlichten caddy-Ports
			{Port: 8099, Container: "fedcba9876543210ffff"}, // server im Host-Netz
			{Port: 8930}, {Port: 22}, {Port: 8930}, // Dienste des Hosts
		}
	}
	r := Collect(env, "x")
	if got := r.Containers[1].Ports; len(got) != 1 || got[0] != 8099 {
		t.Fatalf("Host-Netz-Port dem Container zugeordnet erwartet: %v", got)
	}
	if fmt.Sprint(r.HostPorts) != "[22 8930]" {
		t.Fatalf("Host-Ports ohne veröffentlichte und Doppelte erwartet: %v", r.HostPorts)
	}
}

func TestImageQueryFailureKeepsContainersWithoutDigests(t *testing.T) {
	f := ubuntu()
	f.docker = func(path string) ([]byte, int, error) {
		if path == "/images/json" {
			return nil, 500, nil
		}
		return []byte(dockerJSON), 200, nil
	}
	r := Collect(f.env(), "x")
	if len(r.Containers) != 2 || r.CollectionErrors["containers"] != "" || r.Containers[0].RepoDigests != nil {
		t.Fatalf("Digests sind optional: %+v %v", r.Containers, r.CollectionErrors)
	}
}

func TestHostWithoutDockerHasNoContainersAndNoError(t *testing.T) {
	r := Collect(ubuntu().env(), "x")
	if len(r.Containers) != 0 || r.CollectionErrors["containers"] != "" {
		t.Fatalf("erwartet: kein Docker, kein Fehler: %v", r.CollectionErrors)
	}
}

func TestDockerFailuresAreErrorsNotZeroContainers(t *testing.T) {
	cases := map[string]func(string) ([]byte, int, error){
		"permission denied": func(string) ([]byte, int, error) { return nil, 0, errors.New("dial unix: permission denied") },
		"HTTP 500":          func(string) ([]byte, int, error) { return []byte("x"), 500, nil },
		"invalid":           func(string) ([]byte, int, error) { return []byte("{kein json"), 200, nil },
	}
	for want, fn := range cases {
		f := ubuntu()
		f.docker = fn
		r := Collect(f.env(), "x")
		if !strings.Contains(r.CollectionErrors["containers"], want) {
			t.Errorf("%s: erwartet Fehler, erhalten %v", want, r.CollectionErrors)
		}
	}
}

func TestCleanCollectionSerializesEmptyErrorsObjectAndNeverContainerEnvironment(t *testing.T) {
	f := ubuntu()
	f.docker = func(string) ([]byte, int, error) { return []byte(dockerJSON), 200, nil }
	data, _ := json.Marshal(Collect(f.env(), "0.3.0"))
	s := string(data)
	if !strings.Contains(s, `"collection_errors":{}`) || !strings.Contains(s, `"security_updates_known":true`) {
		t.Fatalf("JSON: %s", s)
	}
	if strings.Contains(strings.ToLower(s), `"env"`) {
		t.Fatal("Container-Umgebungsvariablen dürfen nie gemeldet werden")
	}
}

func TestSafeLabelsTraefik(t *testing.T) {
	got := safeLabels(map[string]string{
		"traefik.enable":                                "true",
		"traefik.http.routers.app.rule":                 "Host(`app.example.org`)",
		"traefik.http.routers.app.entrypoints":          "websecure",
		"traefik.tcp.routers.mc.rule":                   "HostSNI(`mc.example.org`)",
		"traefik.http.middlewares.auth.basicauth.users": "noah:$apr1$secret",
		"traefik.tcp.middlewares.ip.ipallowlist.source": "10.0.0.0/8",
		"traefik.http.services.app.loadbalancer.server": "x",
		"traefik.enabled":                               "true",
	})
	if len(got) != 4 || got["traefik.http.routers.app.rule"] == "" || got["traefik.http.middlewares.auth.basicauth.users"] != "" {
		t.Fatalf("%v", got)
	}
}

func TestOnlyHarmlessContainerLabelsLeaveTheHost(t *testing.T) {
	got := safeLabels(map[string]string{
		"com.docker.compose.project":                    "web",
		"org.opencontainers.image.version":              "1.2",
		"traefik.http.middlewares.auth.basicauth.users": "noah:$apr1$secret",
	})
	if len(got) != 2 || got["com.docker.compose.project"] != "web" || got["traefik.http.middlewares.auth.basicauth.users"] != "" {
		t.Fatalf("%v", got)
	}
}
