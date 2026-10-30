package collector

import (
	"reflect"
	"strings"
	"testing"
)

func TestFindSocketsOrder(t *testing.T) {
	exists := map[string]bool{dockerSocket: true, podmanSocket: true,
		"/run/user/1000/podman/podman.sock": true, "/run/user/0/podman/podman.sock": true}
	glob := func(string) ([]string, error) {
		return []string{"/run/user/1000/podman/podman.sock", "/run/user/0/podman/podman.sock", "/run/user/5/podman/podman.sock"}, nil
	}
	got := findSockets(glob, func(p string) bool { return exists[p] })
	want := []runtimeSocket{{"docker", dockerSocket}, {"podman", podmanSocket},
		{"podman", "/run/user/0/podman/podman.sock"}, {"podman", "/run/user/1000/podman/podman.sock"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestPodmanBinaryWithoutSocketIsError(t *testing.T) {
	f := ubuntu()
	f.exists["/usr/bin/podman"] = true
	f.podman = func(string, string) ([]byte, int, error) { t.Fatal("kein Socket, keine Abfrage"); return nil, 0, nil }
	r := Collect(f.env(), "x")
	msg := r.CollectionErrors["containers"]
	if !strings.Contains(msg, "Podman found, socket not active: systemctl enable --now podman.socket") ||
		!strings.Contains(msg, "systemctl --user") {
		t.Fatalf("%q", msg)
	}
}

func TestMergeDockerAndPodman(t *testing.T) {
	f := ubuntu()
	f.docker = func(path string) ([]byte, int, error) {
		if path == "/images/json" {
			return []byte(`[]`), 200, nil
		}
		return []byte(dockerJSON), 200, nil
	}
	f.exists[podmanSocket] = true
	f.podman = func(socket, path string) ([]byte, int, error) {
		if socket != podmanSocket {
			t.Fatalf("socket %s", socket)
		}
		if path == "/images/json" {
			return []byte(`[{"Id":"sha256:9","RepoDigests":["docker.io/library/nginx@sha256:bb"]}]`), 200, nil
		}
		// "caddy" gibt es schon bei Docker; die gleiche ID wie bei Docker (podman-docker-Shim) zählt nur einmal
		return []byte(`[{"Id":"aaaaaaaaaaaaaaaa","Names":["/caddy"],"Image":"docker.io/library/caddy:2","ImageID":"sha256:8","State":"running","Created":1700000000},
{"Id":"bbbbbbbbbbbbbbbb","Names":["/web"],"Image":"docker.io/library/nginx:latest","ImageID":"sha256:9","State":"running","Created":1700000000},
{"Id":"0123456789abcdef0123","Names":["/caddy"],"Image":"caddy:2.9.1-alpine","ImageID":"sha256:1","State":"running","Created":1700000000}]`), 200, nil
	}
	r := Collect(f.env(), "x")
	var got []string
	for _, c := range r.Containers {
		got = append(got, c.Runtime+"/"+c.Name)
	}
	if strings.Join(got, ",") != "docker/caddy,docker/server,podman/podman:caddy,podman/web" {
		t.Fatalf("%v", got)
	}
	if r.Containers[3].RepoDigests[0] != "docker.io/library/nginx@sha256:bb" {
		t.Fatalf("%+v", r.Containers[3])
	}
	if msg, bad := r.CollectionErrors["containers"]; bad {
		t.Fatalf("kein Fehler erwartet: %s", msg)
	}
}
