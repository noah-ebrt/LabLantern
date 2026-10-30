package collector

import "sort"

// Container-Laufzeiten: Docker, dazu Podman (rootful und rootless) über seine Docker-kompatible API.
// Der Agent läuft als root und sieht auch die Sockets der Benutzer unter /run/user/<uid>/.
const (
	dockerSocket   = "/var/run/docker.sock"
	podmanSocket   = "/run/podman/podman.sock"
	rootlessGlob   = "/run/user/*/podman/podman.sock"
	podmanNoSocket = "Podman found, socket not active: systemctl enable --now podman.socket " +
		"(rootless: systemctl --user enable --now podman.socket as that user, plus loginctl enable-linger)"
)

var podmanBinaries = []string{"/usr/bin/podman", "/usr/local/bin/podman"}

type runtimeSocket struct{ Runtime, Path string }

// findSockets: vorhandene Sockets in fester Reihenfolge (Docker, Podman rootful, Podman rootless nach Pfad).
func findSockets(glob func(string) ([]string, error), exists func(string) bool) []runtimeSocket {
	var out []runtimeSocket
	if exists(dockerSocket) {
		out = append(out, runtimeSocket{"docker", dockerSocket})
	}
	if exists(podmanSocket) {
		out = append(out, runtimeSocket{"podman", podmanSocket})
	}
	if glob != nil {
		matches, _ := glob(rootlessGlob)
		sort.Strings(matches)
		for _, m := range matches {
			if exists(m) {
				out = append(out, runtimeSocket{"podman", m})
			}
		}
	}
	return out
}

func podmanInstalled(exists func(string) bool) bool {
	for _, b := range podmanBinaries {
		if exists(b) {
			return true
		}
	}
	return false
}
