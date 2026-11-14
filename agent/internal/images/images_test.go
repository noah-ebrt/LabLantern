//go:build !windows

package images

import (
	"io"
	"os"
	"strings"
	"testing"

	"lablantern/agent/internal/collector"
)

func TestSbomSourceByRuntime(t *testing.T) {
	var got []string
	h := Host{
		Sockets: func() []collector.RuntimeSocket {
			return []collector.RuntimeSocket{{Runtime: "docker", Path: "/d.sock"}, {Runtime: "podman", Path: "/run/user/1000/podman/podman.sock"}}
		},
		Has: func(socket, id string) bool { return (socket == "/d.sock") == (id == "sha256:docker") },
		Export: func(socket, id string, w io.Writer) error {
			_, err := io.WriteString(w, "tar of "+id)
			return err
		},
		Syft: func(input, source string) ([]byte, error) {
			if source == "docker-archive" {
				data, _ := os.ReadFile(input)
				input = string(data)
			}
			got = append(got, source+":"+input)
			return []byte("{}"), nil
		},
	}
	for _, id := range []string{"sha256:docker", "sha256:podman"} {
		if _, err := h.SBOM(id); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(got, ",") != "docker:sha256:docker,docker-archive:tar of sha256:podman" {
		t.Fatalf("%v", got)
	}
}
