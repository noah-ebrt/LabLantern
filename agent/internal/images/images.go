// Package images erzeugt die SBOM eines lokalen Container-Images mit der Syft-Bibliothek.
// Gelesen wird über den Container-Socket; das Image verlässt den Host nie, nur die SBOM.
//
// Docker-Images liest Syft wie bisher selbst (Quelle "docker"). Podman-Images (ab 0.17) exportiert der Agent über
// die Docker-kompatible API des Podman-Sockets (GET /images/{id}/get, wie docker save) in eine Temp-Datei, die Syft
// als "docker-archive" liest. Syfts eigene Podman-Quelle findet Sockets nur über CONTAINER_HOST oder die
// Podman-Konfiguration des aufrufenden Benutzers, also nicht die rootless Sockets anderer Benutzer; der Export geht
// mit jedem Socket gleich. Platzbedarf wie bei Docker: Syft legt dort ebenfalls ein Archiv im Temp-Verzeichnis an.
package images

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	_ "modernc.org/sqlite" // Treiber für neuere RPM-Datenbanken (wie im Syft-CLI)

	"vulnwatch/agent/internal/collector"
)

// Host: wo die Images liegen und wie sie gelesen werden; austauschbar für Tests.
type Host struct {
	Sockets func() []collector.RuntimeSocket
	Has     func(socket, imageID string) bool               // GET /images/{id}/json antwortet 200
	Export  func(socket, imageID string, w io.Writer) error // GET /images/{id}/get
	Syft    func(input, source string) ([]byte, error)      // SBOM aus einer Syft-Quelle
}

func DefaultHost() Host {
	return Host{Sockets: collector.Sockets, Has: hasImage, Export: exportImage, Syft: syftSBOM}
}

// SyftSBOM: SBOM des Images mit dieser ID, aus Docker oder einem Podman-Socket.
func SyftSBOM(imageID string) ([]byte, error) {
	return DefaultHost().SBOM(imageID)
}

func (h Host) SBOM(imageID string) ([]byte, error) {
	for _, s := range h.Sockets() {
		if !h.Has(s.Path, imageID) {
			continue
		}
		if s.Runtime == "docker" {
			return h.Syft(imageID, "docker")
		}
		f, err := os.CreateTemp("", "vulnwatch-image-*.tar")
		if err != nil {
			return nil, fmt.Errorf("image not readable: %w", err)
		}
		defer os.Remove(f.Name())
		err = h.Export(s.Path, imageID, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("image not readable from Podman (%s): %w", s.Path, err)
		}
		return h.Syft(f.Name(), "docker-archive")
	}
	return h.Syft(imageID, "docker") // nirgends gefunden: Syft nennt den Grund wie bisher
}

func client(socket string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
}

func hasImage(socket, imageID string) bool {
	resp, err := client(socket, 15*time.Second).Get("http://unix/images/" + url.PathEscape(imageID) + "/json")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func exportImage(socket, imageID string, w io.Writer) error {
	resp, err := client(socket, 10*time.Minute).Get("http://unix/images/" + url.PathEscape(imageID) + "/get")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func syftSBOM(input, source string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	src, err := syft.GetSource(ctx, input, syft.DefaultGetSourceConfig().WithSources(source))
	if err != nil {
		if strings.Contains(err.Error(), "pull access denied for sha256") {
			// Mit dem containerd-Image-Store ist ein umgetaggtes Image oft nicht mehr per ID abrufbar.
			return nil, fmt.Errorf("image is no longer available locally (its tag was rebuilt); recreate the container to scan the current image")
		}
		return nil, fmt.Errorf("image not readable: %w", err)
	}
	defer src.Close()
	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("Syft failed: %w", err)
	}
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, err
	}
	return format.Encode(*s, enc)
}
