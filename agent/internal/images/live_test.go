//go:build live

package images

import (
	"os"
	"strings"
	"testing"
)

// Läuft nur mit -tags live und Docker-Socket: LL_LIVE_IMAGE=<Image-ID>.
func TestSyftAgainstARealLocalImage(t *testing.T) {
	out, err := SyftSBOM(os.Getenv("LL_LIVE_IMAGE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"bomFormat":"CycloneDX"`) || !strings.Contains(string(out), "pkg:") {
		t.Fatalf("keine brauchbare SBOM: %.200s", out)
	}
	t.Logf("SBOM %d Bytes, %d PURLs", len(out), strings.Count(string(out), `"purl"`))
}
