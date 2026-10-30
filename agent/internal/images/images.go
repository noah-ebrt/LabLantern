// Package images erzeugt die SBOM eines lokalen Container-Images mit der Syft-Bibliothek.
// Gelesen wird über den Docker-Socket; das Image verlässt den Host nie, nur die SBOM.
package images

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	_ "modernc.org/sqlite" // Treiber für neuere RPM-Datenbanken (wie im Syft-CLI)
)

func SyftSBOM(imageID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	src, err := syft.GetSource(ctx, imageID, syft.DefaultGetSourceConfig().WithSources("docker"))
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
