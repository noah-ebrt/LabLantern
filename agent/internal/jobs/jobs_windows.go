//go:build windows

package jobs

import (
	"fmt"
	"os"
	"path/filepath"
)

// Unter Windows gibt es keinen getrennten root-Sammler: Der Dienst sammelt selbst, niemand liest hier Dateien
// eines weniger vertrauten Prozesses. Symlinks werden trotzdem abgelehnt.
func ReadNoFollow(path string, max int64) ([]byte, error) {
	if st, err := os.Lstat(path); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not readable: not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	return readRegular(f, max)
}

func ReadNoFollowIn(dir, name string, max int64) ([]byte, error) {
	return ReadNoFollow(filepath.Join(dir, name), max)
}
