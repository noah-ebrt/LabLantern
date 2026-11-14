//go:build !windows

package jobs

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ReadNoFollow liest eine reguläre Datei ohne Symlinks zu verfolgen, höchstens max Bytes.
func ReadNoFollow(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	return readRegular(f, max)
}

// ReadNoFollowIn liest name aus dir, ohne dir oder name als Symlink zu verfolgen. Für Verzeichnisse, die dem
// Daemon gehören: Er könnte sie sonst auf eine fremde Stelle umbiegen, und root läse von dort.
func ReadNoFollowIn(dir, name string, max int64) ([]byte, error) {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	defer d.Close()
	fd, err := syscall.Openat(int(d.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("not readable: %w", err)
	}
	return readRegular(os.NewFile(uintptr(fd), filepath.Join(dir, name)), max)
}
