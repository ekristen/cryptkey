//go:build !windows

package passphrase

import (
	"fmt"
	"os"
)

func openTTY() (fd int, cleanup func(), err error) {
	f, err := os.Open("/dev/tty")
	if err != nil {
		return 0, nil, fmt.Errorf("passphrase: open /dev/tty: %w", err)
	}
	return int(f.Fd()), func() { f.Close() }, nil //nolint:gosec // Fd() fits in int on all supported platforms
}
