//go:build windows

package passphrase

import (
	"fmt"
	"os"
)

func openTTY() (fd int, close func(), err error) {
	f, err := os.Open("CONIN$")
	if err != nil {
		return 0, nil, fmt.Errorf("passphrase: open CONIN$: %w", err)
	}
	return int(f.Fd()), func() { f.Close() }, nil
}
