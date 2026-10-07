//go:build linux || darwin

package app

import (
	"bufio"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func readHiddenTerminal(f *os.File) ([]byte, error) {
	discardTypeAhead(int(f.Fd()))
	return term.ReadPassword(int(f.Fd()))
}

// discardTypeAhead drops keys pressed before a hidden prompt appeared, such as
// an extra Enter after pasting a line that already ended in a newline.
func discardTypeAhead(fd int) {
	if t, err := unix.IoctlGetTermios(fd, ioctlGetTermios); err == nil {
		_ = unix.IoctlSetTermios(fd, ioctlSetTermiosFlush, t)
	}
}

func terminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

var _ = bufio.NewReader
