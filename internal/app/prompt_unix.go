//go:build linux || darwin

package app

import (
	"bufio"
	"golang.org/x/term"
	"os"
)

func readHiddenTerminal(f *os.File) ([]byte, error) {
	return term.ReadPassword(int(f.Fd()))
}

func terminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

var _ = bufio.NewReader
