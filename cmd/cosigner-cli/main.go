package main

import (
	"fmt"
	"os"

	"github.com/fystack/cosigner-cli/internal/app"
)

var (
	version = "dev"
	commit  = "dev"
)

func main() {
	a := app.New()
	a.Version, a.Commit = version, commit
	if err := a.Command().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
