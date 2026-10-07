package main

import (
	"errors"
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
		var usage *app.UsageError
		if errors.As(err, &usage) {
			fmt.Fprint(os.Stderr, usage.Help())
		}
		os.Exit(1)
	}
}
