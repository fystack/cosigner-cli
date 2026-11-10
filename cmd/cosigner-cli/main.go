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
		// Checks such as `update --check` answer with the exit status alone.
		var exit *app.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.Code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		var hinted interface{ Hint() string }
		if errors.As(err, &hinted) {
			fmt.Fprintln(os.Stderr, "hint:", hinted.Hint())
		}
		var usage *app.UsageError
		if errors.As(err, &usage) {
			fmt.Fprint(os.Stderr, usage.Help())
		}
		os.Exit(1)
	}
}
