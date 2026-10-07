package app

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// UsageError marks a mistake in how a command was typed, as opposed to a
// failure while running it, so only these errors are followed by usage help.
type UsageError struct {
	Err error
	cmd *cobra.Command
}

func (e *UsageError) Error() string { return e.Err.Error() }
func (e *UsageError) Unwrap() error { return e.Err }

// Help is the short usage block printed after the error.
func (e *UsageError) Help() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nUsage:\n  %s\n", e.cmd.UseLine())
	if e.cmd.Example != "" {
		fmt.Fprintf(&b, "\nExamples:\n%s\n", e.cmd.Example)
	}
	fmt.Fprintf(&b, "\nRun '%s --help' for all flags.\n", e.cmd.CommandPath())
	return b.String()
}

// markUsageErrors routes flag and argument errors of every command through UsageError.
func markUsageErrors(root *cobra.Command) {
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return &UsageError{Err: err, cmd: c} })
	// A runnable root validates its own args, which turns unknown commands into usage errors.
	root.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
	root.SuggestionsMinimumDistance = 2
	root.Args = func(c *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		err := fmt.Errorf("unknown command %q", args[0])
		if suggestions := c.SuggestionsFor(args[0]); len(suggestions) > 0 {
			err = fmt.Errorf("unknown command %q; did you mean %q?", args[0], suggestions[0])
		}
		return &UsageError{Err: err, cmd: c}
	}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if check := sub.Args; check != nil {
				sub.Args = func(c *cobra.Command, args []string) error {
					if err := check(c, args); err != nil {
						return &UsageError{Err: err, cmd: c}
					}
					return nil
				}
			}
			walk(sub)
		}
	}
	walk(root)
}
