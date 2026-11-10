package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// exitUpdateAvailable is the status of `update --check` and
// `self-update --check` when a newer release exists, so scripts can branch on it.
const exitUpdateAvailable = 10

// hintError carries the next command an operator (or an agent) should run.
// main prints it on its own "hint:" line after the error.
type hintError struct {
	err  error
	hint string
}

func (e *hintError) Error() string { return e.err.Error() }
func (e *hintError) Unwrap() error { return e.err }
func (e *hintError) Hint() string  { return e.hint }

func withHint(err error, format string, args ...any) error {
	return &hintError{err: err, hint: fmt.Sprintf(format, args...)}
}

// ExitError ends a command with a status code and no message, for checks whose
// answer is the exit code.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// vtag normalises a release version to the vX.Y.Z form used in all output.
func vtag(version string) string { return "v" + strings.TrimPrefix(version, "v") }

// jsonMode sends human progress to stderr for the rest of the command, so that
// stdout carries only the JSON document the returned function writes.
func (a *App) jsonMode(enabled bool) (emit func(any) error, restore func()) {
	if !enabled {
		return func(any) error { return nil }, func() {}
	}
	stdout := a.Out
	a.Out = a.Err
	return func(v any) error { return writeJSON(stdout, v) }, func() { a.Out = stdout }
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
