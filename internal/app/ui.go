package app

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
	ansiBold   = "\x1b[1m"
	ansiReset  = "\x1b[0m"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (a *App) interactive() bool {
	f, ok := a.Out.(*os.File)
	return ok && isTerminal(f)
}

func (a *App) mark(color, symbol, message string) {
	if a.interactive() {
		fmt.Fprintf(a.Out, "%s%s%s %s\n", color, symbol, ansiReset, message)
		return
	}
	fmt.Fprintln(a.Out, "==> "+message)
}

func (a *App) success(message string) { a.mark(ansiGreen+ansiBold, "✔", message) }
func (a *App) warn(message string)    { a.mark(ansiYellow+ansiBold, "⚠", message) }

// step shows a spinner while fn runs, so fn must not write to a.Out itself.
// fn returns the success message; an empty one reuses running.
func (a *App) step(running string, fn func() (string, error)) error {
	if !a.interactive() {
		a.progress(running + "…")
		done, err := fn()
		if err == nil && done != "" {
			a.progress(done)
		}
		return err
	}
	stop, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(a.Out, "\r\x1b[K%s%s%s %s…", ansiCyan, spinnerFrames[i%len(spinnerFrames)], ansiReset, running)
			select {
			case <-stop:
				fmt.Fprint(a.Out, "\r\x1b[K")
				return
			case <-ticker.C:
			}
		}
	}()
	done, err := fn()
	close(stop)
	<-finished
	if err != nil {
		a.mark(ansiRed+ansiBold, "✖", running)
		return err
	}
	if done == "" {
		done = running
	}
	a.success(done)
	return nil
}

// logWriter indents subprocess output line by line and redacts secrets that
// must never reach the terminal.
type logWriter struct {
	mu     sync.Mutex
	out    io.Writer
	prefix string
	dim    bool
	redact []byte
	buf    []byte
}

func (a *App) logWriter(redact []byte) *logWriter {
	return &logWriter{out: a.Out, prefix: "    │ ", dim: a.interactive(), redact: redact}
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
}

func (w *logWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) > 0 {
		w.emit(w.buf)
		w.buf = nil
	}
}

func (w *logWriter) emit(line []byte) {
	line = bytes.TrimRight(line, "\r")
	if len(w.redact) > 0 {
		line = bytes.ReplaceAll(line, w.redact, []byte("[REDACTED]"))
	}
	if w.dim {
		fmt.Fprint(w.out, ansiDim, w.prefix, string(line), ansiReset, "\n")
		return
	}
	fmt.Fprint(w.out, w.prefix, string(line), "\n")
}
