package app

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiOrange = "\x1b[38;5;208m"
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

type menuOption struct {
	Label    string
	Disabled bool
}

// choose returns the index of the selected option. On a terminal it is an
// arrow-key menu; otherwise the operator types the option number.
func (a *App) choose(file *os.File, title string, options []menuOption) (int, error) {
	first := -1
	for i, o := range options {
		if !o.Disabled {
			first = i
			break
		}
	}
	if !a.interactive() {
		return a.chooseNumbered(file, title, options, first)
	}
	state, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		return a.chooseNumbered(file, title, options, first)
	}
	fmt.Fprintf(a.Out, "%s%s:%s %s(↑/↓ to move, Enter to select)%s\r\n\x1b[?25l", ansiBold, title, ansiReset, ansiDim, ansiReset)
	selected := first
	draw := func() {
		for i, o := range options {
			switch {
			case i == selected:
				fmt.Fprintf(a.Out, "\r\x1b[K%s❯ %s%s\r\n", ansiCyan+ansiBold, o.Label, ansiReset)
			case o.Disabled:
				fmt.Fprintf(a.Out, "\r\x1b[K%s  %s%s\r\n", ansiDim, o.Label, ansiReset)
			default:
				fmt.Fprintf(a.Out, "\r\x1b[K  %s\r\n", o.Label)
			}
		}
	}
	move := func(step int) {
		for i := selected + step; i >= 0 && i < len(options); i += step {
			if !options[i].Disabled {
				selected = i
				return
			}
		}
	}
	finish := func() {
		fmt.Fprintf(a.Out, "\x1b[%dA\r\x1b[J\x1b[?25h", len(options)+1)
		_ = term.Restore(int(file.Fd()), state)
	}
	pick := func(i int) (int, error) {
		finish()
		a.success(title + ": " + strings.Join(strings.Fields(options[i].Label), " "))
		return i, nil
	}
	draw()
	buf := make([]byte, 8)
	for {
		n, err := file.Read(buf)
		if err != nil {
			finish()
			return 0, err
		}
		key := string(buf[:n])
		switch {
		case key == "\x1b[A" || key == "\x1bOA" || key == "k":
			move(-1)
		case key == "\x1b[B" || key == "\x1bOB" || key == "j":
			move(1)
		case key == "\r" || key == "\n":
			return pick(selected)
		case key == "\x03":
			finish()
			os.Exit(130)
		default:
			if i, err := strconv.Atoi(key); err == nil && i >= 1 && i <= len(options) && !options[i-1].Disabled {
				return pick(i - 1)
			}
		}
		fmt.Fprintf(a.Out, "\x1b[%dA", len(options))
		draw()
	}
}

func (a *App) chooseNumbered(file *os.File, title string, options []menuOption, first int) (int, error) {
	fmt.Fprintln(a.Out, title+":")
	for i, o := range options {
		fmt.Fprintf(a.Out, "  %d) %s\n", i+1, o.Label)
	}
	for {
		fmt.Fprintf(a.Out, "Choice [%d]: ", first+1)
		line, err := readLine(file)
		if err != nil {
			return 0, err
		}
		value := strings.TrimSpace(string(line))
		if value == "" {
			return first, nil
		}
		if i, err := strconv.Atoi(value); err == nil && i >= 1 && i <= len(options) && !options[i-1].Disabled {
			return i - 1, nil
		}
		fmt.Fprintln(a.Out, "That option isn't available; choose another.")
	}
}
