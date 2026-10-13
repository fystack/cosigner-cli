package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const (
	passwordEnv          = "COSIGNER_PASSWORD"
	passwordSaltSize     = 16
	passwordNonceSize    = 12
	passwordKeySize      = 32
	passwordKDFTime      = 3
	passwordKDFMemoryKiB = 64 * 1024
	passwordKDFThreads   = 4
	passphraseCheckWords = 3
)

// encryptedKEK is an encrypted, versioned representation of the hex storage
// KEK. It deliberately contains KDF parameters and salt, but never a password
// or derived key.
type encryptedKEK struct {
	Version    int    `yaml:"version"`
	KDF        string `yaml:"kdf"`
	Time       uint32 `yaml:"time"`
	MemoryKiB  uint32 `yaml:"memory_kib"`
	Threads    uint8  `yaml:"threads"`
	Salt       string `yaml:"salt"`
	Nonce      string `yaml:"nonce"`
	Ciphertext string `yaml:"ciphertext"`
}

func (a *App) readPassword(confirm bool) (result []byte, resultErr error) {
	if a.password != nil {
		return append([]byte(nil), a.password...), nil
	}
	defer func() {
		if resultErr == nil && result != nil {
			a.password = append([]byte(nil), result...)
		}
	}()
	if value := a.Getenv("COSIGNER_PASSWORD_FD"); value != "" {
		fd, err := strconv.ParseUint(value, 10, 32)
		if err != nil || fd < 3 {
			return nil, errors.New("COSIGNER_PASSWORD_FD must identify an open descriptor >= 3")
		}
		f := os.NewFile(uintptr(fd), "password")
		if f == nil {
			return nil, errors.New("invalid password descriptor")
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil {
			clear(raw)
			return nil, err
		}
		password := bytes.TrimSuffix(raw, []byte("\n"))
		if len(password) == 0 || len(raw) > 4096 {
			clear(raw)
			return nil, errors.New("password must contain 1 to 4096 bytes")
		}
		return password, nil
	}
	if value := a.Getenv(passwordEnv); value != "" {
		if len(value) > 4096 {
			return nil, errors.New("password exceeds 4096 bytes")
		}
		return []byte(value), nil
	}
	file, ok := a.In.(*os.File)
	if !ok || !isTerminal(file) {
		return nil, fmt.Errorf("%s is required in non-interactive mode", passwordEnv)
	}
	for {
		fmt.Fprint(a.Out, "Storage encryption passphrase: ")
		password, err := readHidden(file)
		fmt.Fprintln(a.Out)
		if err != nil {
			return nil, fmt.Errorf("read storage encryption passphrase: %w", err)
		}
		if len(password) == 0 {
			fmt.Fprintln(a.Out, "Passphrase can't be empty; try again (Ctrl-C to quit).")
			continue
		}
		if !confirm {
			return password, nil
		}
		fmt.Fprint(a.Out, "Confirm storage encryption password: ")
		confirmed, err := readHidden(file)
		fmt.Fprintln(a.Out)
		if err != nil {
			clear(password)
			return nil, fmt.Errorf("confirm storage encryption password: %w", err)
		}
		match := bytes.Equal(password, confirmed)
		clear(confirmed)
		if match {
			return password, nil
		}
		clear(password)
		fmt.Fprintln(a.Out, "Passwords do not match; please try again.")
	}
}

// newStoragePassword generates a six-word passphrase for a fresh install typed at
// a terminal; passwords supplied by environment or descriptor are used as given.
func (a *App) newStoragePassword() ([]byte, error) {
	if a.password != nil || !a.typedPassword() {
		return a.readPassword(true)
	}
	passphrase, err := generatePassphrase(a.Random)
	if err != nil {
		return nil, err
	}
	file := a.In.(*os.File)
	block := &screenBlock{out: a.Out, erasable: a.interactive()}
	defer block.erase()
	defer a.onInterrupt(file, block.erase)()
	if err := a.showStoragePassphrase(passphrase, file, block); err != nil {
		return nil, fmt.Errorf("show storage encryption passphrase: %w", err)
	}
	if err := a.confirmPassphraseWords(passphrase, file, block); err != nil {
		return nil, fmt.Errorf("confirm storage encryption passphrase: %w", err)
	}
	block.erase()
	a.success("Storage passphrase backed up")
	a.password = []byte(passphrase)
	return []byte(passphrase), nil
}

func (a *App) showStoragePassphrase(passphrase string, file *os.File, block *screenBlock) error {
	warn, bold, reset := "", "", ""
	if block.erasable {
		warn, bold, reset = ansiOrange+ansiBold, ansiBold, ansiReset
	}
	block.printf("\n%s⚠  BACK UP YOUR STORAGE PASSPHRASE NOW%s\n\n    %s%s%s\n\n", warn, reset, bold, passphrase, reset)
	block.printf("%sWrite it on paper or save it in a secure password manager.\n"+
		"It is shown only once and never stored. Without it the encrypted\n"+
		"MPC key shares on this host can't be decrypted, and the Cosigner\n"+
		"can't start or export them.%s\n\n", warn, reset)
	if !block.erasable {
		return nil
	}
	block.printf("Press Enter once it's saved; it will be cleared from the screen. ")
	enter, err := readHidden(file)
	clear(enter)
	block.erase()
	return err
}

// confirmPassphraseWords checks the backup by asking for randomly chosen words,
// one per prompt, instead of the whole passphrase.
func (a *App) confirmPassphraseWords(passphrase string, file *os.File, block *screenBlock) error {
	words := strings.Split(passphrase, "-")
	positions, err := randomPositions(a.Random, len(words), passphraseCheckWords)
	if err != nil {
		return err
	}
	block.printf("\nConfirm your backup: enter %d words from your passphrase.\n\n", len(positions))
	for _, i := range positions {
		for {
			block.printf("Word #%d: ", i+1)
			var typed []byte
			if block.erasable {
				typed, err = readLine(file)
				block.echoed()
			} else {
				typed, err = readHidden(file)
				block.printf("\n")
			}
			if err != nil {
				return err
			}
			match := strings.EqualFold(string(bytes.TrimSpace(typed)), words[i])
			clear(typed)
			if match {
				break
			}
			block.printf("That doesn't match; check your backup and try again (Ctrl-C to quit).\n")
		}
	}
	return nil
}

// randomPositions returns k distinct indexes below n in ascending order.
func randomPositions(random io.Reader, n, k int) ([]int, error) {
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	for i := 0; i < k; i++ {
		j, err := randomIndex(random, n-i)
		if err != nil {
			return nil, err
		}
		all[i], all[i+j] = all[i+j], all[i]
	}
	picked := all[:k]
	sort.Ints(picked)
	return picked, nil
}

// readLine reads one echoed line a byte at a time, so nothing past the newline
// is buffered away from later prompts.
func readLine(file *os.File) ([]byte, error) {
	var line []byte
	b := make([]byte, 1)
	for len(line) < 256 {
		if _, err := file.Read(b); err != nil {
			clear(line)
			return nil, err
		}
		if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	return bytes.TrimSuffix(line, []byte("\r")), nil
}

// screenBlock counts the lines a prompt prints so they can be erased in place;
// while they fit on screen, none of them reach scrollback.
type screenBlock struct {
	mu       sync.Mutex
	out      io.Writer
	erasable bool
	lines    int
}

func (b *screenBlock) printf(format string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := fmt.Sprintf(format, args...)
	b.lines += strings.Count(text, "\n")
	fmt.Fprint(b.out, text)
}

// echoed records a line break the terminal echoed for typed input.
func (b *screenBlock) echoed() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines++
}

func (b *screenBlock) erase() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.erasable {
		return
	}
	if b.lines > 0 {
		fmt.Fprintf(b.out, "\x1b[%dF\x1b[J", b.lines)
	} else {
		fmt.Fprint(b.out, "\r\x1b[J")
	}
	b.lines = 0
}

// onInterrupt runs cleanup and restores the terminal if Ctrl-C arrives before
// the returned func is called.
func (a *App) onInterrupt(file *os.File, cleanup func()) func() {
	state, _ := term.GetState(int(file.Fd()))
	sig, done := make(chan os.Signal, 1), make(chan struct{})
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			cleanup()
			if state != nil {
				_ = term.Restore(int(file.Fd()), state)
			}
			os.Exit(130)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(sig)
		close(done)
	}
}

func encryptKEK(password, plaintext []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("storage encryption password is required")
	}
	salt := make([]byte, passwordSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	key := derivePasswordKey(password, salt, passwordKDFTime, passwordKDFMemoryKiB, passwordKDFThreads)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create KEK cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create KEK cipher mode: %w", err)
	}
	nonce := make([]byte, passwordNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate KEK nonce: %w", err)
	}
	envelope := encryptedKEK{
		Version: 1, KDF: "argon2id", Time: passwordKDFTime, MemoryKiB: passwordKDFMemoryKiB, Threads: passwordKDFThreads,
		Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
	}
	envelope.Ciphertext = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, kekAAD(envelope.Version)))
	raw, err := yaml.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted storage KEK: %w", err)
	}
	return raw, nil
}

func decryptKEK(password, raw []byte) ([]byte, error) {
	var envelope encryptedKEK
	if err := yaml.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parse encrypted storage KEK: %w", err)
	}
	if envelope.Version != 1 || envelope.KDF != "argon2id" || envelope.Time == 0 || envelope.Time > 10 || envelope.MemoryKiB < 8*1024 || envelope.MemoryKiB > 256*1024 || envelope.Threads == 0 || envelope.Threads > 16 {
		return nil, errors.New("unsupported encrypted storage KEK format")
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil || len(salt) < passwordSaltSize {
		return nil, errors.New("invalid encrypted storage KEK salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != passwordNonceSize {
		return nil, errors.New("invalid encrypted storage KEK nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, errors.New("invalid encrypted storage KEK ciphertext")
	}
	key := derivePasswordKey(password, salt, envelope.Time, envelope.MemoryKiB, envelope.Threads)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create KEK cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create KEK cipher mode: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, kekAAD(envelope.Version))
	if err != nil {
		return nil, errWrongPassword
	}
	return plaintext, nil
}

var errWrongPassword = errors.New("could not decrypt storage key; check the passphrase")

// storagePassword returns a password that opens the envelope. A password typed
// at a terminal is asked for again until it is right; one supplied by
// environment or descriptor fails at once.
func (a *App) storagePassword(envelope []byte) ([]byte, error) {
	for {
		password, err := a.readPassword(false)
		if err != nil {
			return nil, err
		}
		plain, used, err := openKEK(password, envelope)
		clear(plain)
		if err == nil {
			return used, nil
		}
		if !errors.Is(err, errWrongPassword) || !a.typedPassword() {
			return nil, err
		}
		clear(a.password)
		a.password = nil
		fmt.Fprintln(a.Out, "Wrong passphrase; try again (Ctrl-C to quit).")
	}
}

// openKEK tries the password exactly as given first, so chosen passwords keep
// working, then as a generated passphrase typed with spaces or capitals.
func openKEK(password, envelope []byte) (plain, used []byte, err error) {
	plain, err = decryptKEK(password, envelope)
	if err == nil {
		return plain, password, nil
	}
	normalized := normalizePassphrase(password)
	if !errors.Is(err, errWrongPassword) || normalized == nil || bytes.Equal(normalized, password) {
		clear(password)
		clear(normalized)
		return nil, nil, err
	}
	clear(password)
	plain, err = decryptKEK(normalized, envelope)
	if err != nil {
		clear(normalized)
		return nil, nil, err
	}
	return plain, normalized, nil
}

// normalizePassphrase returns the canonical hyphenated form of a generated
// passphrase, or nil if the input isn't six wordlist words.
func normalizePassphrase(input []byte) []byte {
	words := strings.FieldsFunc(strings.ToLower(string(input)), func(r rune) bool { return r == '-' || unicode.IsSpace(r) })
	if len(words) != msharePassphraseLen {
		return nil
	}
	for _, w := range words {
		if i := sort.SearchStrings(wordlist, w); i == len(wordlist) || wordlist[i] != w {
			return nil
		}
	}
	return []byte(strings.Join(words, "-"))
}

func (a *App) typedPassword() bool {
	if a.Getenv("COSIGNER_PASSWORD_FD") != "" || a.Getenv(passwordEnv) != "" {
		return false
	}
	file, ok := a.In.(*os.File)
	return ok && isTerminal(file)
}

func derivePasswordKey(password, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, passwordKeySize)
}

func kekAAD(version int) []byte {
	return []byte(fmt.Sprintf("fystack-cosigner/storage-kek/v%d", version))
}
