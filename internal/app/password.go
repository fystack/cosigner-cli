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
	"strconv"

	"golang.org/x/crypto/argon2"
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
		fmt.Fprint(a.Out, "Storage encryption password: ")
		password, err := readHidden(file)
		fmt.Fprintln(a.Out)
		if err != nil {
			return nil, fmt.Errorf("read storage encryption password: %w", err)
		}
		if len(password) == 0 {
			return nil, errors.New("storage encryption password is required")
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
		return nil, errors.New("could not decrypt storage key; check the password")
	}
	return plaintext, nil
}

func derivePasswordKey(password, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, passwordKeySize)
}

func kekAAD(version int) []byte {
	return []byte(fmt.Sprintf("fystack-cosigner/storage-kek/v%d", version))
}
