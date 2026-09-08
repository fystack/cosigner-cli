package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testImage = "fystacklabs/cosigner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const testConfig = "storage:\n  backend: sqlite\n  sqlite:\n    path: data/cosigner.db\n  encryption:\n    kek:\n      type: password_envelope\n      config:\n        path: /run/secrets/storage-kek.enc\napproval:\n  require_callback: false\naudit:\n  type: file\n  config:\n    path: audit.jsonl\n"

type runCall struct {
	name  string
	args  []string
	env   map[string]string
	input []byte
}
type fakeRunner struct {
	calls []runCall
	run   func(runCall) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, in io.Reader, env map[string]string) ([]byte, error) {
	call := runCall{name: name, args: append([]string(nil), args...), env: env}
	if in != nil {
		call.input, _ = io.ReadAll(in)
	}
	f.calls = append(f.calls, call)
	if f.run != nil {
		return f.run(call)
	}
	return nil, nil
}
func (f *fakeRunner) Stream(ctx context.Context, name string, args []string, in io.Reader, env map[string]string, out io.Writer) error {
	raw, err := f.Run(ctx, name, args, in, env)
	out.Write(raw)
	return err
}
func newTestApp(r *fakeRunner) *App {
	return &App{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard, Runner: r, Getenv: func(string) string { return "" }, Random: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 32)), Version: "v1.2.3"}
}
func fixture(t *testing.T, a *App) (layout, Settings) {
	t.Helper()
	l := a.layout(t.TempDir())
	for _, dir := range []string{l.state, filepath.Join(l.state, "data"), filepath.Join(l.home, "secrets")} {
		require.NoError(t, os.MkdirAll(dir, 0700))
	}
	s := Settings{SchemaVersion: 2, Image: testImage, RuntimeVersion: "1.2.3", Profile: "manual", ProjectName: projectName(l.home), Docker: "docker"}
	for path, content := range map[string]string{l.config: testConfig, l.pairing(): "participant_id: participant-1\n", l.key(): "identity", l.pub(): "public\n", l.encryptedKEK(): "envelope", l.compose(): "services: {}\n", filepath.Join(l.state, "data", "cosigner.db"): "database"} {
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	}
	require.NoError(t, saveSettings(l.home, s))
	return l, s
}
func containerJSON(t *testing.T, l layout, s Settings, running bool) []byte {
	t.Helper()
	raw, err := json.Marshal([]map[string]any{{"ID": "id", "Config": map[string]any{"Image": s.Image, "Labels": map[string]string{"com.docker.compose.project": s.ProjectName, "com.docker.compose.service": "cosigner"}}, "State": map[string]any{"Running": running, "Status": "running"}, "Mounts": []map[string]string{{"Source": l.state, "Destination": "/var/lib/cosigner"}}}})
	require.NoError(t, err)
	return raw
}
func TestUpOnRunningInstanceDoesNotMutateOrPrompt(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	r.run = func(c runCall) ([]byte, error) {
		if c.args[0] == "ps" {
			return []byte("id"), nil
		}
		if c.args[0] == "inspect" {
			return containerJSON(t, l, s, true), nil
		}
		t.Fatalf("unexpected mutation: %v", c.args)
		return nil, nil
	}
	before, err := snapshotInstallation(l, s)
	require.NoError(t, err)
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "up"})
	require.NoError(t, cmd.Execute())
	after, err := snapshotInstallation(l, s)
	require.NoError(t, err)
	require.Equal(t, before.Files, after.Files)
}
func TestCopiedProjectCannotControlOtherInstance(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	foreign, _ := fixture(t, a)
	r.run = func(c runCall) ([]byte, error) {
		if c.args[0] == "ps" {
			return []byte("id"), nil
		}
		if c.args[0] == "inspect" {
			return containerJSON(t, foreign, s, true), nil
		}
		t.Fatalf("must not execute Compose: %v", c.args)
		return nil, nil
	}
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "stop"})
	require.ErrorContains(t, cmd.Execute(), "different state directory")
}
func TestLockAndAtomicCreatePreventReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".lock")
	release, err := lockFile(path)
	require.NoError(t, err)
	_, err = lockFile(path)
	require.Error(t, err)
	release()
	release, err = lockFile(path)
	require.NoError(t, err)
	release()
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- atomicWrite(filepath.Join(dir, "key"), []byte("original"), 0600) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	require.Equal(t, 1, success)
	require.Error(t, atomicWrite(filepath.Join(dir, "key"), []byte("replacement"), 0600))
	raw, err := os.ReadFile(filepath.Join(dir, "key"))
	require.NoError(t, err)
	require.Equal(t, "original", string(raw))
}
func TestPasswordExcludedFromSubprocessEnvironment(t *testing.T) {
	for _, key := range []string{"COSIGNER_PASSWORD", "COSIGNER_PASSWORD_FD", "COSIGNER_RECOVERY_PASSWORD", "COSIGNER_UNLOCK_TOKEN"} {
		t.Setenv(key, "sensitive")
	}
	for _, value := range sanitizedEnvironment() {
		require.NotContains(t, value, "sensitive")
	}
}
func TestImagePolicyAndVerificationBeforeExecution(t *testing.T) {
	for _, image := range []string{"fystacklabs/cosigner:latest", "fystacklabs/cosigner", "fystacklabs/cosigner:dev"} {
		r := &fakeRunner{}
		a := newTestApp(r)
		_, _, err := a.resolveImage(context.Background(), "docker", image)
		require.Error(t, err)
		require.Empty(t, r.calls)
	}
	r := &fakeRunner{run: func(c runCall) ([]byte, error) {
		if c.name == "cosign" {
			return nil, errors.New("invalid signature")
		}
		return nil, nil
	}}
	a := newTestApp(r)
	_, err := a.inspectCapabilities(context.Background(), "docker", testImage)
	require.ErrorContains(t, err, "signature")
	require.Len(t, r.calls, 1)
}
func unlockClient(conn net.Conn, token string) ([]byte, error) {
	if _, err := io.WriteString(conn, unlockMagic); err != nil {
		return nil, err
	}
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(token)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(unlockMagic))
	mac.Write(challenge)
	if _, err := conn.Write(mac.Sum(nil)); err != nil {
		return nil, err
	}
	var length [4]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > 8192 {
		return nil, errors.New("oversized payload")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < aead.NonceSize() {
		return nil, errors.New("truncated ciphertext")
	}
	return aead.Open(nil, payload[:aead.NonceSize()], payload[aead.NonceSize():], challenge)
}
func TestUnlockAuthenticatedEncryptedAndSingleUse(t *testing.T) {
	s, err := newUnlockServer([]byte("password"))
	require.NoError(t, err)
	defer s.close()
	addr := fmt.Sprintf("127.0.0.1:%d", s.port())
	wrong, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	wrong.SetDeadline(time.Now().Add(time.Second))
	_, err = unlockClient(wrong, strings.Repeat("ab", 32))
	require.Error(t, err)
	wrong.Close()
	good, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer good.Close()
	good.SetDeadline(time.Now().Add(time.Second))
	password, err := unlockClient(good, s.token)
	require.NoError(t, err)
	require.Equal(t, "password", string(password))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, s.wait(ctx))
	second, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		defer second.Close()
		second.SetDeadline(time.Now().Add(time.Second))
		_, err = unlockClient(second, s.token)
	}
	require.Error(t, err)
}
func TestUnlockCloseJoinsStalledConnections(t *testing.T) {
	s, err := newUnlockServer([]byte("password"))
	require.NoError(t, err)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port()))
	require.NoError(t, err)
	defer conn.Close()
	done := make(chan struct{})
	go func() { s.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("unlock shutdown stuck")
	}
}
func TestRecoveryRestoresIdentityIntoEmptyHome(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	archive := filepath.Join(t.TempDir(), "instance.backup")
	require.NoError(t, a.writeRecovery(l, s, archive, []byte("recovery password")))
	target := t.TempDir()
	a.Getenv = func(k string) string {
		if k == "COSIGNER_RECOVERY_PASSWORD" {
			return "recovery password"
		}
		return ""
	}
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", target, "restore", "--in", archive})
	require.NoError(t, cmd.Execute())
	restored, err := loadSettings(target)
	require.NoError(t, err)
	require.NotEqual(t, s.ProjectName, restored.ProjectName)
	for _, name := range []string{"cosigner.key", "cosigner.pub", "pairing.yaml", "data/cosigner.db"} {
		original, err := os.ReadFile(filepath.Join(l.state, name))
		require.NoError(t, err)
		copy, err := os.ReadFile(filepath.Join(target, "state", name))
		require.NoError(t, err)
		require.Equal(t, original, copy)
	}
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", target, "restore", "--in", archive})
	require.ErrorContains(t, cmd.Execute(), "empty instance")
	require.Empty(t, r.calls, "restore must never start a container")
}
func TestRecoveryRejectsTamperingTraversalAndRunningDatabase(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, s := fixture(t, a)
	bundle, err := snapshotInstallation(l, s)
	require.NoError(t, err)
	require.NoError(t, validateBundle(bundle))
	bundle.Files[0].Path = "../escape"
	require.Error(t, validateBundle(bundle))
	sealed, err := sealRecovery([]byte("pw"), []byte("contents"))
	require.NoError(t, err)
	_, err = openRecovery([]byte("wrong"), sealed)
	require.Error(t, err)
	sealed[len(sealed)-1] ^= 1
	_, err = openRecovery([]byte("pw"), sealed)
	require.Error(t, err)
	unlock, err := lockFile(filepath.Join(l.state, "data", "cosigner.db.lock"))
	require.NoError(t, err)
	defer unlock()
	err = a.writeRecovery(l, s, filepath.Join(t.TempDir(), "backup"), []byte("pw"))
	require.ErrorContains(t, err, "stop the runtime")
}
func TestUnsupportedSchemaAndMissingPairingFailClosed(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, s := fixture(t, a)
	s.SchemaVersion = 1
	require.NoError(t, saveSettings(l.home, s))
	_, err := loadSettings(l.home)
	require.ErrorContains(t, err, "unsupported operator schema")
	s.SchemaVersion = 2
	require.NoError(t, saveSettings(l.home, s))
	require.NoError(t, os.Remove(l.pairing()))
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "up"})
	require.ErrorContains(t, cmd.Execute(), "database exists without pairing")
}
func TestPasswordEnvelopeAuthentication(t *testing.T) {
	blob, err := encryptKEK([]byte("correct"), []byte("key"))
	require.NoError(t, err)
	_, err = decryptKEK([]byte("wrong"), blob)
	require.Error(t, err)
	raw, err := decryptKEK([]byte("correct"), blob)
	require.NoError(t, err)
	require.Equal(t, "key", string(raw))
}

func TestUpdateDryRunVerifiesWithoutChangingInstallation(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	digest := "fystacklabs/cosigner@sha256:" + strings.Repeat("b", 64)
	r.run = func(c runCall) ([]byte, error) {
		if c.name == "cosign" {
			return []byte("verified"), nil
		}
		if c.args[0] == "pull" {
			return nil, nil
		}
		if c.args[0] == "image" {
			raw, _ := json.Marshal([]string{digest})
			return raw, nil
		}
		if c.args[len(c.args)-1] == "capabilities" {
			return []byte(`{"operator_api":2,"unlock_protocol":2,"storage_schema":1,"version":"1.2.4"}`), nil
		}
		t.Fatalf("unexpected state-changing command: %v", c.args)
		return nil, nil
	}
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--version", "1.2.4", "--dry-run"})
	require.NoError(t, cmd.Execute())
	after, err := loadSettings(l.home)
	require.NoError(t, err)
	require.Equal(t, s, after)
}

func TestUpdateRejectsDowngradesBeforeDocker(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, _ := fixture(t, a)
	for _, version := range []string{"1.2.2", "1.2.3", "1.3.0-rc1"} {
		cmd := a.Command()
		cmd.SetArgs([]string{"--home", l.home, "update", "--version", version})
		require.ErrorContains(t, cmd.Execute(), "newer stable")
	}
	require.Empty(t, r.calls)
}

func TestPasswordDescriptorCanBeReusedWithinOneCommand(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "password")
	require.NoError(t, err)
	_, err = file.WriteString("secret\n")
	require.NoError(t, err)
	_, err = file.Seek(0, 0)
	require.NoError(t, err)
	a := newTestApp(&fakeRunner{})
	a.Getenv = func(k string) string {
		if k == "COSIGNER_PASSWORD_FD" {
			return fmt.Sprint(file.Fd())
		}
		return ""
	}
	one, err := a.readPassword(true)
	require.NoError(t, err)
	defer clear(one)
	two, err := a.readPassword(false)
	require.NoError(t, err)
	defer clear(two)
	defer clear(a.password)
	require.Equal(t, one, two)
}
