package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testRSAOnce sync.Once
	testRSAKeys [2]*rsa.PrivateKey
)

// testRSA returns two shared RSA-4096 keys; generating them per test is slow.
func testRSA(t *testing.T) (server, cosigner *rsa.PrivateKey) {
	t.Helper()
	testRSAOnce.Do(func() {
		for i := range testRSAKeys {
			key, err := rsa.GenerateKey(rand.Reader, callbackKeyBits)
			require.NoError(t, err)
			testRSAKeys[i] = key
		}
	})
	return testRSAKeys[0], testRSAKeys[1]
}

func writePublicPEM(t *testing.T, path string, key *rsa.PublicKey) []byte {
	t.Helper()
	raw, _, err := publicKeyPEM(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))
	return raw
}

func writeCosignerCallbackKey(t *testing.T, l layout, key *rsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(l.secret(callbackPrivateKey), []byte(hex.EncodeToString(der)), 0600))
}

func runCLI(t *testing.T, a *App, args ...string) error {
	t.Helper()
	cmd := a.Command()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestNormalizeCallbackURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://cb.example.com":                   "https://cb.example.com/cosigner/approve",
		"https://cb.example.com/":                  "https://cb.example.com/cosigner/approve",
		"https://cb.example.com/v2/approve":        "https://cb.example.com/v2/approve",
		"http://host.docker.internal:8089":         "http://host.docker.internal:8089/cosigner/approve",
		" https://cb.example.com:8443/hook?env=1 ": "https://cb.example.com:8443/hook?env=1",
	} {
		got, err := normalizeCallbackURL(raw)
		require.NoError(t, err, raw)
		require.Equal(t, want, got)
	}
	for raw, msg := range map[string]string{
		"http://localhost:8089":      "host.docker.internal",
		"https://127.0.0.1:8443":     "host.docker.internal",
		"http://[::1]:8089":          "host.docker.internal",
		"http://cb.example.com":      "must use https",
		"ftp://cb.example.com":       "must use https",
		"cb.example.com":             "absolute URL",
		"https://u:p@cb.example.com": "absolute URL",
	} {
		_, err := normalizeCallbackURL(raw)
		require.ErrorContains(t, err, msg, raw)
	}
}

func TestLocalhostCallbackSuggestsDockerHost(t *testing.T) {
	for raw, want := range map[string]string{
		"http://localhost:8150":       "http://host.docker.internal:8150/cosigner/approve",
		"https://127.0.0.1:8443/hook": "https://host.docker.internal:8443/hook",
		"http://0.0.0.0:8089/":        "http://host.docker.internal:8089/cosigner/approve",
	} {
		_, err := normalizeCallbackURL(raw)
		var loopback *loopbackURLError
		require.True(t, errors.As(err, &loopback), raw)
		require.Equal(t, want, loopback.suggested)
		require.ErrorContains(t, err, want, "non-interactive error must spell out the fix")
	}
}

func TestCallbackAddFolderModeGeneratesKeyAndWritesBothSides(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, s := fixture(t, a)
	server, _ := testRSA(t)
	folder := t.TempDir()
	writePublicPEM(t, filepath.Join(folder, folderServerKey), &server.PublicKey)

	require.NoError(t, runCLI(t, a, "--home", l.home, "callback", "add", folder))

	raw, err := os.ReadFile(l.config)
	require.NoError(t, err)
	require.NoError(t, validateManagedConfig(raw, s))
	require.NoError(t, validateCallbackFiles(l, raw))
	cfg, err := parseCallbackConfig(raw)
	require.NoError(t, err)
	require.True(t, cfg.Approval.RequireCallback)
	require.Equal(t, callbackDevURL, cfg.Callback.URL)
	require.Equal(t, "/run/secrets/"+callbackPrivateKey, cfg.Callback.PrivateKey.Config.Path)
	require.Equal(t, "/run/secrets/"+callbackServerKey, cfg.Callback.ResponsePublicKeyPath)
	require.Empty(t, cfg.Callback.CACertPath)
	require.Contains(t, string(raw), "path: data/cosigner.db", "unrelated settings must survive")

	key, err := loadCallbackPrivateKey(l.secret(callbackPrivateKey))
	require.NoError(t, err)
	want, _, err := publicKeyPEM(&key.PublicKey)
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(folder, folderCosignerKey))
	require.NoError(t, err)
	require.Equal(t, want, got, "folder must receive the Cosigner's public key")

	info, err := os.Stat(l.secret(callbackPrivateKey))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestCallbackAddURLModeReusesKeyAndRemoveRestoresConfig(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, s := fixture(t, a)
	server, cosigner := testRSA(t)
	writeCosignerCallbackKey(t, l, cosigner)
	serverKey := filepath.Join(t.TempDir(), "server.pub.pem")
	writePublicPEM(t, serverKey, &server.PublicKey)

	require.NoError(t, runCLI(t, a, "--home", l.home, "callback", "add", "https://cb.example.com", "--server-public-key", serverKey))

	raw, err := os.ReadFile(l.config)
	require.NoError(t, err)
	cfg, err := parseCallbackConfig(raw)
	require.NoError(t, err)
	require.Equal(t, "https://cb.example.com/cosigner/approve", cfg.Callback.URL)
	key, err := loadCallbackPrivateKey(l.secret(callbackPrivateKey))
	require.NoError(t, err)
	require.True(t, key.Equal(cosigner), "existing Cosigner callback key must be reused")
	exported, err := os.ReadFile(filepath.Join(l.home, callbackPublicKey))
	require.NoError(t, err)
	want, _, err := publicKeyPEM(&cosigner.PublicKey)
	require.NoError(t, err)
	require.Equal(t, want, exported, "URL mode exports the public key for the callback server")
	require.Contains(t, callbackInfo(l), "callback_fingerprint: SHA256:")

	require.NoError(t, runCLI(t, a, "--home", l.home, "callback", "remove", "--yes"))

	raw, err = os.ReadFile(l.config)
	require.NoError(t, err)
	require.NoError(t, validateManagedConfig(raw, s))
	cfg, err = parseCallbackConfig(raw)
	require.NoError(t, err)
	require.False(t, cfg.Approval.RequireCallback)
	require.Nil(t, cfg.Callback)
	require.NoFileExists(t, l.secret(callbackServerKey))
	require.FileExists(t, l.secret(callbackPrivateKey), "Cosigner identity is kept for a later add")
	require.Equal(t, "callback: disabled\n", callbackInfo(l))
}

func TestCallbackAddRejectsBadServerKeyWithoutWriting(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serverKey := filepath.Join(t.TempDir(), "server.pub.pem")
	writePublicPEM(t, serverKey, &small.PublicKey)

	err = runCLI(t, a, "--home", l.home, "callback", "add", "https://cb.example.com", "--server-public-key", serverKey)
	require.ErrorContains(t, err, "RSA-4096")

	raw, err := os.ReadFile(l.config)
	require.NoError(t, err)
	require.Equal(t, testConfig, string(raw))
	require.NoFileExists(t, l.secret(callbackPrivateKey))
	require.NoFileExists(t, l.secret(callbackServerKey))
}

func TestCallbackAddNonInteractiveRequiresServerKey(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	err := runCLI(t, a, "--home", l.home, "callback", "add", "https://cb.example.com")
	require.ErrorContains(t, err, "--server-public-key")
}

func TestServerPublicKeyFromFlag(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	server, _ := testRSA(t)
	path := filepath.Join(t.TempDir(), "server.pub.pem")
	want := writePublicPEM(t, path, &server.PublicKey)

	got, source, err := a.serverPublicKey(path)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, path, source)

	a.In = strings.NewReader(string(want))
	got, source, err = a.serverPublicKey("-")
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, "stdin", source)

	summary := keySummary(want)
	lines := strings.Split(strings.TrimSpace(string(want)), "\n")
	require.Contains(t, summary, lines[1], "first key line shown")
	require.Contains(t, summary, lines[len(lines)-2], "last key line shown")
	_, fingerprint, err := publicKeyPEM(&server.PublicKey)
	require.NoError(t, err)
	require.Contains(t, summary, fingerprint)

	_, _, err = a.serverPublicKey(filepath.Join(t.TempDir(), "missing.pem"))
	require.ErrorContains(t, err, "callback server public key")
}

func TestCallbackAddKeepsCustomCallbackSettings(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	server, cosigner := testRSA(t)
	writeCosignerCallbackKey(t, l, cosigner)
	custom := strings.Replace(testConfig, "approval:\n  require_callback: false\n",
		"approval:\n  require_callback: false\ncallback:\n  url: https://old.example.com/cosigner/approve\n  timeout: 10s\n  max_response_bytes: 32768\n  ca_cert_path: /run/secrets/old-ca.pem\n", 1)
	require.NoError(t, os.WriteFile(l.config, []byte(custom), 0600))

	serverKey := filepath.Join(t.TempDir(), "server.pub.pem")
	writePublicPEM(t, serverKey, &server.PublicKey)
	require.NoError(t, runCLI(t, a, "--home", l.home, "callback", "add", "https://new.example.com", "--server-public-key", serverKey))

	raw, err := os.ReadFile(l.config)
	require.NoError(t, err)
	require.Contains(t, string(raw), "timeout: 10s")
	require.Contains(t, string(raw), "max_response_bytes: 32768")
	require.Contains(t, string(raw), "url: https://new.example.com/cosigner/approve")
	require.NotContains(t, string(raw), "old-ca.pem", "stale CA must not stay pinned")
}

func TestValidateCallbackFilesReportsProblemsOnTheHost(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	server, cosigner := testRSA(t)
	writeCosignerCallbackKey(t, l, cosigner)
	writePublicPEM(t, l.secret(callbackServerKey), &server.PublicKey)
	config := func(url, keyPath, serverPath string) []byte {
		return []byte("callback:\n  url: " + url + "\n  private_key:\n    type: file\n    config:\n      path: " + keyPath + "\n  response_public_key_path: " + serverPath + "\n")
	}

	require.NoError(t, validateCallbackFiles(l, config("https://cb.example.com", "/run/secrets/"+callbackPrivateKey, "/run/secrets/"+callbackServerKey)))
	require.ErrorContains(t, validateCallbackFiles(l, config("http://localhost:8089", "/run/secrets/"+callbackPrivateKey, "/run/secrets/"+callbackServerKey)), "host.docker.internal")
	require.ErrorContains(t, validateCallbackFiles(l, config("https://cb.example.com", "/run/secrets/missing.hex", "/run/secrets/"+callbackServerKey)), "missing.hex")
	require.ErrorContains(t, validateCallbackFiles(l, config("https://cb.example.com", "/etc/key.hex", "/run/secrets/"+callbackServerKey)), "not mounted")
	require.ErrorContains(t, validateCallbackFiles(l, config("https://cb.example.com", "/run/secrets/../state/key", "/run/secrets/"+callbackServerKey)), "not mounted")

	// Relative paths resolve against the state directory, the config's directory in the container.
	require.NoError(t, os.MkdirAll(filepath.Join(l.state, "callback"), 0700))
	writePublicPEM(t, filepath.Join(l.state, "callback", "server.pem"), &server.PublicKey)
	require.NoError(t, validateCallbackFiles(l, config("https://cb.example.com", "/run/secrets/"+callbackPrivateKey, "callback/server.pem")))

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})
	require.NoError(t, os.WriteFile(l.secret(callbackServerKey), privatePEM, 0600))
	require.ErrorContains(t, validateCallbackFiles(l, config("https://cb.example.com", "/run/secrets/"+callbackPrivateKey, "/run/secrets/"+callbackServerKey)), "PRIVATE key")
}

func TestStartRejectsBrokenCallbackBeforePassword(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, _ := fixture(t, a)
	broken := strings.Replace(testConfig, "approval:\n  require_callback: false\n",
		"approval:\n  require_callback: true\ncallback:\n  url: https://cb.example.com/cosigner/approve\n  private_key:\n    type: file\n    config:\n      path: /run/secrets/callback-private.hex\n  response_public_key_path: /run/secrets/callback-response.pub.pem\n", 1)
	require.NoError(t, os.WriteFile(l.config, []byte(broken), 0600))

	err := runCLI(t, a, "--home", l.home, "start")
	require.ErrorContains(t, err, "callback.private_key")
	for _, c := range r.calls {
		require.NotContains(t, c.args, "up", "container must not start")
	}
}

func TestCallbackAddChecksOwnershipBeforeWriting(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	server, cosigner := testRSA(t)
	writeCosignerCallbackKey(t, l, cosigner)
	other := l
	other.state = t.TempDir()
	r.run = func(c runCall) ([]byte, error) {
		switch c.args[0] {
		case "ps":
			return []byte("id"), nil
		case "inspect":
			return containerJSON(t, other, s, true), nil
		}
		return nil, nil
	}
	serverKey := filepath.Join(t.TempDir(), "server.pub.pem")
	writePublicPEM(t, serverKey, &server.PublicKey)

	err := runCLI(t, a, "--home", l.home, "callback", "add", "https://cb.example.com", "--server-public-key", serverKey)
	require.ErrorContains(t, err, "different state directory")

	raw, err := os.ReadFile(l.config)
	require.NoError(t, err)
	require.Equal(t, testConfig, string(raw))
	require.NoFileExists(t, l.secret(callbackServerKey))
}

func TestCallbackAddWithoutTargetExplainsUsage(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	err := runCLI(t, a, "--home", l.home, "callback", "add")
	require.ErrorContains(t, err, "cosigner-cli callback add https://")
}

func TestWrongPasswordFromEnvironmentFailsAtOnce(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	envelope, err := encryptKEK([]byte("right-password"), []byte("kek"))
	require.NoError(t, err)
	a.Getenv = func(name string) string {
		if name == passwordEnv {
			return "wrong-password"
		}
		return ""
	}
	_, err = a.storagePassword(envelope)
	require.ErrorIs(t, err, errWrongPassword)

	a.password = nil
	a.Getenv = func(name string) string {
		if name == passwordEnv {
			return "right-password"
		}
		return ""
	}
	password, err := a.storagePassword(envelope)
	require.NoError(t, err)
	require.Equal(t, "right-password", string(password))
}

func TestCallbackAddFolderModeKeepsLegacyNames(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	server, _ := testRSA(t)
	folder := t.TempDir()
	writePublicPEM(t, filepath.Join(folder, legacyFolderServerKey), &server.PublicKey)

	require.NoError(t, runCLI(t, a, "--home", l.home, "callback", "add", folder))

	require.FileExists(t, filepath.Join(folder, legacyFolderCosignerKey), "an older server reads the legacy name")
	require.NoFileExists(t, filepath.Join(folder, folderCosignerKey))
}
