package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// selfUpdateApp returns an app whose binary is a temp file and whose newest
// CLI release is v1.3.0.
func selfUpdateApp(t *testing.T, r *fakeRunner) (*App, string, *[]string) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "cosigner-cli")
	require.NoError(t, os.WriteFile(exe, []byte("old binary"), 0755))
	a := newTestApp(r)
	a.Executable = func() (string, error) { return exe, nil }
	a.LatestCLI = func(context.Context) (string, error) { return "v1.3.0", nil }
	var fetched []string
	a.Fetch = func(_ context.Context, url string, _ int64) ([]byte, error) {
		fetched = append(fetched, url)
		if strings.HasSuffix(url, ".sigstore.json") {
			return []byte("{}"), nil
		}
		return []byte("new binary"), nil
	}
	return a, exe, &fetched
}

func TestSelfUpdateVerifiesThenReplacesBinary(t *testing.T) {
	var verified []string
	r := &fakeRunner{}
	r.run = func(c runCall) ([]byte, error) {
		if c.name == "cosign" && c.args[0] == "verify-blob" {
			verified = c.args
			raw, err := os.ReadFile(c.args[1])
			require.NoError(t, err)
			require.Equal(t, "new binary", string(raw), "cosign must check the bytes that get installed")
			return nil, nil
		}
		if strings.Contains(filepath.Base(c.name), "cosigner-cli-update") {
			return []byte("cosigner-cli v1.3.0 (commit def)\n"), nil
		}
		return nil, nil
	}
	a, exe, fetched := selfUpdateApp(t, r)
	cmd := a.Command()
	cmd.SetArgs([]string{"self-update"})
	require.NoError(t, cmd.Execute())

	raw, err := os.ReadFile(exe)
	require.NoError(t, err)
	require.Equal(t, "new binary", string(raw))
	info, err := os.Stat(exe)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0755), info.Mode().Perm())
	require.Contains(t, verified, "https://github.com/fystack/cosigner-cli/.github/workflows/release.yml@refs/tags/v1.3.0")
	require.Contains(t, verified, "https://token.actions.githubusercontent.com")
	require.Contains(t, (*fetched)[0], "/releases/download/v1.3.0/cosigner-cli-")
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(exe), ".cosigner-cli-update-*"))
	require.NoError(t, err)
	require.Empty(t, leftovers)
}

func TestSelfUpdateKeepsBinaryWhenVerificationFails(t *testing.T) {
	for name, run := range map[string]func(runCall) ([]byte, error){
		"signature": func(c runCall) ([]byte, error) {
			if c.name == "cosign" && c.args[0] == "verify-blob" {
				return []byte("no matching signatures"), errors.New("exit status 1")
			}
			return nil, nil
		},
		"version": func(c runCall) ([]byte, error) {
			if c.name != "cosign" {
				return []byte("cosigner-cli v1.2.9 (commit x)\n"), nil
			}
			return nil, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, exe, _ := selfUpdateApp(t, &fakeRunner{run: run})
			cmd := a.Command()
			cmd.SetArgs([]string{"self-update"})
			require.ErrorContains(t, cmd.Execute(), "nothing was replaced")
			raw, err := os.ReadFile(exe)
			require.NoError(t, err)
			require.Equal(t, "old binary", string(raw))
		})
	}
}

func TestSelfUpdateVerifiesEvenWhenImageVerificationIsSkipped(t *testing.T) {
	var verified bool
	r := &fakeRunner{run: func(c runCall) ([]byte, error) {
		if c.name == "cosign" && c.args[0] == "verify-blob" {
			verified = true
			return nil, errors.New("exit status 1")
		}
		return nil, nil
	}}
	a, _, _ := selfUpdateApp(t, r)
	a.Getenv = func(k string) string {
		if k == "COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION" {
			return "1"
		}
		return ""
	}
	cmd := a.Command()
	cmd.SetArgs([]string{"self-update"})
	require.Error(t, cmd.Execute())
	require.True(t, verified)
}

func TestSelfUpdateCheckAndDevelopmentBuilds(t *testing.T) {
	r := &fakeRunner{}
	a, exe, fetched := selfUpdateApp(t, r)
	cmd := a.Command()
	cmd.SetArgs([]string{"self-update", "--check"})
	var exit *ExitError
	require.True(t, errors.As(cmd.Execute(), &exit))
	require.Equal(t, exitUpdateAvailable, exit.Code)
	require.Empty(t, *fetched)
	require.Empty(t, r.calls)

	a.LatestCLI = func(context.Context) (string, error) { return "v1.2.3", nil }
	cmd = a.Command()
	cmd.SetArgs([]string{"self-update"})
	require.NoError(t, cmd.Execute())
	raw, err := os.ReadFile(exe)
	require.NoError(t, err)
	require.Equal(t, "old binary", string(raw))

	a.Version = "dev"
	cmd = a.Command()
	cmd.SetArgs([]string{"self-update"})
	require.ErrorContains(t, cmd.Execute(), "development build")

	a.Version = "v1.2.3"
	cmd = a.Command()
	cmd.SetArgs([]string{"self-update", "--version", "v1.2.0"})
	require.ErrorContains(t, cmd.Execute(), "newer stable version")
}
