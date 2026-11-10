package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// candidateRunner answers the pull, inspect and capability calls of an update
// to v1.2.4 and records every call.
func candidateRunner(t *testing.T, r *fakeRunner, extra func(runCall) ([]byte, error)) {
	t.Helper()
	digest := "fystacklabs/cosigner@sha256:" + strings.Repeat("b", 64)
	r.run = func(c runCall) ([]byte, error) {
		switch {
		case c.name == "cosign":
			return []byte("verified"), nil
		case len(c.args) > 0 && c.args[0] == "pull":
			return nil, nil
		case len(c.args) > 1 && c.args[0] == "image" && c.args[1] == "inspect" && len(c.args) > 3:
			return json.Marshal([]string{digest})
		case len(c.args) > 0 && c.args[len(c.args)-1] == "capabilities":
			return []byte(`{"operator_api":2,"unlock_protocol":2,"storage_schema":1,"version":"1.2.4"}`), nil
		}
		if extra != nil {
			return extra(c)
		}
		return nil, nil
	}
}

func composeCall(r *fakeRunner, verb string) bool {
	for _, c := range r.calls {
		if len(c.args) > 0 && c.args[0] == "compose" {
			for _, arg := range c.args {
				if arg == verb {
					return true
				}
			}
		}
	}
	return false
}

func TestArchiveDestinationAllowsOnlyOutsideOrBackupsFolder(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	outside := filepath.Join(t.TempDir(), "a.enc")
	for _, ok := range []string{outside, filepath.Join(l.home, "backups", "a.enc"), filepath.Join(l.home, "backups", "nested", "a.enc")} {
		_, err := archiveDestination(l, ok)
		require.NoError(t, err, ok)
	}
	for _, bad := range []string{filepath.Join(l.home, "a.enc"), filepath.Join(l.home, "state", "a.enc"), filepath.Join(l.home, "secrets", "a.enc"), filepath.Join(l.home, "backups")} {
		_, err := archiveDestination(l, bad)
		require.ErrorContains(t, err, "inside the instance directory", bad)
	}
	// A backups/ link into state/ is the state directory, not a backups folder.
	require.NoError(t, os.Symlink(l.state, filepath.Join(l.home, "backups")))
	_, err := archiveDestination(l, filepath.Join(l.home, "backups", "a.enc"))
	require.ErrorContains(t, err, "inside the instance directory")
}

func TestUpdateRejectsCheckpointInsideInstanceBeforePulling(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, _ := fixture(t, a)
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--version", "1.2.4", "--backup-out", filepath.Join(l.state, "pre.enc")})
	err := cmd.Execute()
	require.ErrorContains(t, err, "inside the instance directory")
	var hinted interface{ Hint() string }
	require.True(t, errors.As(err, &hinted))
	require.Contains(t, hinted.Hint(), filepath.Join(l.home, "backups"))
	require.Empty(t, r.calls)
}

func TestUpdateWithoutTerminalRequiresYes(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	candidateRunner(t, r, nil)
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--version", "1.2.4"})
	require.ErrorContains(t, cmd.Execute(), "--yes")
	require.False(t, composeCall(r, "stop"), "update must not stop Cosigner before it is confirmed")
	after, err := loadSettings(l.home)
	require.NoError(t, err)
	require.Equal(t, s, after)
	_, err = os.Stat(filepath.Join(l.home, "backups"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestUpdateWritesDefaultCheckpointBeforeStartingCandidate(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, s := fixture(t, a)
	a.Getenv = recoveryPasswordEnv("recovery password")
	candidateRunner(t, r, nil)
	var out bytes.Buffer
	a.Out = &out
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--version", "1.2.4", "--yes"})
	// The fixture has no storage passphrase, so the candidate fails to start
	// after the checkpoint; that is the path where the checkpoint matters.
	runErr := cmd.Execute()
	require.ErrorContains(t, runErr, "did not start")
	require.True(t, composeCall(r, "stop"))

	entries, readErr := os.ReadDir(filepath.Join(l.home, "backups"))
	require.NoError(t, readErr)
	require.Len(t, entries, 1)
	name := entries[0].Name()
	require.True(t, strings.HasPrefix(name, "pre-update-v1.2.3-to-v1.2.4-"), name)
	home, err := filepath.EvalSymlinks(l.home)
	require.NoError(t, err)
	checkpoint := filepath.Join(home, "backups", name)
	var hinted interface{ Hint() string }
	require.True(t, errors.As(runErr, &hinted))
	require.Contains(t, hinted.Hint(), checkpoint)
	require.Contains(t, out.String(), "Cosigner runtime update")
	require.Contains(t, out.String(), "Checkpoint  "+checkpoint)

	after, loadErr := loadSettings(l.home)
	require.NoError(t, loadErr)
	require.Equal(t, s.Image, after.PreviousImage)
	require.Equal(t, "1.2.4", after.RuntimeVersion)

	// The checkpoint restores into a directory that holds only it.
	target := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(target, "backups"), 0700))
	require.NoError(t, os.Rename(checkpoint, filepath.Join(target, "backups", name)))
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", target, "restore", "--in", filepath.Join(target, "backups", name)})
	require.NoError(t, cmd.Execute())
	restored, err := loadSettings(target)
	require.NoError(t, err)
	require.Equal(t, s.Image, restored.Image)
}

func TestUpdateCheckAnswersWithExitStatus(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, _ := fixture(t, a)
	a.Tags = func(context.Context, string) ([]string, error) { return []string{"1.2.3", "1.2.4"}, nil }
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--check"})
	var exit *ExitError
	require.True(t, errors.As(cmd.Execute(), &exit))
	require.Equal(t, exitUpdateAvailable, exit.Code)
	require.Empty(t, r.calls, "--check must not pull or verify anything")

	a.Tags = func(context.Context, string) ([]string, error) { return []string{"1.2.3"}, nil }
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--check"})
	require.NoError(t, cmd.Execute())
}

func TestUpdateJSONKeepsStdoutParseable(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, _ := fixture(t, a)
	candidateRunner(t, r, nil)
	var stdout, stderr bytes.Buffer
	a.Out, a.Err = &stdout, &stderr
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "update", "--version", "1.2.4", "--dry-run", "--json"})
	require.NoError(t, cmd.Execute())
	var report updateReport
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report), stdout.String())
	require.Equal(t, "runtime", report.Component)
	require.Equal(t, "v1.2.3", report.Installed.Version)
	require.True(t, report.UpdateAvailable)
	require.Equal(t, "v1.2.4", report.Candidate.Version)
	require.False(t, report.Updated)
	require.Contains(t, stderr.String(), "Cosigner runtime update")
}

func TestRuntimeNeedingNewerCLIPointsAtSelfUpdate(t *testing.T) {
	a := newTestApp(&fakeRunner{run: func(runCall) ([]byte, error) {
		return []byte(`{"operator_api":3,"unlock_protocol":2,"storage_schema":1,"version":"2.0.0"}`), nil
	}})
	_, err := a.runtimeCapabilities(context.Background(), "docker", testImage)
	require.ErrorContains(t, err, "runtime v2.0.0 needs a newer cosigner-cli")
	var hinted interface{ Hint() string }
	require.True(t, errors.As(err, &hinted))
	require.Contains(t, hinted.Hint(), "self-update")
}

func TestVersionShowsCLIAndRuntime(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	a.Commit = "abc123"
	l, s := fixture(t, a)
	var out bytes.Buffer
	a.Out = &out
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "version"})
	require.NoError(t, cmd.Execute())
	lines := strings.Split(out.String(), "\n")
	require.Equal(t, "cosigner-cli v1.2.3 (commit abc123)", lines[0], "install.sh parses this line")
	require.Equal(t, "runtime      v1.2.3 ("+s.Image+")", lines[1])

	out.Reset()
	a.LatestCLI = func(context.Context) (string, error) { return "v1.3.0", nil }
	a.Tags = func(context.Context, string) ([]string, error) { return []string{"1.2.3"}, nil }
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", l.home, "version", "--check", "--json"})
	require.NoError(t, cmd.Execute())
	var report versionReport
	require.NoError(t, json.Unmarshal(out.Bytes(), &report))
	require.Equal(t, "v1.3.0", report.CLI.Latest)
	require.True(t, report.CLI.UpdateAvailable)
	require.Equal(t, "v1.2.3", report.Runtime.Latest)
	require.False(t, report.Runtime.UpdateAvailable)

	out.Reset()
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", t.TempDir(), "version"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "runtime      not installed here")
}

func TestBackupDefaultsToBackupsFolder(t *testing.T) {
	r := &fakeRunner{}
	a := newTestApp(r)
	l, _ := fixture(t, a)
	a.Getenv = recoveryPasswordEnv("recovery password")
	cmd := a.Command()
	cmd.SetArgs([]string{"--home", l.home, "backup"})
	require.NoError(t, cmd.Execute())
	entries, err := os.ReadDir(filepath.Join(l.home, "backups"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.True(t, strings.HasPrefix(entries[0].Name(), "backup-v1.2.3-"))
	info, err := os.Stat(filepath.Join(l.home, "backups"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())

	dir := t.TempDir()
	a.Getenv = func(k string) string {
		if k == "COSIGNER_BACKUP_DIR" {
			return dir
		}
		return recoveryPasswordEnv("recovery password")(k)
	}
	cmd = a.Command()
	cmd.SetArgs([]string{"--home", l.home, "backup"})
	require.NoError(t, cmd.Execute())
	entries, err = os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// A later backup never captures earlier archives.
	bundle, err := snapshotInstallation(l, Settings{Image: testImage})
	require.NoError(t, err)
	for _, f := range bundle.Files {
		require.False(t, strings.HasPrefix(f.Path, "backups/"), f.Path)
	}
}

func TestRecoveryPasswordWithoutTerminalNamesRecoveryVariables(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	_, err := a.recoveryPassword(false)
	require.ErrorContains(t, err, "COSIGNER_RECOVERY_PASSWORD is required")
	var hinted interface{ Hint() string }
	require.True(t, errors.As(err, &hinted))
	require.Contains(t, hinted.Hint(), "COSIGNER_RECOVERY_PASSWORD_FD")
}

func TestHelpEnvironmentListsEveryVariable(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	var out bytes.Buffer
	a.Out = &out
	cmd := a.Command()
	cmd.SetArgs([]string{"help", "environment"})
	require.NoError(t, cmd.Execute())
	for _, name := range []string{"COSIGNER_HOME", "COSIGNER_BACKUP_DIR", "COSIGNER_PASSWORD_FD", "COSIGNER_PASSWORD", "COSIGNER_RECOVERY_PASSWORD_FD", "COSIGNER_RECOVERY_PASSWORD", "COSIGNER_NO_UPDATE_CHECK", "COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION"} {
		require.Contains(t, out.String(), name)
	}
}
