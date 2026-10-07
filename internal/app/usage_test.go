package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUsageMistakesCarryCommandHelp(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)

	var usage *UsageError
	err := runCLI(t, a, "--home", l.home, "callback", "add", "--sever-public-key", "x.pem")
	require.True(t, errors.As(err, &usage), "unknown flag must be a usage error: %v", err)
	require.Contains(t, usage.Help(), "cosigner-cli callback add [url|folder] [flags]")
	require.Contains(t, usage.Help(), "cosigner-cli callback add ./callback-keys")
	require.Contains(t, usage.Help(), "Run 'cosigner-cli callback add --help'")

	err = runCLI(t, a, "--home", l.home, "callback", "add", "a", "b")
	require.True(t, errors.As(err, &usage), "too many args must be a usage error: %v", err)

	err = runCLI(t, a, "--home", l.home, "strat")
	require.True(t, errors.As(err, &usage), "unknown command must be a usage error: %v", err)
	require.ErrorContains(t, err, `did you mean "start"`)

	err = runCLI(t, a, "--home", l.home, "start", "extra")
	require.True(t, errors.As(err, &usage), "stray argument must be a usage error: %v", err)
}

func TestRuntimeFailuresAreNotUsageErrors(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	l, _ := fixture(t, a)
	var usage *UsageError
	err := runCLI(t, a, "--home", l.home, "callback", "add", "http://localhost:8089")
	require.Error(t, err)
	require.False(t, errors.As(err, &usage))
}

func TestRootWithoutCommandShowsHelp(t *testing.T) {
	a := newTestApp(&fakeRunner{})
	require.NoError(t, runCLI(t, a))
}
