package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func projectName(home string) string {
	sum := sha256.Sum256([]byte(home))
	return fmt.Sprintf("fystack-cosigner-%x", sum[:8])
}

// withInstance serializes operations even when the command returns an error.
// Lock files are never removed: unlinking a flock inode permits double ownership.
func (a *App) withInstance(run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		defer func() { clear(a.password); a.password = nil }()
		home, err := a.home(cmd)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(home, 0700); err != nil {
			return err
		}
		unlock, err := lockFile(filepath.Join(home, ".cosigner-cli.lock"))
		if err != nil {
			return err
		}
		defer unlock()
		for _, name := range []string{"state", "secrets", "config.yaml", "cosigner-cli.yaml", "docker-compose.yaml"} {
			info, err := os.Lstat(filepath.Join(home, name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("instance path %s must not be a symlink", name)
			}
		}
		return run(cmd, args)
	}
}

type containerDetails struct {
	ID     string
	Config struct {
		Labels map[string]string
		Image  string
	}
	State struct {
		Status  string
		Running bool
	}
	Mounts []struct{ Source, Destination string }
}

// Always resolve Compose ownership before invoking it. A copied settings file
// or legacy global project name must never redirect another instance's service.
func (a *App) ownedContainers(ctx context.Context, docker string, l layout, saved Settings) ([]containerDetails, error) {
	if saved.ProjectName == "" {
		return nil, errors.New("missing instance project name")
	}
	raw, err := a.Runner.Run(ctx, docker, []string{"ps", "-aq", "--filter", "label=com.docker.compose.project=" + saved.ProjectName}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("inspect instance ownership: %w", err)
	}
	ids := strings.Fields(string(raw))
	if len(ids) == 0 {
		return nil, nil
	}
	raw, err = a.Runner.Run(ctx, docker, append([]string{"inspect"}, ids...), nil, nil)
	if err != nil {
		return nil, fmt.Errorf("inspect instance containers: %w", err)
	}
	var containers []containerDetails
	if err := json.Unmarshal(raw, &containers); err != nil {
		return nil, fmt.Errorf("decode instance ownership: %w", err)
	}
	if len(containers) != len(ids) {
		return nil, errors.New("incomplete container ownership response")
	}
	for _, c := range containers {
		if c.Config.Labels["com.docker.compose.project"] != saved.ProjectName || c.Config.Labels["com.docker.compose.service"] != "cosigner" {
			return nil, errors.New("Compose project contains an unexpected service; refusing to modify it")
		}
		owned := false
		for _, mount := range c.Mounts {
			if mount.Destination == "/var/lib/cosigner" {
				source, err := filepath.EvalSymlinks(mount.Source)
				if err != nil {
					return nil, err
				}
				state, err := filepath.EvalSymlinks(l.state)
				if err != nil {
					return nil, err
				}
				owned = source == state
			}
		}
		if !owned {
			return nil, fmt.Errorf("Compose project %s belongs to a different state directory; refusing operation", saved.ProjectName)
		}
	}
	return containers, nil
}

func (a *App) alreadyRunning(ctx context.Context, docker string, l layout, saved Settings) (bool, error) {
	containers, err := a.ownedContainers(ctx, docker, l, saved)
	if err != nil {
		return false, err
	}
	for _, c := range containers {
		if c.State.Running {
			if c.State.Status == "paused" || c.State.Status == "restarting" {
				return false, fmt.Errorf("instance is %s; stop it explicitly before continuing", c.State.Status)
			}
			if c.Config.Image != saved.Image && c.Config.Image != taggedImage(saved) {
				return false, errors.New("running image differs from the installed digest; stop and reconcile it explicitly")
			}
			return true, nil
		}
		if c.State.Status == "restarting" || c.State.Status == "paused" {
			return false, fmt.Errorf("instance is %s; stop it explicitly before continuing", c.State.Status)
		}
	}
	return false, nil
}

func sanitizedEnvironment() []string {
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == passwordEnv || name == "COSIGNER_PASSWORD_FD" || strings.HasPrefix(name, "COSIGNER_RECOVERY_PASSWORD") || strings.HasPrefix(name, "COSIGNER_UNLOCK_") {
			continue
		}
		env = append(env, entry)
	}
	return env
}
