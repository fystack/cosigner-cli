package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func (a *App) setupCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "up", Short: "Provision once, or start the installed instance", RunE: a.setup}
	cmd.Flags().String("apex-endpoint", DefaultApexEndpoint, "Apex HTTPS endpoint")
	cmd.Flags().String("image", "", "Release image tag or digest (required for first setup)")
	cmd.Flags().String("token-file", "", "Pairing token file; - reads stdin")
	cmd.Flags().String("config", "", "Runtime configuration to copy into a new instance")
	cmd.Flags().String("profile", "manual", "manual or unattended (KMS storage key)")
	cmd.Flags().Bool("allow-insecure-http", false, "Allow HTTP endpoint for isolated development")
	return cmd
}
func (a *App) setup(cmd *cobra.Command, _ []string) error {
	home, err := a.home(cmd)
	if err != nil {
		return err
	}
	l := a.layout(home)
	saved, err := loadSettings(home)
	if err != nil {
		return err
	}
	if fileExists(l.pairing()) {
		for _, flag := range []string{"image", "apex-endpoint", "config", "profile", "token-file"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("up cannot modify a paired instance (%s); use its maintenance command", flag)
			}
		}
		return a.start(cmd, nil)
	}
	// Existing database state without pairing metadata is a recovery case.
	if entries, err := os.ReadDir(filepath.Join(l.state, "data")); err == nil && len(entries) > 0 {
		return errors.New("database exists without pairing metadata; restore the installation")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	docker := a.docker(cmd, saved)
	if err := a.dockerOK(cmd.Context(), docker); err != nil {
		return err
	}
	if _, err := a.ownedContainers(cmd.Context(), docker, l, saved); err != nil {
		return err
	}
	if !fileExists(filepath.Join(home, "cosigner-cli.yaml")) {
		for _, path := range []string{l.config, l.pairing(), l.key(), l.pub(), l.encryptedKEK(), l.compose()} {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("unmanaged file %s exists; use a new directory or restore", path)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		saved.Profile, _ = cmd.Flags().GetString("profile")
		if saved.Profile != "manual" && saved.Profile != "unattended" {
			return errors.New("profile must be manual or unattended")
		}
		saved.ApexEndpoint, _ = cmd.Flags().GetString("apex-endpoint")
		insecure, _ := cmd.Flags().GetBool("allow-insecure-http")
		if err := endpointAllowed(saved.ApexEndpoint, insecure); err != nil {
			return err
		}
		image, _ := cmd.Flags().GetString("image")
		pinned, caps, err := a.resolveImage(cmd.Context(), docker, image)
		if err != nil {
			return err
		}
		saved.Image, saved.RuntimeVersion, saved.Docker = pinned, caps.Version, docker
		input, _ := cmd.Flags().GetString("config")
		if err := a.provision(l, saved, input); err != nil {
			return err
		}
		if err := saveSettings(home, saved); err != nil {
			return err
		}
	} else {
		for _, flag := range []string{"image", "apex-endpoint", "config", "profile"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("incomplete setup already has saved %s; refusing to replace it", flag)
			}
		}
	}
	tokenFile, _ := cmd.Flags().GetString("token-file")
	token, err := a.readToken(tokenFile)
	if err != nil {
		return err
	}
	defer clear(token)
	args, err := a.runtimeArgs(l, saved)
	if err != nil {
		return err
	}
	args = append(args, "-i", saved.Image, "pair", "--mode=regular", "--connect=false", "--config=/var/lib/cosigner/config.yaml", "--out=/var/lib/cosigner", "--token-file=-", "--apex-endpoint="+containerEndpoint(saved.ApexEndpoint))
	a.progress("Pairing the existing local identity with Apex…")
	raw, err := a.Runner.Run(cmd.Context(), docker, args, bytes.NewReader(token), nil)
	if err != nil {
		if bytes.Contains(raw, []byte("cosigner_public_key_already_registered")) {
			return errors.New("identity already registered; restore pairing metadata; no identity was rotated")
		}
		return fmt.Errorf("pairing failed: %w: %s", err, strings.ReplaceAll(string(raw), string(token), "[REDACTED]"))
	}
	if err := validatePaired(l, saved); err != nil {
		return err
	}
	return a.start(cmd, nil)
}
func (a *App) provision(l layout, s Settings, configPath string) error {
	for _, dir := range []string{l.state, filepath.Join(l.home, "secrets")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	raw := []byte("storage:\n  backend: sqlite\n  sqlite:\n    path: data/cosigner.db\n  encryption:\n    kek:\n      type: password_envelope\n      config:\n        path: /run/secrets/storage-kek.enc\napproval:\n  require_callback: true\n")
	if configPath != "" {
		var err error
		raw, err = os.ReadFile(configPath)
		if err != nil {
			return err
		}
	}
	if err := validateManagedConfig(raw, s); err != nil {
		return err
	}
	// New installations must make their approval policy explicit.
	if configPath == "" {
		return errors.New("--config is required: configure an approval callback, or explicitly set approval.require_callback: false for trusted-coordinator signing")
	}
	if s.Profile == "manual" {
		password, err := a.readPassword(true)
		if err != nil {
			return err
		}
		defer clear(password)
		key := make([]byte, 32)
		if _, err := io.ReadFull(a.Random, key); err != nil {
			clear(key)
			return err
		}
		defer clear(key)
		plain := make([]byte, hex.EncodedLen(len(key)))
		hex.Encode(plain, key)
		defer clear(plain)
		envelope, err := encryptKEK(password, plain)
		if err != nil {
			return err
		}
		if err := atomicWrite(l.encryptedKEK(), envelope, 0600); err != nil {
			return err
		}
	}
	if err := atomicWrite(l.config, raw, 0600); err != nil {
		return err
	}
	compose, err := templates.ReadFile("docker-compose.yaml")
	if err != nil {
		return err
	}
	return atomicWrite(l.compose(), compose, 0600)
}
func validateManagedConfig(raw []byte, s Settings) error {
	var cfg struct {
		Storage struct {
			Backend    string
			SQLite     struct{ Path string }
			Encryption struct {
				KEK struct {
					Type   string
					Config struct{ Path string }
				}
			}
		}
		Approval *struct {
			RequireCallback bool `yaml:"require_callback"`
		}
		Callback map[string]any
		Audit    struct{ Type string }
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if cfg.Storage.Backend != "sqlite" || cfg.Storage.SQLite.Path != "data/cosigner.db" {
		return errors.New("operator-managed storage requires sqlite at data/cosigner.db; use native tooling for other backends")
	}
	if cfg.Audit.Type != "file" {
		return errors.New("operator-managed deployments require file audit logging")
	}
	if cfg.Approval == nil {
		return errors.New("configuration must explicitly set approval.require_callback")
	}
	if cfg.Approval.RequireCallback && len(cfg.Callback) == 0 {
		return errors.New("approval.require_callback requires a configured callback")
	}
	if s.Profile == "unattended" && cfg.Storage.Encryption.KEK.Type != "kms" {
		return errors.New("unattended profile requires a configuration with a KMS storage key")
	}
	if s.Profile == "manual" && cfg.Storage.Encryption.KEK.Type != "password_envelope" {
		return errors.New("manual profile requires password_envelope storage key")
	}
	if s.Profile == "manual" && cfg.Storage.Encryption.KEK.Config.Path != "/run/secrets/storage-kek.enc" {
		return errors.New("manual storage envelope must be /run/secrets/storage-kek.enc")
	}
	return nil
}

func (a *App) readToken(path string) ([]byte, error) {
	var reader io.Reader = a.In
	if path == "" {
		f, ok := a.In.(*os.File)
		if !ok || !isTerminal(f) {
			return nil, errors.New("--token-file is required in non-interactive mode")
		}
		fmt.Fprint(a.Out, "Pairing token: ")
		raw, err := readHidden(f)
		fmt.Fprintln(a.Out)
		if err != nil {
			clear(raw)
			return nil, err
		}
		if len(raw) == 0 || len(raw) > defaultTokenMax {
			clear(raw)
			return nil, errors.New("invalid pairing token length")
		}
		return raw, nil
	}
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		reader = f
	}
	raw, err := io.ReadAll(io.LimitReader(reader, defaultTokenMax+1))
	if err != nil {
		clear(raw)
		return nil, err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(raw) > defaultTokenMax {
		clear(raw)
		return nil, errors.New("invalid pairing token length")
	}
	token := append([]byte(nil), trimmed...)
	clear(raw)
	return token, nil
}
func validatePaired(l layout, s Settings) error {
	for _, path := range []string{l.config, l.compose(), l.pairing(), l.key(), l.pub()} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("installation is incomplete (%s); restore it before starting", path)
		}
	}
	if s.Profile == "manual" && !fileExists(l.encryptedKEK()) {
		return errors.New("storage key envelope is missing; restore it")
	}
	var paired struct {
		ParticipantID string `yaml:"participant_id"`
	}
	raw, err := os.ReadFile(l.pairing())
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(raw, &paired); err != nil {
		return err
	}
	if paired.ParticipantID == "" {
		return errors.New("pairing participant_id is missing")
	}
	config, err := os.ReadFile(l.config)
	if err != nil {
		return err
	}
	if err := validateManagedConfig(config, s); err != nil {
		return err
	}
	return validatePinnedImage(s.Image)
}
func (a *App) installation(cmd *cobra.Command) (layout, Settings, error) {
	home, err := a.home(cmd)
	if err != nil {
		return layout{}, Settings{}, err
	}
	l := a.layout(home)
	s, err := loadSettings(home)
	if err != nil {
		return l, s, err
	}
	return l, s, validatePaired(l, s)
}
func (a *App) startCommand() *cobra.Command {
	return &cobra.Command{Use: "start", Short: "Start the installed image", RunE: a.start}
}
func (a *App) start(cmd *cobra.Command, _ []string) error {
	l, s, err := a.installation(cmd)
	if err != nil {
		return err
	}
	running, err := a.alreadyRunning(cmd.Context(), a.docker(cmd, s), l, s)
	if err != nil {
		return err
	}
	if running {
		a.progress("Cosigner is already running; no changes made.")
		return nil
	}
	return a.startService(cmd.Context(), a.docker(cmd, s), l, s, false)
}
func (a *App) startService(ctx context.Context, docker string, l layout, s Settings, recreate bool) error {
	if err := a.dockerOK(ctx, docker); err != nil {
		return err
	}
	if _, err := a.Runner.Run(ctx, docker, []string{"image", "inspect", s.Image}, nil, nil); err != nil {
		if err := a.Runner.Stream(ctx, docker, []string{"pull", s.Image}, nil, nil, a.Out); err != nil {
			return err
		}
	}
	if _, err := a.inspectCapabilities(ctx, docker, s.Image); err != nil {
		return err
	}
	port, token := "0", "unused"
	var unlock *unlockServer
	if s.Profile == "manual" {
		password, err := a.readPassword(false)
		if err != nil {
			return err
		}
		// Verify before recreating a healthy container.
		envelope, err := os.ReadFile(l.encryptedKEK())
		if err != nil {
			clear(password)
			return err
		}
		plain, err := decryptKEK(password, envelope)
		clear(plain)
		if err != nil {
			clear(password)
			return err
		}
		unlock, err = newUnlockServer(password)
		clear(password)
		if err != nil {
			return err
		}
		defer unlock.close()
		port, token = strconv.Itoa(unlock.port()), unlock.token
	}
	args := []string{"up", "-d", "--pull", "never"}
	if recreate {
		args = append(args, "--force-recreate")
	}
	args = append(args, "cosigner")
	if err := a.composeStream(ctx, docker, l, s, port, token, args...); err != nil {
		return err
	}
	if unlock != nil {
		unlockCtx, cancel := context.WithTimeout(ctx, time.Minute)
		err := unlock.wait(unlockCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("storage unlock failed; inspect logs and restart explicitly: %w", err)
		}
	}
	if err := a.waitReady(ctx, docker, l, s); err != nil {
		return err
	}
	a.progress("Cosigner is ready.")
	return nil
}
func (a *App) stopCommand() *cobra.Command {
	return &cobra.Command{Use: "stop", Short: "Stop without deleting state", RunE: func(c *cobra.Command, _ []string) error { return a.lifecycle(c, "stop", "cosigner") }}
}
func (a *App) restartCommand() *cobra.Command {
	return &cobra.Command{Use: "restart", Short: "Restart the installed image", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		return a.startService(c.Context(), a.docker(c, s), l, s, true)
	}}
}
func (a *App) lifecycle(cmd *cobra.Command, args ...string) error {
	l, s, err := a.installation(cmd)
	if err != nil {
		return err
	}
	raw, err := a.compose(cmd.Context(), a.docker(cmd, s), l, s, "0", "unused", args...)
	fmt.Fprint(a.Out, string(raw))
	return err
}
func (a *App) statusCommand() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show runtime readiness", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		raw, err := a.compose(c.Context(), a.docker(c, s), l, s, "0", "unused", "exec", "-T", "cosigner", "/cosigner", "health", "--json")
		fmt.Fprint(a.Out, string(raw))
		return err
	}}
}
func (a *App) logsCommand() *cobra.Command {
	c := &cobra.Command{Use: "logs", Short: "Show container logs", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		tail, _ := c.Flags().GetInt("tail")
		if tail < 1 || tail > 10000 {
			return errors.New("tail must be between 1 and 10000")
		}
		args := []string{"logs", "--tail", strconv.Itoa(tail)}
		if follow, _ := c.Flags().GetBool("follow"); follow {
			args = append(args, "--follow")
		}
		return a.composeStream(c.Context(), a.docker(c, s), l, s, "0", "unused", append(args, "cosigner")...)
	}}
	c.Flags().Int("tail", 200, "Log lines")
	c.Flags().BoolP("follow", "f", false, "Follow logs")
	return c
}
func (a *App) doctorCommand() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Validate installation and runtime compatibility", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		docker := a.docker(c, s)
		if err := a.dockerOK(c.Context(), docker); err != nil {
			return err
		}
		if _, err := a.ownedContainers(c.Context(), docker, l, s); err != nil {
			return err
		}
		caps, err := a.inspectCapabilities(c.Context(), docker, s.Image)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "profile: %s\nimage: %s\nruntime_version: %s\n", s.Profile, s.Image, caps.Version)
		return nil
	}}
}
func (a *App) infoCommand() *cobra.Command {
	return &cobra.Command{Use: "info", Short: "Show public identity and installed version", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(l.pub())
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "public_key: %simage: %s\nruntime_version: %s\n", raw, s.Image, s.RuntimeVersion)
		return nil
	}}
}
func (a *App) runtimeArgs(l layout, s Settings) ([]string, error) {
	platform, err := a.platform()
	if err != nil {
		return nil, err
	}
	return []string{"run", "--rm", "--pull", "never", "--platform", platform, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp", "--add-host", "host.docker.internal:host-gateway", "--volume", l.state + ":/var/lib/cosigner", "--volume", l.config + ":/var/lib/cosigner/config.yaml:ro", "--volume", filepath.Join(l.home, "secrets") + ":/run/secrets:ro"}, nil
}
func (a *App) waitReady(ctx context.Context, docker string, l layout, s Settings) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		raw, err := a.compose(ctx, docker, l, s, "0", "unused", "exec", "-T", "cosigner", "/cosigner", "health", "--json")
		var health struct {
			Ready bool `json:"ready"`
		}
		if err == nil && json.Unmarshal(raw, &health) == nil && health.Ready {
			return nil
		}
		running, checkErr := a.alreadyRunning(ctx, docker, l, s)
		if checkErr != nil {
			return checkErr
		}
		if !running {
			return errors.New("runtime exited before becoming ready; inspect logs")
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("runtime did not become ready: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
func (a *App) versionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print CLI build identity", RunE: func(*cobra.Command, []string) error {
		fmt.Fprintf(a.Out, "cosigner-cli %s (commit %s), operator API 2\n", a.Version, a.Commit)
		return nil
	}}
}
