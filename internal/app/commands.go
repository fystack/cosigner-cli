package app

import (
	"bufio"
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
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Provision and start Cosigner",
		PreRun: func(_ *cobra.Command, _ []string) {
			a.printBanner()
		},
		RunE: a.setup,
	}
	cmd.Flags().String("apex-endpoint", "", "Apex HTTPS endpoint")
	cmd.Flags().String("image", "", "Cosigner release image tag or digest (default: newest signed release)")
	cmd.Flags().String("token-file", "", "Read pairing token from a file; use - for stdin")
	cmd.Flags().String("config", "", "Runtime configuration to copy into a new instance")
	cmd.Flags().String("profile", "manual", "manual or unattended (KMS storage key)")
	cmd.Flags().Bool("allow-insecure-http", false, "Allow non-loopback HTTP Apex endpoint")
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
		if err := a.preflight(cmd.Context(), a.docker(cmd, saved)); err != nil {
			return err
		}
		fmt.Fprintln(a.Out, "Cosigner is already paired; starting the existing identity.")
		return a.start(cmd, nil)
	}
	// Existing database state without pairing metadata is a recovery case.
	if entries, err := os.ReadDir(filepath.Join(l.state, "data")); err == nil && len(entries) > 0 {
		return errors.New("database exists without pairing metadata; restore the installation")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fresh := !fileExists(filepath.Join(home, "cosigner-cli.yaml"))
	if fresh {
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
		saved.ApexEndpoint = strings.TrimRight(strings.TrimSpace(saved.ApexEndpoint), "/")
		if saved.ApexEndpoint == "" {
			if saved.ApexEndpoint, err = a.promptEndpoint(DefaultApexEndpoint); err != nil {
				return err
			}
		}
		insecure, _ := cmd.Flags().GetBool("allow-insecure-http")
		if err := endpointAllowed(saved.ApexEndpoint, insecure); err != nil {
			return err
		}
	} else {
		for _, flag := range []string{"image", "apex-endpoint", "config", "profile"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("incomplete setup already has saved %s; refusing to replace it", flag)
			}
		}
	}
	docker := a.docker(cmd, saved)
	if err := a.preflight(cmd.Context(), docker); err != nil {
		return err
	}
	if _, err := a.ownedContainers(cmd.Context(), docker, l, saved); err != nil {
		return err
	}
	if fresh {
		if err := a.cosignOK(cmd.Context()); err != nil {
			return err
		}
	}
	image, _ := cmd.Flags().GetString("image")
	if fresh && image == "" {
		err := a.step("Finding the newest Cosigner release", func() (string, error) {
			version, err := a.newestRelease(cmd.Context(), defaultRepository)
			image = defaultRepository + ":" + strings.TrimPrefix(version, "v")
			return "Newest release: v" + strings.TrimPrefix(version, "v") + " (" + image + ")", err
		})
		if err != nil {
			return err
		}
	}
	// Pull and verify before asking for secrets, so operators know the image
	// is trustworthy before they type a password or pairing token.
	if fresh {
		a.progress("Pulling Cosigner image " + image + "…")
		pinned, caps, err := a.resolveImage(cmd.Context(), docker, image)
		if err != nil {
			return err
		}
		a.success("Cosigner " + caps.Version + " pinned to " + pinned)
		saved.Image, saved.RuntimeVersion, saved.Docker = pinned, caps.Version, docker
	}
	if input, _ := cmd.Flags().GetString("config"); fresh && input != "" {
		raw, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		if err := validateCallbackFiles(l, raw); err != nil {
			return err
		}
	}
	if saved.Profile == "manual" {
		a.progress("Unlocking encrypted local storage…")
		// Cached on the App, so provisioning and startup reuse this entry.
		readPassword := func() ([]byte, error) { return a.readPassword(false) }
		if fresh {
			readPassword = a.newStoragePassword
		}
		password, err := readPassword()
		if err != nil {
			return err
		}
		clear(password)
	}
	a.progress("Reading pairing token…")
	tokenFile, _ := cmd.Flags().GetString("token-file")
	token, err := a.readToken(tokenFile)
	if err != nil {
		return err
	}
	defer clear(token)
	if fresh {
		input, _ := cmd.Flags().GetString("config")
		if err := a.provision(l, saved, input); err != nil {
			return err
		}
		if err := saveSettings(home, saved); err != nil {
			return err
		}
	}
	args, err := a.runtimeArgs(l, saved)
	if err != nil {
		return err
	}
	args = append(args, "-i", saved.Image, "pair", "--mode=regular", "--connect=false", "--config=/var/lib/cosigner/config.yaml", "--out=/var/lib/cosigner", "--token-file=-", "--apex-endpoint="+containerEndpoint(saved.ApexEndpoint))
	a.progress("Pairing identity with Apex; this may take a minute…")
	var raw bytes.Buffer
	logs := a.logWriter(token)
	err = a.Runner.Stream(cmd.Context(), docker, args, bytes.NewReader(token), nil, io.MultiWriter(&raw, logs))
	logs.Flush()
	if err != nil {
		if bytes.Contains(raw.Bytes(), []byte("cosigner_public_key_already_registered")) {
			return errors.New("identity already registered; restore pairing metadata; no identity was rotated")
		}
		return fmt.Errorf("pairing failed: %w", err)
	}
	if err := validatePaired(l, saved); err != nil {
		return err
	}
	a.success("Paired with Apex")
	return a.start(cmd, nil)
}

func (a *App) preflight(ctx context.Context, docker string) error {
	if err := a.step("Checking Docker and Docker Compose", func() (string, error) { return "", a.dockerOK(ctx, docker) }); err != nil {
		return err
	}
	return a.step("Checking host platform", func() (string, error) {
		platform, err := a.platform()
		return "Host platform: " + platform, err
	})
}

// promptEndpoint lets an interactive operator review the Apex endpoint on a
// fresh setup; non-interactive runs keep the default.
func (a *App) promptEndpoint(defaultValue string) (string, error) {
	file, ok := a.In.(*os.File)
	if !ok || !isTerminal(file) {
		return defaultValue, nil
	}
	fmt.Fprintf(a.Out, "Fystack Endpoint (Optional) [%s]: ", defaultValue)
	value, err := bufio.NewReader(file).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read Apex endpoint: %w", err)
	}
	if value = strings.TrimRight(strings.TrimSpace(value), "/"); value != "" {
		return value, nil
	}
	return defaultValue, nil
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
	// The built-in configuration is deliberately suitable only for an isolated
	// development or trusted-coordinator deployment. Production installations
	// should supply --config with a callback policy.
	raw := []byte("storage:\n  backend: sqlite\n  sqlite:\n    path: data/cosigner.db\n  encryption:\n    kek:\n      type: password_envelope\n      config:\n        path: /run/secrets/storage-kek.enc\napproval:\n  require_callback: false\naudit:\n  type: file\n  config:\n    path: /var/lib/cosigner/audit.jsonl\n")
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
	if s.Profile == "manual" {
		password, err := a.newStoragePassword()
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
			return nil, errors.New("pairing token is required in non-interactive mode; pass --token-file=-")
		}
		fmt.Fprint(a.Out, "Pairing token: ")
		raw, err := readHidden(f)
		fmt.Fprintln(a.Out)
		if err != nil {
			clear(raw)
			return nil, err
		}
		token := append([]byte(nil), bytes.TrimSpace(raw)...)
		clear(raw)
		if err := tokenLength(token); err != nil {
			return nil, err
		}
		return token, nil
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
	if len(raw) > defaultTokenMax {
		clear(raw)
		return nil, errors.New("pairing token is too large")
	}
	token := append([]byte(nil), bytes.TrimSpace(raw)...)
	clear(raw)
	if err := tokenLength(token); err != nil {
		return nil, err
	}
	return token, nil
}
func tokenLength(token []byte) error {
	if len(token) == 0 {
		return errors.New("pairing token is required")
	}
	if len(token) > defaultTokenMax {
		clear(token)
		return errors.New("pairing token is too large")
	}
	return nil
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
	return &cobra.Command{Use: "start", Short: "Start an existing paired Cosigner", RunE: a.start}
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
	} else if err := a.startService(cmd.Context(), a.docker(cmd, s), l, s, false); err != nil {
		return err
	}
	a.notifyUpdate(cmd.Context(), s)
	return nil
}
func (a *App) startService(ctx context.Context, docker string, l layout, s Settings, recreate bool) error {
	if err := a.dockerOK(ctx, docker); err != nil {
		return err
	}
	config, err := os.ReadFile(l.config)
	if err != nil {
		return err
	}
	if err := validateCallbackFiles(l, config); err != nil {
		return err
	}
	if _, err := a.Runner.Run(ctx, docker, []string{"image", "inspect", s.Image}, nil, nil); err != nil {
		a.progress("Pulling Cosigner image " + s.Image + "…")
		if err := a.Runner.Stream(ctx, docker, []string{"pull", s.Image}, nil, nil, a.Out); err != nil {
			return err
		}
	}
	// The digest was signature-verified when it was installed and is content
	// addressed, so startup only rechecks the runtime contract (offline).
	if _, err := a.runtimeCapabilities(ctx, docker, s.Image); err != nil {
		return err
	}
	port, token := "0", "unused"
	var unlock *unlockServer
	if s.Profile == "manual" {
		envelope, err := os.ReadFile(l.encryptedKEK())
		if err != nil {
			return err
		}
		// Verify before recreating a healthy container.
		password, err := a.storagePassword(envelope)
		if err != nil {
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
	a.progress("Starting Cosigner container…")
	if err := a.composeStream(ctx, docker, l, s, port, token, args...); err != nil {
		return fmt.Errorf("start Cosigner: %w", err)
	}
	if unlock != nil {
		err := a.step("Unlocking storage inside Cosigner", func() (string, error) {
			unlockCtx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			return "Storage unlocked", unlock.wait(unlockCtx)
		})
		if err != nil {
			a.dumpContainerLogs(ctx, docker, l, s)
			return fmt.Errorf("storage unlock failed; inspect logs and restart explicitly: %w", err)
		}
	}
	if err := a.step("Waiting for Cosigner to become ready", func() (string, error) {
		return "Cosigner " + s.RuntimeVersion + " is running", a.waitReady(ctx, docker, l, s)
	}); err != nil {
		a.dumpContainerLogs(ctx, docker, l, s)
		return err
	}
	a.showRecentLogs(ctx, docker, l, s)
	return nil
}

// showRecentLogs gives operators a glimpse of a healthy startup; failures to
// read logs are ignored because the service is already up.
func (a *App) showRecentLogs(ctx context.Context, docker string, l layout, s Settings) {
	raw, err := a.compose(ctx, docker, l, s, "0", "unused", "logs", "--tail", "20", "--no-color", "--no-log-prefix", "cosigner")
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return
	}
	a.progress("Recent Cosigner logs (follow with `cosigner-cli logs -f`):")
	logs := a.logWriter(nil)
	logs.Write(raw)
	logs.Flush()
}

// dumpContainerLogs shows why a startup failed without a separate `logs` run.
func (a *App) dumpContainerLogs(ctx context.Context, docker string, l layout, s Settings) {
	raw, err := a.compose(ctx, docker, l, s, "0", "unused", "logs", "--tail", "100", "--no-color", "cosigner")
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		fmt.Fprintln(a.Err, "==> Could not read Cosigner container logs; run `cosigner-cli logs` to see the failure.")
		return
	}
	fmt.Fprintln(a.Err, "==> Recent Cosigner container logs:")
	fmt.Fprint(a.Err, string(raw))
}
func (a *App) stopCommand() *cobra.Command {
	return &cobra.Command{Use: "stop", Short: "Stop Cosigner without deleting state", RunE: func(c *cobra.Command, _ []string) error { return a.lifecycle(c, "stop", "cosigner") }}
}
func (a *App) restartCommand() *cobra.Command {
	return &cobra.Command{Use: "restart", Short: "Restart an existing paired Cosigner", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		if err := a.startService(c.Context(), a.docker(c, s), l, s, true); err != nil {
			return err
		}
		a.notifyUpdate(c.Context(), s)
		return nil
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
	return &cobra.Command{Use: "status", Short: "Show Cosigner runtime status", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		raw, err := a.compose(c.Context(), a.docker(c, s), l, s, "0", "unused", "exec", "-T", "cosigner", "/cosigner", "health", "--json")
		fmt.Fprint(a.Out, string(raw))
		if err != nil {
			return err
		}
		a.notifyUpdate(c.Context(), s)
		return nil
	}}
}
func (a *App) logsCommand() *cobra.Command {
	c := &cobra.Command{Use: "logs", Short: "Show Cosigner logs", RunE: func(c *cobra.Command, _ []string) error {
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
	c.Flags().Int("tail", 200, "Number of log lines")
	c.Flags().BoolP("follow", "f", false, "Follow logs")
	return c
}
func (a *App) doctorCommand() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check Docker, configuration, and installation state", RunE: func(c *cobra.Command, _ []string) error {
		home, err := a.home(c)
		if err != nil {
			return err
		}
		l := a.layout(home)
		s, err := loadSettings(home)
		if err != nil {
			return err
		}
		docker := a.docker(c, s)
		if err := a.dockerOK(c.Context(), docker); err != nil {
			return err
		}
		if !fileExists(l.config) {
			fmt.Fprintln(a.Out, "State: unconfigured")
			return nil
		}
		if !fileExists(l.pairing()) {
			fmt.Fprintln(a.Out, "State: configured but unpaired")
			return nil
		}
		if err := validatePaired(l, s); err != nil {
			return err
		}
		config, err := os.ReadFile(l.config)
		if err != nil {
			return err
		}
		if err := validateCallbackFiles(l, config); err != nil {
			return err
		}
		if _, err := a.ownedContainers(c.Context(), docker, l, s); err != nil {
			return err
		}
		if err := a.cosignOK(c.Context()); err != nil {
			return err
		}
		caps, err := a.inspectCapabilities(c.Context(), docker, s.Image)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "profile: %s\nimage: %s\nruntime_version: %s\n", s.Profile, s.Image, caps.Version)
		fmt.Fprintln(a.Out, "State: paired (run `cosigner-cli status` for container state)")
		a.notifyUpdate(c.Context(), s)
		return nil
	}}
}
func (a *App) infoCommand() *cobra.Command {
	return &cobra.Command{Use: "info", Short: "Print public Cosigner identity", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(l.pub())
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "public_key: %simage: %s\nruntime_version: %s\n%s", raw, s.Image, s.RuntimeVersion, callbackInfo(l))
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
	return &cobra.Command{Use: "version", Short: "Print host and runtime build identity", RunE: func(*cobra.Command, []string) error {
		fmt.Fprintf(a.Out, "cosigner-cli %s (commit %s)\n", a.Version, a.Commit)
		return nil
	}}
}
