// Package app implements the host-side operator. Runtime formats are accessed
// through a versioned container contract, never by linking the MPC runtime.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	DefaultApexEndpoint = "https://api.enterprise-sandbox.fystack.io"
	defaultTokenMax     = 4096
	operatorSchema      = 2
)

//go:embed docker-compose.yaml
var templates embed.FS

//go:embed assets/banner
var banner string

type Settings struct {
	SchemaVersion  int    `yaml:"schema_version"`
	ApexEndpoint   string `yaml:"apex_endpoint"`
	Image          string `yaml:"image"`
	PreviousImage  string `yaml:"previous_image,omitempty"`
	ProjectName    string `yaml:"project_name"`
	Docker         string `yaml:"docker"`
	Profile        string `yaml:"profile"`
	RuntimeVersion string `yaml:"runtime_version"`
}

type Runner interface {
	Run(context.Context, string, []string, io.Reader, map[string]string) ([]byte, error)
	Stream(context.Context, string, []string, io.Reader, map[string]string, io.Writer) error
}
type execRunner struct{}

func subprocess(ctx context.Context, name string, args []string, input io.Reader, env map[string]string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = input
	cmd.Env = sanitizedEnvironment()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd
}
func (execRunner) Run(ctx context.Context, name string, args []string, input io.Reader, env map[string]string) ([]byte, error) {
	cmd := subprocess(ctx, name, args, input, env)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.Bytes(), err
}
func (execRunner) Stream(ctx context.Context, name string, args []string, input io.Reader, env map[string]string, out io.Writer) error {
	cmd := subprocess(ctx, name, args, input, env)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

type App struct {
	password        []byte
	In              io.Reader
	Out, Err        io.Writer
	Getenv          func(string) string
	Runner          Runner
	Random          io.Reader
	Tags            func(ctx context.Context, repository string) ([]string, error)
	Version, Commit string
}

func New() *App {
	return &App{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Getenv: os.Getenv, Runner: execRunner{}, Random: rand.Reader, Tags: registryTags, Version: "dev", Commit: "dev"}
}
func (a *App) Command() *cobra.Command {
	root := &cobra.Command{Use: "cosigner-cli", Short: "Manage a Cosigner installation", SilenceUsage: true, SilenceErrors: true}
	root.SetIn(a.In)
	root.SetOut(a.Out)
	root.SetErr(a.Err)
	root.PersistentFlags().String("home", "", "Instance directory (default: current directory)")
	root.PersistentFlags().String("docker", "", "Docker command")
	root.AddCommand(a.setupCommand(), a.startCommand(), a.stopCommand(), a.restartCommand(), a.statusCommand(), a.logsCommand(), a.doctorCommand(), a.infoCommand(), a.backupCommand(), a.restoreCommand(), a.exportCommand(), a.updateCommand(), a.versionCommand())
	for _, cmd := range root.Commands() {
		cmd.Args = cobra.NoArgs
		switch cmd.Name() {
		case "version", "logs", "status", "info", "doctor":
		default:
			if cmd.RunE != nil {
				cmd.RunE = a.withInstance(cmd.RunE)
			}
		}
	}
	return root
}
func (a *App) progress(message string) { fmt.Fprintln(a.Out, "==> "+message) }

// printBanner is terminal-only so that scripts retain clean, parseable output.
func (a *App) printBanner() {
	file, ok := a.Out.(*os.File)
	if !ok || !isTerminal(file) {
		return
	}
	const cyan = "\x1b[38;5;45m"
	const bold = "\x1b[1m"
	const reset = "\x1b[0m"
	fmt.Fprint(a.Out, cyan+bold+"\n"+banner+"\n"+reset)
}

func (a *App) home(cmd *cobra.Command) (string, error) {
	home, _ := cmd.Flags().GetString("home")
	if home == "" {
		home = a.Getenv("COSIGNER_HOME")
	}
	if home == "" {
		home = "."
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, nil
	}
	return abs, nil
}
func (a *App) docker(cmd *cobra.Command, saved Settings) string {
	if v, _ := cmd.Flags().GetString("docker"); v != "" {
		return v
	}
	if saved.Docker != "" {
		return saved.Docker
	}
	return "docker"
}
func loadSettings(home string) (Settings, error) {
	raw, err := os.ReadFile(filepath.Join(home, "cosigner-cli.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return Settings{SchemaVersion: operatorSchema, ProjectName: projectName(home), Docker: "docker", Profile: "manual"}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var cfg Settings
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if cfg.SchemaVersion != operatorSchema {
		return cfg, fmt.Errorf("unsupported operator schema %d; use a new instance directory or the recovery procedure", cfg.SchemaVersion)
	}
	if cfg.ProjectName == "" || (cfg.Profile != "manual" && cfg.Profile != "unattended") {
		return cfg, errors.New("invalid instance settings")
	}
	if err := validatePinnedImage(cfg.Image); err != nil {
		return cfg, err
	}
	return cfg, nil
}
func atomicWrite(path string, content []byte, perm os.FileMode) error {
	return writeAtomic(path, content, perm, false)
}
func atomicReplace(path string, content []byte, perm os.FileMode) error {
	return writeAtomic(path, content, perm, true)
}
func writeAtomic(path string, content []byte, perm os.FileMode, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".cosigner-write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(content)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if replace {
		err = os.Rename(tmp, path)
	} else {
		err = os.Link(tmp, path)
	}
	if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func saveSettings(home string, s Settings) error {
	raw, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	return atomicReplace(filepath.Join(home, "cosigner-cli.yaml"), raw, 0600)
}

type layout struct{ home, state, config string }

func (a *App) layout(home string) layout {
	return layout{home, filepath.Join(home, "state"), filepath.Join(home, "config.yaml")}
}
func (l layout) pairing() string      { return filepath.Join(l.state, "pairing.yaml") }
func (l layout) key() string          { return filepath.Join(l.state, "cosigner.key") }
func (l layout) pub() string          { return filepath.Join(l.state, "cosigner.pub") }
func (l layout) encryptedKEK() string { return filepath.Join(l.home, "secrets", "storage-kek.enc") }
func (l layout) compose() string      { return filepath.Join(l.home, "docker-compose.yaml") }
func fileExists(path string) bool     { i, err := os.Stat(path); return err == nil && i.Mode().IsRegular() }
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func endpointAllowed(endpoint string, insecure bool) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("invalid Apex endpoint")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (insecure || host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return errors.New("Apex endpoint must use HTTPS")
}
func containerEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	host := u.Hostname()
	if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		return endpoint
	}
	port := u.Port()
	u.Host = "host.docker.internal"
	if port != "" {
		u.Host += ":" + port
	}
	return u.String()
}
func (a *App) platform() (string, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return "", errors.New("supported architectures: amd64 and arm64")
	}
	return "linux/" + runtime.GOARCH, nil
}
func (a *App) dockerOK(ctx context.Context, docker string) error {
	if _, err := a.Runner.Run(ctx, docker, []string{"version"}, nil, nil); err != nil {
		return fmt.Errorf("Docker daemon unavailable: %w", err)
	}
	if _, err := a.Runner.Run(ctx, docker, []string{"compose", "version"}, nil, nil); err != nil {
		return fmt.Errorf("Docker Compose v2 required: %w", err)
	}
	return nil
}
func (a *App) composeEnv(l layout, s Settings, port, token string) (map[string]string, error) {
	platform, err := a.platform()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(l.pairing())
	if err != nil {
		return nil, err
	}
	var paired struct {
		Apex struct {
			Endpoint string `yaml:"endpoint"`
		}
		Gateway struct {
			Endpoint string `yaml:"endpoint"`
		}
	}
	if err := yaml.Unmarshal(raw, &paired); err != nil {
		return nil, err
	}
	restart := "no"
	if s.Profile == "unattended" {
		restart = "on-failure:5"
	}
	return map[string]string{
		"COSIGNER_IMAGE": taggedImage(s), "COSIGNER_PLATFORM": platform,
		"COSIGNER_UID": strconv.Itoa(os.Getuid()), "COSIGNER_GID": strconv.Itoa(os.Getgid()),
		"COSIGNER_STATE_DIR": l.state, "COSIGNER_CONFIG": l.config,
		"COSIGNER_SECRETS_DIR": filepath.Join(l.home, "secrets"),
		"COSIGNER_UNLOCK_PORT": port, "COSIGNER_UNLOCK_TOKEN": token,
		"COSIGNER_APEX_ENDPOINT":    containerEndpoint(paired.Apex.Endpoint),
		"COSIGNER_GATEWAY_ENDPOINT": containerEndpoint(paired.Gateway.Endpoint),
		"COSIGNER_RESTART":          restart,
		"COSIGNER_CONTAINER_NAME":   s.ProjectName,
	}, nil
}

// taggedImage adds the release tag in front of the pinned digest so `docker ps`
// shows the version; Docker ignores the tag when a digest is present.
func taggedImage(s Settings) string {
	repository, digest, ok := strings.Cut(s.Image, "@")
	if !ok || !releaseVersion.MatchString(s.RuntimeVersion) {
		return s.Image
	}
	return repository + ":" + strings.TrimPrefix(s.RuntimeVersion, "v") + "@" + digest
}
func (a *App) compose(ctx context.Context, docker string, l layout, s Settings, port, token string, args ...string) ([]byte, error) {
	if _, err := a.ownedContainers(ctx, docker, l, s); err != nil {
		return nil, err
	}
	env, err := a.composeEnv(l, s, port, token)
	if err != nil {
		return nil, err
	}
	full := append([]string{"compose", "-p", s.ProjectName, "-f", l.compose()}, args...)
	return a.Runner.Run(ctx, docker, full, nil, env)
}
func (a *App) composeStream(ctx context.Context, docker string, l layout, s Settings, port, token string, args ...string) error {
	if _, err := a.ownedContainers(ctx, docker, l, s); err != nil {
		return err
	}
	env, err := a.composeEnv(l, s, port, token)
	if err != nil {
		return err
	}
	full := append([]string{"compose", "-p", s.ProjectName, "-f", l.compose()}, args...)
	return a.Runner.Stream(ctx, docker, full, nil, env, a.Out)
}
func isTerminal(f *os.File) bool            { return terminal(f) }
func readHidden(f *os.File) ([]byte, error) { return readHiddenTerminal(f) }
