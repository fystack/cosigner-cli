package app

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	callbackKeyBits     = 4096
	callbackApprovePath = "/cosigner/approve"
	callbackDevURL      = "http://host.docker.internal:8089" + callbackApprovePath
	callbackPrivateKey  = "callback-private.hex"
	callbackServerKey   = "callback-response.pub.pem"
	callbackCA          = "callback-ca.pem"
	// Public half exported for the callback server; not secret, so it lives outside secrets/.
	callbackPublicKey       = "cosigner-public.pem"
	legacyCallbackPublicKey = "callback-public.pem"
	callbackMaxInputBytes   = 64 << 10

	// Folder mode names files by owner, matching examples/node-callback-server.
	folderServerKey   = "server-public.pem"
	folderCosignerKey = "cosigner-public.pem"
	// Older callback servers name them by message direction instead.
	legacyFolderServerKey   = "response-public.pem"
	legacyFolderCosignerKey = "request-public.pem"

	containerSecrets = "/run/secrets/"
	containerState   = "/var/lib/cosigner/"
)

func (l layout) secret(name string) string { return filepath.Join(l.home, "secrets", name) }

func (a *App) callbackCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "callback", Short: "Manage the transaction approval callback"}
	cmd.AddCommand(a.callbackAddCommand(), a.callbackRemoveCommand())
	return cmd
}

func (a *App) callbackAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [url|folder]",
		Short: "Require approval from a callback server before signing",
		Long: "Point Cosigner at a callback server. Pass the server URL, or the server's key folder\n" +
			"when it runs on this machine (reads " + folderServerKey + ", writes " + folderCosignerKey + ").",
		Example: "  cosigner-cli callback add ./callback-keys\n" +
			"  cosigner-cli callback add https://callback.example.com --server-public-key server-public.pem",
		Args: cobra.MaximumNArgs(1),
		RunE: a.withInstance(a.callbackAdd),
	}
	cmd.Flags().String("url", "", "Callback URL in folder mode (default "+callbackDevURL+")")
	cmd.Flags().String("server-public-key", "", "Callback server's PUBLIC key PEM file (never its private key); - for stdin (default: prompt)")
	cmd.Flags().String("ca", "", "CA certificate PEM when the callback uses a private or self-signed TLS certificate")
	cmd.Flags().Bool("no-restart", false, "Do not restart a running Cosigner")
	return cmd
}

func (a *App) callbackRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Stop requiring callback approval",
		Args:  cobra.NoArgs,
		RunE:  a.withInstance(a.callbackRemove),
	}
	cmd.Flags().BoolP("yes", "y", false, "Skip the confirmation prompt")
	cmd.Flags().Bool("no-restart", false, "Do not restart a running Cosigner")
	return cmd
}

func (a *App) callbackAdd(cmd *cobra.Command, args []string) error {
	l, s, err := a.installation(cmd)
	if err != nil {
		return err
	}
	rawURL, _ := cmd.Flags().GetString("url")
	serverKeyPath, _ := cmd.Flags().GetString("server-public-key")
	caPath, _ := cmd.Flags().GetString("ca")

	folder, callbackURL, err := a.callbackTarget(args, rawURL)
	if err != nil {
		return err
	}
	cosignerKeyName := folderCosignerKey
	if folder != "" && serverKeyPath == "" {
		serverKeyPath = filepath.Join(folder, folderServerKey)
		if legacy := filepath.Join(folder, legacyFolderServerKey); !fileExists(serverKeyPath) && fileExists(legacy) {
			serverKeyPath, cosignerKeyName = legacy, legacyFolderCosignerKey
		}
	}
	running, err := a.alreadyRunning(cmd.Context(), a.docker(cmd, s), l, s)
	if err != nil {
		return err
	}

	// Validate every input before writing anything, so a bad key leaves the instance untouched.
	serverPEM, source, err := a.serverPublicKey(serverKeyPath)
	if err != nil {
		return err
	}
	a.success("Callback server public key (RSA-4096) from " + source)
	fmt.Fprint(a.Out, keySummary(serverPEM))
	var caPEM []byte
	if caPath != "" {
		if caPEM, err = readLimited(caPath); err != nil {
			return err
		}
		if err := validateCertificates(caPEM); err != nil {
			return fmt.Errorf("--ca: %w", err)
		}
	}
	raw, err := os.ReadFile(l.config)
	if err != nil {
		return err
	}

	key, err := a.callbackKey(l)
	if err != nil {
		return err
	}
	publicPEM, fingerprint, err := publicKeyPEM(&key.PublicKey)
	if err != nil {
		return err
	}

	block := callbackBlock{URL: callbackURL, PrivateKeyPath: containerSecrets + callbackPrivateKey, ServerKeyPath: containerSecrets + callbackServerKey}
	if caPEM != nil {
		block.CAPath = containerSecrets + callbackCA
	}
	updated, err := setCallbackConfig(raw, &block)
	if err != nil {
		return err
	}
	if err := validateManagedConfig(updated, s); err != nil {
		return err
	}
	if err := atomicReplace(l.secret(callbackServerKey), serverPEM, 0600); err != nil {
		return err
	}
	if caPEM != nil {
		err = atomicReplace(l.secret(callbackCA), caPEM, 0600)
	} else {
		err = removeIfExists(l.secret(callbackCA))
	}
	if err != nil {
		return err
	}
	if err := atomicReplace(l.config, updated, 0600); err != nil {
		return err
	}
	a.success("Callback set to " + callbackURL)

	if folder != "" {
		path := filepath.Join(folder, cosignerKeyName)
		if err := atomicReplace(path, publicPEM, 0644); err != nil {
			return err
		}
		a.success("Wrote Cosigner public key to " + path + " (the Node example picks it up; restart other callback servers)")
	} else {
		path := filepath.Join(l.home, callbackPublicKey)
		if err := atomicReplace(path, publicPEM, 0644); err != nil {
			return err
		}
		if err := removeIfExists(filepath.Join(l.home, legacyCallbackPublicKey)); err != nil {
			return err
		}
		a.success("Cosigner public key: " + path)
		fmt.Fprintf(a.Out, "\nNext: copy %s to the callback server (it verifies requests with this key).\nThe Node example expects it as keys/%s and picks it up; restart other servers. Fingerprint: %s\n\n", path, folderCosignerKey, fingerprint)
	}

	if err := a.applyConfig(cmd, l, s, running); err != nil {
		return err
	}
	a.warn("Signing requests are rejected until the callback server is reachable and trusts this Cosigner public key.")
	return nil
}

func (a *App) callbackRemove(cmd *cobra.Command, _ []string) error {
	l, s, err := a.installation(cmd)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(l.config)
	if err != nil {
		return err
	}
	cfg, err := parseCallbackConfig(raw)
	if err != nil {
		return err
	}
	if cfg.Callback == nil && !cfg.Approval.RequireCallback {
		fmt.Fprintln(a.Out, "No callback is configured.")
		return nil
	}
	running, err := a.alreadyRunning(cmd.Context(), a.docker(cmd, s), l, s)
	if err != nil {
		return err
	}
	if yes, _ := cmd.Flags().GetBool("yes"); !yes {
		ok, err := a.confirm("Remove the callback? Cosigner will sign without external approval. [y/N]: ")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("callback not removed")
		}
	}
	updated, err := setCallbackConfig(raw, nil)
	if err != nil {
		return err
	}
	if err := validateManagedConfig(updated, s); err != nil {
		return err
	}
	if err := atomicReplace(l.config, updated, 0600); err != nil {
		return err
	}
	// The Cosigner's own callback key is kept so a later `callback add` reuses the same identity.
	for _, name := range []string{callbackServerKey, callbackCA} {
		if err := removeIfExists(l.secret(name)); err != nil {
			return err
		}
	}
	a.success("Callback removed")
	return a.applyConfig(cmd, l, s, running)
}

// applyConfig restarts a running Cosigner so a config change takes effect.
// Callers check running before writing, so an ownership error changes nothing.
func (a *App) applyConfig(cmd *cobra.Command, l layout, s Settings, running bool) error {
	if noRestart, _ := cmd.Flags().GetBool("no-restart"); !running || noRestart {
		verb := "start"
		if running {
			verb = "restart"
		}
		a.progress("Run `cosigner-cli " + verb + "` to apply the change.")
		return nil
	}
	a.progress("Restarting Cosigner to apply the change…")
	return a.startService(cmd.Context(), a.docker(cmd, s), l, s, true)
}

func (a *App) confirm(prompt string) (bool, error) {
	answer, err := a.promptLine(prompt)
	if err != nil {
		return false, errors.New("confirmation required; pass --yes in non-interactive mode")
	}
	answer = strings.ToLower(answer)
	return answer == "y" || answer == "yes", nil
}

// callbackTarget resolves the URL or key folder. In a terminal it asks again
// after a typo and offers the host.docker.internal form of a localhost URL.
func (a *App) callbackTarget(args []string, urlFlag string) (folder, callbackURL string, err error) {
	missing := errors.New("callback target required: cosigner-cli callback add https://callback.example.com (or a key folder)")
	prompted := len(args) == 0
	target := ""
	if !prompted {
		target = args[0]
	}
	for {
		if prompted {
			if target, err = a.promptLine("Callback server URL, or its key folder on this machine: "); err != nil || target == "" {
				return "", "", missing
			}
		}
		folder, raw := "", target
		if info, statErr := os.Stat(target); statErr == nil && info.IsDir() {
			folder, raw = target, urlFlag
			if raw == "" {
				raw = callbackDevURL
			}
		} else if urlFlag != "" {
			return "", "", errors.New("--url is only used with a folder argument")
		}
		callbackURL, err = normalizeCallbackURL(raw)
		if err == nil {
			return folder, callbackURL, nil
		}
		var loopback *loopbackURLError
		if errors.As(err, &loopback) {
			ok, askErr := a.confirmYes("That address is the Cosigner container itself. Use " + loopback.suggested + " instead? [Y/n]: ")
			if askErr == nil && ok {
				return folder, loopback.suggested, nil
			}
		}
		// Only a typed answer can be corrected; a bad argument or --url fails as before.
		if !prompted || folder != "" {
			return "", "", err
		}
		a.warn(err.Error())
	}
}

func (a *App) confirmYes(prompt string) (bool, error) {
	answer, err := a.promptLine(prompt)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(answer)
	return answer == "" || answer == "y" || answer == "yes", nil
}

// promptLine reads one trimmed line from an interactive terminal.
func (a *App) promptLine(prompt string) (string, error) {
	file, ok := a.In.(*os.File)
	if !ok || !isTerminal(file) {
		return "", errors.New("not an interactive terminal")
	}
	fmt.Fprint(a.Out, prompt)
	answer, err := bufio.NewReader(file).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(answer), nil
}

// callbackKey loads the Cosigner's callback signing key, generating it on first use.
func (a *App) callbackKey(l layout) (*rsa.PrivateKey, error) {
	path := l.secret(callbackPrivateKey)
	if fileExists(path) {
		key, err := loadCallbackPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return key, nil
	}
	var key *rsa.PrivateKey
	err := a.step("Generating Cosigner callback key (RSA-4096)", func() (string, error) {
		var err error
		if key, err = rsa.GenerateKey(rand.Reader, callbackKeyBits); err != nil {
			return "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		}
		// The runtime's file secret provider reads hex-encoded PKCS#8 DER.
		encoded := []byte(hex.EncodeToString(der))
		clear(der)
		defer clear(encoded)
		return "Generated Cosigner callback key in secrets/" + callbackPrivateKey, atomicWrite(path, encoded, 0600)
	})
	return key, err
}

func loadCallbackPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	der, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, errors.New("callback private key must be hex-encoded PKCS#8 DER")
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("callback private key must be PKCS#8 DER: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != callbackKeyBits {
		return nil, errors.New("callback private key must be RSA-4096")
	}
	return key, nil
}

// serverPublicKey returns the callback server's public key as normalized PEM.
// A flag value fails fast; in a terminal it asks for a file path until one works.
func (a *App) serverPublicKey(path string) (key []byte, source string, err error) {
	if path != "" {
		var raw []byte
		source = path
		if path == "-" {
			source = "stdin"
			raw, err = io.ReadAll(io.LimitReader(a.In, callbackMaxInputBytes))
		} else {
			source = absPath(expandHome(path))
			raw, err = readLimited(source)
		}
		if err == nil {
			_, raw, err = parseCallbackPublicKey(raw)
		}
		if err != nil {
			return nil, "", fmt.Errorf("callback server public key: %w", err)
		}
		return raw, source, nil
	}
	file, ok := a.In.(*os.File)
	if !ok || !isTerminal(file) {
		return nil, "", errors.New("callback server public key is required in non-interactive mode; pass --server-public-key FILE")
	}
	reader := bufio.NewReader(io.LimitReader(file, callbackMaxInputBytes))
	for {
		fmt.Fprint(a.Out, "Path to the callback server's PUBLIC key file (.pem): ")
		line, err := reader.ReadString('\n')
		answer := strings.Trim(strings.TrimSpace(line), `"'`)
		if answer == "" {
			return nil, "", errors.New("callback server public key required; pass --server-public-key FILE")
		}
		var raw []byte
		if strings.HasPrefix(answer, "-----BEGIN") {
			source = "pasted text"
			raw, err = readPastedPEM(reader, line)
		} else {
			source = absPath(expandHome(answer))
			raw, err = readLimited(source)
		}
		if err == nil {
			_, raw, err = parseCallbackPublicKey(raw)
		}
		if err == nil {
			return raw, source, nil
		}
		a.warn(err.Error())
	}
}

// readPastedPEM collects a PEM block pasted at a prompt, starting with its first line.
func readPastedPEM(reader *bufio.Reader, first string) ([]byte, error) {
	var buf bytes.Buffer
	for line := first; ; {
		buf.WriteString(line)
		if strings.HasPrefix(strings.TrimSpace(line), "-----END ") {
			return buf.Bytes(), nil
		}
		var err error
		if line, err = reader.ReadString('\n'); err != nil {
			return nil, errors.New("pasted key has no -----END line")
		}
	}
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// keySummary shows the first and last lines of a PEM key, as they appear in
// the file, plus its fingerprint, so the operator can confirm the right key.
func keySummary(keyPEM []byte) string {
	lines := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")
	shown := lines
	if len(lines) > 4 {
		shown = []string{lines[0], lines[1], "…", lines[len(lines)-2], lines[len(lines)-1]}
	}
	fingerprint := ""
	if block, _ := pem.Decode(keyPEM); block != nil {
		sum := sha256.Sum256(block.Bytes)
		fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	return "    " + strings.Join(shown, "\n    ") + "\n    Fingerprint " + fingerprint + "\n\n"
}

func expandHome(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return path
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, callbackMaxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > callbackMaxInputBytes {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return raw, nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// normalizeCallbackURL applies the runtime's URL rules plus one the runtime
// cannot know: localhost resolves to the Cosigner container itself.
func normalizeCallbackURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("callback %q must be an absolute URL such as https://callback.example.com", raw)
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); host == "localhost" || ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		fixed := *u
		fixed.Host = "host.docker.internal"
		if port := u.Port(); port != "" {
			fixed.Host += ":" + port
		}
		suggested, err := normalizeCallbackURL(fixed.String())
		if err != nil {
			return "", err
		}
		return "", &loopbackURLError{raw: raw, suggested: suggested}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if host != "host.docker.internal" {
			return "", fmt.Errorf("callback %q must use https (http is allowed only for host.docker.internal)", raw)
		}
	default:
		return "", fmt.Errorf("callback %q must use https", raw)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = callbackApprovePath
	}
	return u.String(), nil
}

// loopbackURLError carries the host.docker.internal URL to offer instead.
type loopbackURLError struct{ raw, suggested string }

func (e *loopbackURLError) Error() string {
	return fmt.Sprintf("callback %q points inside the Cosigner container; use %s to reach this machine", e.raw, e.suggested)
}

// parseCallbackPublicKey accepts PKIX or PKCS#1 PEM and returns it re-encoded as PKIX PEM.
func parseCallbackPublicKey(raw []byte) (*rsa.PublicKey, []byte, error) {
	block, rest := pem.Decode(bytes.TrimSpace(raw))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, errors.New("must contain exactly one PEM public key")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return nil, nil, errors.New("this is a PRIVATE key; it must stay on the callback server. Use its PUBLIC key (-----BEGIN PUBLIC KEY-----)")
	default:
		return nil, nil, fmt.Errorf("unsupported PEM type %q; expected PUBLIC KEY", block.Type)
	}
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("must be an RSA key")
	}
	if key.N.BitLen() != callbackKeyBits {
		return nil, nil, fmt.Errorf("must be RSA-4096, got %d bits", key.N.BitLen())
	}
	normalized, _, err := publicKeyPEM(key)
	return key, normalized, err
}

func publicKeyPEM(key *rsa.PublicKey) ([]byte, string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func validateCertificates(raw []byte) error {
	found := false
	for rest := bytes.TrimSpace(raw); len(rest) > 0; rest = bytes.TrimSpace(rest) {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("must contain only PEM CERTIFICATE blocks")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return errors.New("no certificate found")
	}
	return nil
}

type callbackBlock struct {
	URL, PrivateKeyPath, ServerKeyPath, CAPath string
}

type callbackFileConfig struct {
	Approval struct {
		RequireCallback bool `yaml:"require_callback"`
	} `yaml:"approval"`
	Callback *struct {
		URL        string `yaml:"url"`
		PrivateKey struct {
			Type   string `yaml:"type"`
			Config struct {
				Path string `yaml:"path"`
			} `yaml:"config"`
		} `yaml:"private_key"`
		ResponsePublicKeyPath string `yaml:"response_public_key_path"`
		CACertPath            string `yaml:"ca_cert_path"`
	} `yaml:"callback"`
}

func parseCallbackConfig(raw []byte) (callbackFileConfig, error) {
	var cfg callbackFileConfig
	err := yaml.Unmarshal(raw, &cfg)
	return cfg, err
}

// setCallbackConfig edits config.yaml in place, keeping unrelated keys, their
// order and comments. A nil block removes the callback.
func setCallbackConfig(raw []byte, block *callbackBlock) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config.yaml must be a YAML mapping")
	}
	root := doc.Content[0]
	approval := mappingValue(root, "approval")
	if approval == nil || approval.Kind != yaml.MappingNode {
		approval = &yaml.Node{Kind: yaml.MappingNode}
		setMappingValue(root, "approval", approval)
	}
	if block == nil {
		setMappingValue(approval, "require_callback", boolNode(false))
		deleteMappingValue(root, "callback")
	} else {
		setMappingValue(approval, "require_callback", boolNode(true))
		cb := mappingValue(root, "callback")
		if cb == nil || cb.Kind != yaml.MappingNode {
			cb = &yaml.Node{Kind: yaml.MappingNode}
			setMappingValue(cb, "timeout", stringNode("30s"))
			setMappingValue(cb, "retry_count", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"})
			setMappingValue(root, "callback", cb)
		}
		setMappingValue(cb, "url", stringNode(block.URL))
		privateKey := &yaml.Node{Kind: yaml.MappingNode}
		setMappingValue(privateKey, "type", stringNode("file"))
		keyConfig := &yaml.Node{Kind: yaml.MappingNode}
		setMappingValue(keyConfig, "path", stringNode(block.PrivateKeyPath))
		setMappingValue(privateKey, "config", keyConfig)
		setMappingValue(cb, "private_key", privateKey)
		setMappingValue(cb, "response_public_key_path", stringNode(block.ServerKeyPath))
		if block.CAPath != "" {
			setMappingValue(cb, "ca_cert_path", stringNode(block.CAPath))
		} else {
			deleteMappingValue(cb, "ca_cert_path")
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func stringNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}
func boolNode(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(v)}
}
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
func setMappingValue(m *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = value
			return
		}
	}
	m.Content = append(m.Content, stringNode(key), value)
}
func deleteMappingValue(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// hostPath maps a path as the container sees it to the instance file backing it.
// Relative paths resolve against the config directory, which is the state mount.
func hostPath(l layout, containerPath string) (string, error) {
	p := filepath.Clean(containerPath)
	var base, rel string
	switch {
	case strings.HasPrefix(p, containerSecrets):
		base, rel = filepath.Join(l.home, "secrets"), strings.TrimPrefix(p, containerSecrets)
	case strings.HasPrefix(p, containerState):
		base, rel = l.state, strings.TrimPrefix(p, containerState)
	case !filepath.IsAbs(p):
		base, rel = l.state, p
	default:
		return "", fmt.Errorf("%s is not mounted into the Cosigner container; put it in secrets/ and reference it as %s<name>", containerPath, containerSecrets)
	}
	if rel == "" || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%s escapes the instance directory", containerPath)
	}
	return filepath.Join(base, rel), nil
}

// validateCallbackFiles catches callback mistakes on the host, before the
// password prompt and container start, instead of in the runtime logs.
func validateCallbackFiles(l layout, raw []byte) error {
	cfg, err := parseCallbackConfig(raw)
	if err != nil {
		return err
	}
	cb := cfg.Callback
	if cb == nil {
		return nil
	}
	if _, err := normalizeCallbackURL(cb.URL); err != nil {
		return fmt.Errorf("config.yaml callback.url: %w", err)
	}
	if cb.PrivateKey.Type == "file" && cb.PrivateKey.Config.Path != "" {
		path, err := hostPath(l, cb.PrivateKey.Config.Path)
		if err != nil {
			return fmt.Errorf("config.yaml callback.private_key: %w", err)
		}
		if _, err := loadCallbackPrivateKey(path); err != nil {
			return fmt.Errorf("config.yaml callback.private_key (%s): %w", path, err)
		}
	}
	path, err := hostPath(l, cb.ResponsePublicKeyPath)
	if err != nil {
		return fmt.Errorf("config.yaml callback.response_public_key_path: %w", err)
	}
	keyPEM, err := readLimited(path)
	if err == nil {
		_, _, err = parseCallbackPublicKey(keyPEM)
	}
	if err != nil {
		return fmt.Errorf("config.yaml callback.response_public_key_path (%s): %w", path, err)
	}
	if cb.CACertPath != "" {
		path, err := hostPath(l, cb.CACertPath)
		if err != nil {
			return fmt.Errorf("config.yaml callback.ca_cert_path: %w", err)
		}
		caPEM, err := readLimited(path)
		if err == nil {
			err = validateCertificates(caPEM)
		}
		if err != nil {
			return fmt.Errorf("config.yaml callback.ca_cert_path (%s): %w", path, err)
		}
	}
	return nil
}

// callbackInfo describes the callback for `info`; it never fails the command.
func callbackInfo(l layout) string {
	raw, err := os.ReadFile(l.config)
	if err != nil {
		return ""
	}
	cfg, err := parseCallbackConfig(raw)
	if err != nil || cfg.Callback == nil {
		return "callback: disabled\n"
	}
	out := "callback_url: " + cfg.Callback.URL + "\n"
	if cfg.Callback.PrivateKey.Type != "file" {
		return out
	}
	path, err := hostPath(l, cfg.Callback.PrivateKey.Config.Path)
	if err != nil {
		return out
	}
	key, err := loadCallbackPrivateKey(path)
	if err != nil {
		return out
	}
	publicPEM, fingerprint, err := publicKeyPEM(&key.PublicKey)
	if err != nil {
		return out
	}
	return out + "callback_fingerprint: " + fingerprint + "\ncallback_public_key: |\n  " + strings.ReplaceAll(strings.TrimSpace(string(publicPEM)), "\n", "\n  ") + "\n"
}
