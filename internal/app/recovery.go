package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const recoveryMagic = "COSREC02"
const maxRecoveryBytes = 256 << 20

type recoveryFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}
type recoveryBundle struct {
	Version   int            `json:"version"`
	CreatedAt time.Time      `json:"created_at"`
	Image     string         `json:"image"`
	Files     []recoveryFile `json:"files"`
}

func (a *App) recoveryPassword(confirm bool) ([]byte, error) {
	copy := *a
	copy.password = nil
	defer func() { clear(copy.password) }()
	copy.Getenv = func(key string) string {
		if key == passwordEnv {
			return a.Getenv("COSIGNER_RECOVERY_PASSWORD")
		}
		if key == "COSIGNER_PASSWORD_FD" {
			return a.Getenv("COSIGNER_RECOVERY_PASSWORD_FD")
		}
		return ""
	}
	a.progress("Enter the separate recovery password (retain it outside this host).")
	password, err := copy.readPassword(confirm)
	if errors.Is(err, errNoPasswordInput) {
		return nil, withHint(errors.New("COSIGNER_RECOVERY_PASSWORD is required in non-interactive mode"), "pass it on an open descriptor, for example COSIGNER_RECOVERY_PASSWORD_FD=3 3<recovery-password-file, or set COSIGNER_RECOVERY_PASSWORD")
	}
	return password, err
}

func sealRecovery(password, plaintext []byte) ([]byte, error) {
	header := make([]byte, len(recoveryMagic)+16+12)
	copy(header, recoveryMagic)
	if _, err := rand.Read(header[len(recoveryMagic):]); err != nil {
		return nil, err
	}
	key := derivePasswordKey(password, header[8:24], 3, 64*1024, 4)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, header[24:36], plaintext, header), nil
}
func openRecovery(password, blob []byte) ([]byte, error) {
	if len(blob) < 52 || len(blob) > maxRecoveryBytes || string(blob[:8]) != recoveryMagic {
		return nil, errors.New("invalid recovery archive")
	}
	key := derivePasswordKey(password, blob[8:24], 3, 64*1024, 4)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, blob[24:36], blob[36:], blob[:36])
	if err != nil {
		return nil, errors.New("recovery password is incorrect or archive is damaged")
	}
	return plain, nil
}

// legacyComposePath is the compose file that older archives carried. It is
// accepted so those archives still restore, but never installed: the compose
// file decides what runs on the host, so restore regenerates it from the
// template of the running CLI instead of trusting the archive.
const legacyComposePath = "docker-compose.yaml"

func allowedRecoveryPath(path string) bool {
	if !filepath.IsLocal(path) || filepath.ToSlash(filepath.Clean(path)) != path || strings.Contains(path, "\\") {
		return false
	}
	switch path {
	case "config.yaml", "cosigner-cli.yaml", legacyComposePath:
		return true
	}
	return strings.HasPrefix(path, "state/") || strings.HasPrefix(path, "secrets/")
}

// snapshotInstallation requires both the operator lock and the database lock.
// The latter is shared with the runtime's SQLite backend, including direct runs.
// It archives data only; the compose file is CLI output and is regenerated on restore.
func snapshotInstallation(l layout, s Settings) (recoveryBundle, error) {
	bundle := recoveryBundle{Version: 2, CreatedAt: time.Now().UTC(), Image: s.Image}
	var total int64
	for _, root := range []string{"config.yaml", "cosigner-cli.yaml", "state", "secrets"} {
		err := filepath.WalkDir(filepath.Join(l.home, root), func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(l.home, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("recovery refuses symlink %s", rel)
			}
			if d.IsDir() {
				return nil
			}
			if rel == "state/data/cosigner.db.lock" {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("recovery refuses non-regular file %s", rel)
			}
			total += info.Size()
			if total > maxRecoveryBytes/2 {
				return errors.New("installation exceeds recovery archive size limit")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(raw)
			bundle.Files = append(bundle.Files, recoveryFile{rel, hex.EncodeToString(sum[:]), raw})
			return nil
		})
		if err != nil {
			clearBundle(&bundle)
			return recoveryBundle{}, err
		}
	}
	return bundle, nil
}
func clearBundle(b *recoveryBundle) {
	for i := range b.Files {
		clear(b.Files[i].Data)
	}
}

func (a *App) writeRecovery(l layout, s Settings, path string, password []byte) error {
	unlock, err := lockFile(filepath.Join(l.state, "data", "cosigner.db.lock"))
	if err != nil {
		return fmt.Errorf("stop the runtime before backup: %w", err)
	}
	defer unlock()
	bundle, err := snapshotInstallation(l, s)
	if err != nil {
		return err
	}
	defer clearBundle(&bundle)
	plain, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	defer clear(plain)
	blob, err := sealRecovery(password, plain)
	if err != nil {
		return err
	}
	// Authenticate and parse the complete archive before acknowledging its write.
	check, err := openRecovery(password, blob)
	if err != nil {
		return err
	}
	defer clear(check)
	if !bytes.Equal(check, plain) {
		return errors.New("recovery archive verification failed")
	}
	return atomicWrite(path, blob, 0600)
}
func (a *App) backupCommand() *cobra.Command {
	c := &cobra.Command{Use: "backup", Short: "Create an encrypted backup (service must be stopped)", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		running, err := a.alreadyRunning(c.Context(), a.docker(c, s), l, s)
		if err != nil {
			return err
		}
		if running {
			return errors.New("stop the runtime before backup")
		}
		path, _ := c.Flags().GetString("out")
		if path == "" {
			path = a.defaultArchive(l, "backup-"+vtag(s.RuntimeVersion))
		}
		if path, err = archiveDestination(l, path); err != nil {
			return err
		}
		password, err := a.recoveryPassword(true)
		if err != nil {
			return err
		}
		defer clear(password)
		if err := a.writeRecovery(l, s, path, password); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "Verified encrypted recovery archive: %s\nKeep the recovery password and storage unlock credentials separately.\n", path)
		a.warnIfOnHost(l, path)
		return nil
	}}
	c.Flags().String("out", "", "Output archive (default: <home>/backups/backup-<version>-<time>.enc, or COSIGNER_BACKUP_DIR)")
	return c
}

// backupDir is the one folder inside an instance that may hold recovery
// archives. Snapshots only read config, settings, state/ and secrets/, so
// archives here are never captured into later archives.
const backupDir = "backups"

// defaultArchive names a new archive in COSIGNER_BACKUP_DIR or <home>/backups/.
// The UTC timestamp keeps names unique, since archives are never overwritten.
func (a *App) defaultArchive(l layout, name string) string {
	dir := a.Getenv("COSIGNER_BACKUP_DIR")
	if dir == "" {
		dir = filepath.Join(l.home, backupDir)
	}
	return filepath.Join(dir, name+"-"+time.Now().UTC().Format("20060102T150405Z")+".enc")
}

// archiveDestination resolves where an archive may be written: outside the
// instance, or inside its backups/ folder. Symlinks are resolved first, so a
// backups/ link into state/ is refused like state/ itself.
func archiveDestination(l layout, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := resolveExisting(abs)
	if err != nil {
		return "", err
	}
	home, err := resolveExisting(l.home)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(home, resolved)
	if err != nil {
		return "", err
	}
	if !filepath.IsLocal(rel) {
		return resolved, nil
	}
	if first, rest, _ := strings.Cut(filepath.ToSlash(rel), "/"); first == backupDir && rest != "" {
		return resolved, nil
	}
	return "", withHint(fmt.Errorf("%s is inside the instance directory; recovery archives go outside it or in its %s/ folder", resolved, backupDir), "leave out the path to use %s", filepath.Join(l.home, backupDir))
}

// resolveExisting evaluates symlinks in the longest existing prefix of path.
func resolveExisting(path string) (string, error) {
	rest := ""
	for p := path; ; {
		real, err := filepath.EvalSymlinks(p)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path, nil
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// warnIfOnHost reminds operators that an archive inside the instance shares
// its disk: it undoes a bad update, but does not survive losing the host.
func (a *App) warnIfOnHost(l layout, path string) {
	if rel, err := filepath.Rel(l.home, path); err == nil && filepath.IsLocal(rel) {
		a.warn("This archive is on the same host as the instance. Copy it off-host; it does not survive losing this disk.")
	}
}
func (a *App) restoreCommand() *cobra.Command {
	c := &cobra.Command{Use: "restore", Short: "Restore an encrypted backup into an empty directory", RunE: func(c *cobra.Command, _ []string) error {
		home, err := a.home(c)
		if err != nil {
			return err
		}
		entries, err := os.ReadDir(home)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			// backups/ may hold the very archive being restored.
			if entry.Name() != ".cosigner-cli.lock" && !(entry.Name() == backupDir && entry.IsDir()) {
				return errors.New("restore requires an empty instance directory; existing state is never overwritten")
			}
		}
		// The archive names the image that start will run, so its signature is
		// checked before the restored settings are published. Fail before any prompt.
		if err := a.cosignOK(c.Context()); err != nil {
			return err
		}
		input, _ := c.Flags().GetString("in")
		f, err := os.Open(input)
		if err != nil {
			return err
		}
		defer f.Close()
		blob, err := io.ReadAll(io.LimitReader(f, maxRecoveryBytes+1))
		if err != nil {
			return err
		}
		password, err := a.recoveryPassword(false)
		if err != nil {
			return err
		}
		defer clear(password)
		plain, err := openRecovery(password, blob)
		if err != nil {
			return err
		}
		defer clear(plain)
		var bundle recoveryBundle
		if err := json.Unmarshal(plain, &bundle); err != nil {
			return err
		}
		defer clearBundle(&bundle)
		if err := validateBundle(bundle); err != nil {
			return err
		}
		stage, err := os.MkdirTemp(home, ".restore-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		for _, file := range bundle.Files {
			if file.Path == legacyComposePath {
				continue
			}
			if err := atomicWrite(filepath.Join(stage, filepath.FromSlash(file.Path)), file.Data, 0600); err != nil {
				return err
			}
		}
		compose, err := templates.ReadFile("docker-compose.yaml")
		if err != nil {
			return err
		}
		if err := atomicWrite(a.layout(stage).compose(), compose, 0600); err != nil {
			return err
		}
		s, err := loadSettings(stage)
		if err != nil {
			return err
		}
		if s.Image != bundle.Image {
			return errors.New("archive image identity mismatch")
		}
		if err := validatePaired(a.layout(stage), s); err != nil {
			return err
		}
		if err := a.verifyImage(c.Context(), s.Image); err != nil {
			return err
		}
		s.ProjectName = projectName(home)
		// The Docker command is host configuration, not recovery data: take it
		// from this host, never from the archive.
		s.Docker = "docker"
		if docker, _ := c.Flags().GetString("docker"); docker != "" {
			s.Docker = docker
		}
		if err := saveSettings(stage, s); err != nil {
			return err
		}
		// Publish the settings last. A crash leaves an incomplete, non-startable
		// directory and never damages an existing installation.
		for _, name := range []string{"state", "secrets", "config.yaml", "docker-compose.yaml", "cosigner-cli.yaml"} {
			if err := os.Rename(filepath.Join(stage, name), filepath.Join(home, name)); err != nil {
				return err
			}
		}
		if err := syncDirectory(home); err != nil {
			return err
		}
		a.progress("Installation restored offline. Fence the old host, verify identity, then run start and a test signing operation.")
		return nil
	}}
	c.Flags().String("in", "", "Encrypted recovery archive")
	_ = c.MarkFlagRequired("in")
	return c
}
func validateBundle(b recoveryBundle) error {
	if b.Version != 2 {
		return errors.New("unsupported recovery version")
	}
	if err := validatePinnedImage(b.Image); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, f := range b.Files {
		if !allowedRecoveryPath(f.Path) || seen[f.Path] || f.Path == "state/data/cosigner.db.lock" {
			return errors.New("invalid or duplicate archive path")
		}
		seen[f.Path] = true
		sum := sha256.Sum256(f.Data)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("archive checksum mismatch: %s", f.Path)
		}
	}
	for _, path := range []string{"config.yaml", "cosigner-cli.yaml", "state/cosigner.key", "state/cosigner.pub", "state/pairing.yaml", "state/data/cosigner.db"} {
		if !seen[path] {
			return fmt.Errorf("archive is missing %s", path)
		}
	}
	return nil
}
