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
	return copy.readPassword(confirm)
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

func allowedRecoveryPath(path string) bool {
	if !filepath.IsLocal(path) || filepath.ToSlash(filepath.Clean(path)) != path || strings.Contains(path, "\\") {
		return false
	}
	switch path {
	case "config.yaml", "cosigner-cli.yaml", "docker-compose.yaml":
		return true
	}
	return strings.HasPrefix(path, "state/") || strings.HasPrefix(path, "secrets/")
}

// snapshotInstallation requires both the operator lock and the database lock.
// The latter is shared with the runtime's SQLite backend, including direct runs.
func snapshotInstallation(l layout, s Settings) (recoveryBundle, error) {
	bundle := recoveryBundle{Version: 2, CreatedAt: time.Now().UTC(), Image: s.Image}
	var total int64
	for _, root := range []string{"config.yaml", "cosigner-cli.yaml", "docker-compose.yaml", "state", "secrets"} {
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
		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}
		if rel, err := filepath.Rel(l.home, path); err != nil || filepath.IsLocal(rel) {
			return errors.New("write recovery archives outside the instance directory")
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
		return nil
	}}
	c.Flags().String("out", "", "Output archive outside the instance directory")
	_ = c.MarkFlagRequired("out")
	return c
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
			if entry.Name() != ".cosigner-cli.lock" {
				return errors.New("restore requires an empty instance directory; existing state is never overwritten")
			}
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
			if err := atomicWrite(filepath.Join(stage, filepath.FromSlash(file.Path)), file.Data, 0600); err != nil {
				return err
			}
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
		s.ProjectName = projectName(home)
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
	for _, path := range []string{"config.yaml", "cosigner-cli.yaml", "docker-compose.yaml", "state/cosigner.key", "state/cosigner.pub", "state/pairing.yaml", "state/data/cosigner.db"} {
		if !seen[path] {
			return fmt.Errorf("archive is missing %s", path)
		}
	}
	return nil
}
