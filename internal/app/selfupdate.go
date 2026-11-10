package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

const (
	cliRepository = "fystack/cosigner-cli"
	cliBinaryMax  = 128 << 20
	cliBundleMax  = 1 << 20
	oidcIssuer    = "https://token.actions.githubusercontent.com"
)

// cliReport is the JSON shape of `self-update --json`.
type cliReport struct {
	Component       string `json:"component"`
	Installed       string `json:"installed"`
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	Path            string `json:"path,omitempty"`
	Updated         bool   `json:"updated"`
}

func (a *App) selfUpdateCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "self-update",
		Short: "Update cosigner-cli itself to a newer signed release (not the runtime)",
		Long: `Replace this cosigner-cli binary with a newer release from github.com/` + cliRepository + `.

The new binary is verified with cosign against this repository's release workflow
for that tag (the same check install.sh makes) and must report the expected version
before it replaces the current one. The running Cosigner runtime is not touched; run
"cosigner-cli update" to update the runtime.`,
		Example: `  cosigner-cli self-update
  cosigner-cli self-update --check            # exit 10 when a newer CLI exists
  sudo cosigner-cli self-update               # when the binary is in a root-owned directory
  cosigner-cli self-update --version v1.4.0`,
		RunE: a.selfUpdate,
	}
	c.Flags().String("version", "", "Exact release version (default: newest stable release)")
	c.Flags().Bool("check", false, "Only report whether a newer CLI exists (exit 10 when it does)")
	c.Flags().Bool("json", false, "Print the result as JSON on stdout; progress goes to stderr")
	return c
}

func (a *App) selfUpdate(c *cobra.Command, _ []string) error {
	asJSON, _ := c.Flags().GetBool("json")
	emit, restore := a.jsonMode(asJSON)
	defer restore()
	report := cliReport{Component: "cli", Installed: a.Version}
	if !stableTag.MatchString(a.Version) {
		return withHint(fmt.Errorf("this cosigner-cli is a development build (%s); self-update only replaces release builds", a.Version), "install a release with install.sh: https://cosigner.fystack.io")
	}
	version, _ := c.Flags().GetString("version")
	if version == "" {
		a.progress("Checking for the newest cosigner-cli release…")
		latest, err := a.LatestCLI(c.Context())
		if err != nil {
			return fmt.Errorf("find the newest cosigner-cli release: %w", err)
		}
		version = latest
		report.Latest = vtag(latest)
		if !stableVersionAfter(version, a.Version) {
			a.progress("cosigner-cli is up to date (" + vtag(a.Version) + ").")
			return emit(report)
		}
	}
	if !stableTag.MatchString(version) || !stableVersionAfter(version, a.Version) {
		return errors.New("self-update requires a newer stable version (vX.Y.Z); to install another release, run install.sh --version")
	}
	tag := vtag(version)
	report.UpdateAvailable = true
	if check, _ := c.Flags().GetBool("check"); check {
		a.progress(fmt.Sprintf("cosigner-cli update available: %s → %s (run `cosigner-cli self-update`)", vtag(a.Version), tag))
		if err := emit(report); err != nil {
			return err
		}
		return &ExitError{Code: exitUpdateAvailable}
	}

	exe, err := a.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	report.Path = exe
	// Stage next to the binary so the final rename is atomic, and so a
	// read-only directory fails before anything is downloaded.
	staged, err := os.CreateTemp(filepath.Dir(exe), ".cosigner-cli-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return withHint(fmt.Errorf("cannot write to %s: %w", filepath.Dir(exe), err), "run `sudo cosigner-cli self-update`")
		}
		return err
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if err := a.cosignInstalled(c.Context()); err != nil {
		staged.Close()
		return err
	}

	asset := "cosigner-cli-" + runtime.GOOS + "-" + runtime.GOARCH
	base := "https://github.com/" + cliRepository + "/releases/download/" + tag + "/"
	var binary, bundle []byte
	err = a.step("Downloading cosigner-cli "+tag+" ("+asset+")", func() (string, error) {
		var err error
		if binary, err = a.Fetch(c.Context(), base+asset, cliBinaryMax); err != nil {
			return "", err
		}
		bundle, err = a.Fetch(c.Context(), base+asset+".sigstore.json", cliBundleMax)
		return "Downloaded cosigner-cli " + tag, err
	})
	if err == nil {
		_, err = staged.Write(binary)
	}
	if e := staged.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Chmod(stagedPath, 0755)
	}
	if err != nil {
		return fmt.Errorf("download cosigner-cli %s: %w", tag, err)
	}
	bundleFile, err := os.CreateTemp("", "cosigner-cli-bundle-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(bundleFile.Name())
	_, err = bundleFile.Write(bundle)
	if e := bundleFile.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}

	identity := "https://github.com/" + cliRepository + "/.github/workflows/release.yml@refs/tags/" + tag
	var raw []byte
	err = a.step("Verifying cosigner-cli signature with Cosign", func() (string, error) {
		var err error
		raw, err = a.Runner.Run(c.Context(), "cosign", []string{"verify-blob", stagedPath, "--bundle", bundleFile.Name(), "--certificate-identity", identity, "--certificate-oidc-issuer", oidcIssuer}, nil, nil)
		return "Signature verified: built by the " + cliRepository + " release workflow for " + tag, err
	})
	if err != nil {
		return fmt.Errorf("signature verification failed for %s %s; nothing was replaced: %w: %s", asset, tag, err, bytes.TrimSpace(raw))
	}
	out, err := a.Runner.Run(c.Context(), stagedPath, []string{"version"}, nil, nil)
	if want := []byte("cosigner-cli " + tag + " "); err != nil || !bytes.HasPrefix(out, want) {
		return fmt.Errorf("downloaded cosigner-cli does not report %s; nothing was replaced", tag)
	}
	if err := os.Rename(stagedPath, exe); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(exe)); err != nil {
		return err
	}
	report.Updated = true
	a.success(fmt.Sprintf("cosigner-cli updated: %s → %s (%s)", vtag(a.Version), tag, exe))
	a.progress("The Cosigner runtime was not changed. Run `cosigner-cli update --check` to see whether it has an update.")
	return emit(report)
}

// githubLatestRelease asks GitHub for the newest published release, which
// excludes drafts and pre-releases.
func githubLatestRelease(ctx context.Context) (string, error) {
	raw, err := httpsFetch(ctx, "https://api.github.com/repos/"+cliRepository+"/releases/latest", 1<<20)
	if err != nil {
		return "", err
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(raw, &release); err != nil {
		return "", err
	}
	if !stableTag.MatchString(release.TagName) {
		return "", fmt.Errorf("newest release tag %q is not a stable version", release.TagName)
	}
	return release.TagName, nil
}

// httpsFetch downloads url over HTTPS only, following redirects only to HTTPS.
func httpsFetch(ctx context.Context, url string, max int64) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("refusing a redirect away from HTTPS")
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("only HTTPS downloads are allowed")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", url, max)
	}
	return raw, nil
}
