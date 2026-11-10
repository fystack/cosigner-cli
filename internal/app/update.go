package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var releaseVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
var imageDigest = regexp.MustCompile(`^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$`)
var imageRepository = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*[a-zA-Z0-9](:[0-9]+/[a-zA-Z0-9][a-zA-Z0-9._/-]*[a-zA-Z0-9])?$`)

type capabilities struct {
	OperatorAPI    int    `json:"operator_api"`
	UnlockProtocol int    `json:"unlock_protocol"`
	StorageSchema  int    `json:"storage_schema"`
	Version        string `json:"version"`
}

func validatePinnedImage(image string) error {
	if !imageDigest.MatchString(image) {
		return errors.New("installed image must be pinned by sha256 digest")
	}
	return nil
}

// updateRepository decides where the candidate release is pulled from. The
// installed digest names the repository (and therefore the registry) that this
// instance was provisioned against, so an override is required to move an
// installation between registries instead of it happening implicitly.
func updateRepository(installed, override string) (string, error) {
	repository := override
	if repository == "" {
		repository, _, _ = strings.Cut(installed, "@")
	}
	if !imageRepository.MatchString(repository) {
		return "", fmt.Errorf("%q is not an image repository; give --repository as a registry path without a tag or digest (for example ghcr.io/fystack/cosigner)", repository)
	}
	return repository, nil
}

func (a *App) verifyImage(ctx context.Context, image string) error {
	if err := validatePinnedImage(image); err != nil {
		return err
	}
	// This is intentionally an explicit local-development escape hatch rather
	// than a permanent removal of provenance verification. Digest pinning still
	// applies, but a digest alone does not establish who published the image.
	if a.Getenv("COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION") == "1" {
		a.warn("Image signature verification skipped (COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION=1)")
		return nil
	}
	// Verify before executing any code from the image. The identity expression
	// accepts only this repository's release workflow on a version tag.
	var raw []byte
	err := a.step("Verifying image signature with Cosign", func() (done string, err error) {
		raw, err = a.Runner.Run(ctx, "cosign", []string{"verify", "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "--certificate-identity-regexp", `^https://github\.com/fystack/cosigner/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`, image}, nil, nil)
		return "Image signature verified: signed by the fystack/cosigner GitHub release workflow", err
	})
	if err != nil {
		return fmt.Errorf("image signature verification failed (cosign is required): %w: %s", err, bytes.TrimSpace(raw))
	}
	return nil
}

func (a *App) inspectCapabilities(ctx context.Context, docker, image string) (capabilities, error) {
	if err := a.verifyImage(ctx, image); err != nil {
		return capabilities{}, err
	}
	return a.runtimeCapabilities(ctx, docker, image)
}

func (a *App) runtimeCapabilities(ctx context.Context, docker, image string) (capabilities, error) {
	var caps capabilities
	if err := validatePinnedImage(image); err != nil {
		return caps, err
	}
	raw, err := a.Runner.Run(ctx, docker, []string{"run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", image, "capabilities"}, nil, nil)
	if err != nil {
		return caps, fmt.Errorf("runtime capability check: %w", err)
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		return caps, fmt.Errorf("decode runtime contract: %w", err)
	}
	// A contract newer than this CLI speaks means the runtime was released for
	// a newer cosigner-cli, which is the one fix an operator can apply.
	if caps.OperatorAPI > 2 || caps.UnlockProtocol > 2 || caps.StorageSchema > 1 {
		return caps, withHint(fmt.Errorf("runtime %s needs a newer cosigner-cli (this is %s)", vtag(caps.Version), a.Version), "run `cosigner-cli self-update`, then run this command again")
	}
	if caps.OperatorAPI != 2 || caps.UnlockProtocol != 2 || caps.StorageSchema != 1 || !releaseVersion.MatchString(caps.Version) {
		return caps, withHint(errors.New("runtime is incompatible: require operator API 2, unlock 2, storage schema 1 and a release version"), "choose a runtime release made for cosigner-cli %s", a.Version)
	}
	return caps, nil
}

func (a *App) resolveImage(ctx context.Context, docker, image string) (string, capabilities, error) {
	var caps capabilities
	repository, requestedDigest, hasDigest := strings.Cut(image, "@")
	if hasDigest {
		if err := validatePinnedImage(image); err != nil {
			return "", caps, err
		}
	} else {
		i := strings.LastIndex(image, ":")
		if i < strings.LastIndex(image, "/") || i < 0 || !releaseVersion.MatchString(image[i+1:]) {
			return "", caps, errors.New("select an explicit release image tag (for example :1.2.3) or sha256 digest; latest and implicit tags are not supported")
		}
		repository = image[:i]
	}
	if err := a.Runner.Stream(ctx, docker, []string{"pull", image}, nil, nil, a.Out); err != nil {
		return "", caps, fmt.Errorf("pull release image: %w", err)
	}
	pinned := image
	if !hasDigest {
		raw, err := a.Runner.Run(ctx, docker, []string{"image", "inspect", "--format", "{{json .RepoDigests}}", image}, nil, nil)
		if err != nil {
			return "", caps, err
		}
		var digests []string
		if err := json.Unmarshal(raw, &digests); err != nil {
			return "", caps, err
		}
		pinned = ""
		for _, digest := range digests {
			repo, _, _ := strings.Cut(digest, "@")
			if strings.TrimPrefix(repo, "docker.io/") == strings.TrimPrefix(repository, "docker.io/") {
				pinned = digest
				break
			}
		}
		if pinned == "" {
			return "", caps, errors.New("registry image has no matching repository digest")
		}
	} else if requestedDigest == "" {
		return "", caps, errors.New("empty digest")
	}
	caps, err := a.inspectCapabilities(ctx, docker, pinned)
	if err != nil {
		return "", caps, err
	}
	if !hasDigest {
		tag := image[strings.LastIndex(image, ":")+1:]
		if strings.TrimPrefix(tag, "v") != strings.TrimPrefix(caps.Version, "v") {
			return "", caps, errors.New("image tag and runtime version disagree")
		}
	}
	return pinned, caps, nil
}

// releaseRef names one release of a component in reports.
type releaseRef struct {
	Version string `json:"version"`
	Image   string `json:"image,omitempty"`
}

// updateReport is the JSON shape of `update --json`.
type updateReport struct {
	Component       string      `json:"component"`
	Installed       releaseRef  `json:"installed"`
	Latest          string      `json:"latest,omitempty"`
	UpdateAvailable bool        `json:"update_available"`
	Candidate       *releaseRef `json:"candidate,omitempty"`
	Checkpoint      string      `json:"checkpoint,omitempty"`
	Updated         bool        `json:"updated"`
}

func (a *App) updateCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "update",
		Short: "Update the Cosigner runtime (container image); self-update updates this CLI",
		Long: `Update the Cosigner runtime: the signed container image that holds the key shares
and signs. This does not update cosigner-cli itself; run "cosigner-cli self-update" for that.

update verifies the new image's signature and runtime contract, asks for confirmation,
stops Cosigner, writes an encrypted recovery checkpoint and starts the new image.
Signing pauses until the new runtime is ready. There is no automatic rollback.

The checkpoint goes to <home>/backups/ unless --backup-out or COSIGNER_BACKUP_DIR names
another place. Copy it off this host afterwards.`,
		Example: `  cosigner-cli update --dry-run      # verify and preview the newest release
  cosigner-cli update                # checkpoint to <home>/backups/, then install it
  cosigner-cli update --check        # exit 10 when a newer runtime exists
  cosigner-cli update --version v1.2.3 --backup-out /secure/pre-update.enc --yes`,
		RunE: a.update,
	}
	c.Flags().String("version", "", "Exact runtime release version (default: newest signed release)")
	c.Flags().String("repository", "", "Image repository to pull the release from (default: the installed image's repository)")
	c.Flags().Bool("dry-run", false, "Download, verify and show the candidate without changing the installation")
	c.Flags().Bool("check", false, "Only report whether a newer runtime exists (exit 10 when it does); downloads nothing")
	c.Flags().String("backup-out", "", "Recovery checkpoint path (default: <home>/backups/pre-update-<from>-to-<to>-<time>.enc)")
	c.Flags().BoolP("yes", "y", false, "Do not ask for confirmation (required without a terminal)")
	c.Flags().Bool("json", false, "Print the result as JSON on stdout; progress goes to stderr")
	return c
}

func (a *App) update(c *cobra.Command, _ []string) error {
	l, s, err := a.installation(c)
	if err != nil {
		return err
	}
	asJSON, _ := c.Flags().GetBool("json")
	emit, restore := a.jsonMode(asJSON)
	defer restore()
	report := updateReport{Component: "runtime", Installed: releaseRef{Version: vtag(s.RuntimeVersion), Image: s.Image}}

	override, _ := c.Flags().GetString("repository")
	repository, err := updateRepository(s.Image, override)
	if err != nil {
		return err
	}
	check, _ := c.Flags().GetBool("check")
	dryRun, _ := c.Flags().GetBool("dry-run")
	if check && dryRun {
		return &UsageError{Err: errors.New("--check and --dry-run cannot be combined"), cmd: c}
	}
	version, _ := c.Flags().GetString("version")
	if version == "" {
		a.progress("Checking for the newest Cosigner runtime release…")
		if version, err = a.newestRelease(c.Context(), repository); err != nil {
			return err
		}
		report.Latest = vtag(version)
		if !stableVersionAfter(version, s.RuntimeVersion) {
			a.progress("Cosigner runtime is up to date (" + vtag(s.RuntimeVersion) + ").")
			return emit(report)
		}
	}
	if !releaseVersion.MatchString(version) {
		return errors.New("--version must be a release version")
	}
	if !stableVersionAfter(version, s.RuntimeVersion) {
		return errors.New("update requires a newer stable version; downgrades and mutable replacement tags are not supported")
	}
	report.UpdateAvailable = true
	if check {
		a.progress(fmt.Sprintf("Runtime update available: %s → %s (run `cosigner-cli update`)", vtag(s.RuntimeVersion), vtag(version)))
		if err := emit(report); err != nil {
			return err
		}
		return &ExitError{Code: exitUpdateAvailable}
	}

	// Settle the checkpoint location before downloading anything, so a bad
	// path fails fast and the plan shows where the archive will go.
	backupPath, _ := c.Flags().GetString("backup-out")
	if backupPath == "" {
		backupPath = a.defaultArchive(l, fmt.Sprintf("pre-update-%s-to-%s", vtag(s.RuntimeVersion), vtag(version)))
	}
	if backupPath, err = archiveDestination(l, backupPath); err != nil {
		return err
	}
	yes, _ := c.Flags().GetBool("yes")

	if err := a.cosignOK(c.Context()); err != nil {
		return err
	}
	docker := a.docker(c, s)
	image := repository + ":" + strings.TrimPrefix(version, "v")
	a.progress("Pulling Cosigner runtime image " + image + "…")
	pinned, caps, err := a.resolveImage(c.Context(), docker, image)
	if err != nil {
		return err
	}
	report.Candidate = &releaseRef{Version: vtag(caps.Version), Image: pinned}
	if !dryRun {
		report.Checkpoint = backupPath
	}
	a.printUpdatePlan(s, caps, pinned, backupPath, dryRun)
	if dryRun {
		return emit(report)
	}
	if pinned == s.Image {
		a.progress("This digest is already installed.")
		report.UpdateAvailable = false
		return emit(report)
	}
	if !yes {
		ok, err := a.confirm(fmt.Sprintf("Stop Cosigner, write the checkpoint and start %s? [y/N]: ", vtag(caps.Version)))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("update cancelled; nothing was changed")
		}
	}
	password, err := a.recoveryPassword(true)
	if err != nil {
		return err
	}
	defer clear(password)
	if _, err := a.compose(c.Context(), docker, l, s, "0", "unused", "stop", "cosigner"); err != nil {
		return err
	}
	a.progress("Writing recovery checkpoint " + backupPath + "…")
	if err := a.writeRecovery(l, s, backupPath, password); err != nil {
		return withHint(fmt.Errorf("runtime remains stopped; checkpoint failed: %w", err), "fix the checkpoint location (--backup-out) and run update again, or run `cosigner-cli start` to resume %s", vtag(s.RuntimeVersion))
	}
	a.success("Recovery checkpoint written")
	next := s
	next.PreviousImage = s.Image
	next.Image = pinned
	next.RuntimeVersion = caps.Version
	// Persist the candidate before launch so a failed launch is explicitly
	// recoverable with start. Never restore an older MPC database automatically.
	if err := saveSettings(l.home, next); err != nil {
		return err
	}
	if err := a.startService(c.Context(), docker, l, next, true); err != nil {
		return withHint(fmt.Errorf("runtime %s did not start; it stays selected and no signing state was rolled back: %w", vtag(caps.Version), err), "inspect `cosigner-cli logs`, fix the cause and run `cosigner-cli start`; the pre-update installation is in %s", backupPath)
	}
	report.Updated = true
	a.success(fmt.Sprintf("Cosigner runtime updated: %s → %s", vtag(s.RuntimeVersion), vtag(caps.Version)))
	a.printCheckpointNext(l, backupPath)
	return emit(report)
}

// printUpdatePlan shows what update is about to do before anything changes.
func (a *App) printUpdatePlan(s Settings, caps capabilities, pinned, checkpoint string, dryRun bool) {
	verified := "signature and runtime contract verified"
	if a.Getenv("COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION") == "1" {
		verified = "runtime contract verified; signature NOT checked"
	}
	if dryRun {
		checkpoint = "not written (dry run)"
	}
	fmt.Fprintf(a.Out, "\nCosigner runtime update\n")
	fmt.Fprintf(a.Out, "  Installed   %-9s %s\n", vtag(s.RuntimeVersion), s.Image)
	fmt.Fprintf(a.Out, "  Candidate   %-9s %s\n", vtag(caps.Version), pinned)
	fmt.Fprintf(a.Out, "              %s\n", verified)
	fmt.Fprintf(a.Out, "  Storage     schema %d, no migration\n", caps.StorageSchema)
	fmt.Fprintf(a.Out, "  Checkpoint  %s\n", checkpoint)
	fmt.Fprintf(a.Out, "  Downtime    signing pauses from stop until %s is ready\n\n", vtag(caps.Version))
}

// printCheckpointNext tells the operator where the checkpoint is and how to use it.
func (a *App) printCheckpointNext(l layout, path string) {
	fmt.Fprintf(a.Out, "Recovery checkpoint: %s\n", path)
	a.warnIfOnHost(l, path)
	fmt.Fprintf(a.Out, "To return to the pre-update installation, restore it into an empty directory:\n  cosigner-cli restore --home <empty-dir> --in %s\n", path)
}

func stableVersionAfter(candidate, current string) bool {
	a := strings.Split(strings.TrimPrefix(candidate, "v"), ".")
	b := strings.Split(strings.TrimPrefix(current, "v"), ".")
	if len(a) != 3 || len(b) != 3 {
		return false
	}
	comparison := 0
	for i := 0; i < 3; i++ {
		x, err := strconv.ParseUint(a[i], 10, 64)
		if err != nil {
			return false
		}
		y, err := strconv.ParseUint(b[i], 10, 64)
		if err != nil {
			return false
		}
		if comparison == 0 {
			if x > y {
				comparison = 1
			} else if x < y {
				comparison = -1
			}
		}
	}
	return comparison > 0
}
