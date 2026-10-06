package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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
	if caps.OperatorAPI != 2 || caps.UnlockProtocol != 2 || caps.StorageSchema != 1 || !releaseVersion.MatchString(caps.Version) {
		return caps, errors.New("runtime is incompatible: require operator API 2, unlock 2, storage schema 1 and a release version")
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

func (a *App) updateCommand() *cobra.Command {
	c := &cobra.Command{Use: "update", Short: "Verify and install a release with an offline recovery checkpoint", RunE: func(c *cobra.Command, _ []string) error {
		l, s, err := a.installation(c)
		if err != nil {
			return err
		}
		override, _ := c.Flags().GetString("repository")
		repository, err := updateRepository(s.Image, override)
		if err != nil {
			return err
		}
		version, _ := c.Flags().GetString("version")
		if version == "" {
			a.progress("Checking for the newest Cosigner release…")
			if version, err = a.newestRelease(c.Context(), repository); err != nil {
				return err
			}
			if !stableVersionAfter(version, s.RuntimeVersion) {
				a.progress("Cosigner is up to date (v" + strings.TrimPrefix(s.RuntimeVersion, "v") + ").")
				return nil
			}
		}
		if !releaseVersion.MatchString(version) {
			return errors.New("--version must be a release version")
		}
		if !stableVersionAfter(version, s.RuntimeVersion) {
			return errors.New("update requires a newer stable version; downgrades and mutable replacement tags are not supported")
		}
		dryRun, _ := c.Flags().GetBool("dry-run")
		backupPath, _ := c.Flags().GetString("backup-out")
		if !dryRun && backupPath == "" {
			return errors.New("--backup-out outside the instance directory is required")
		}
		if err := a.cosignOK(c.Context()); err != nil {
			return err
		}
		docker := a.docker(c, s)
		a.progress("Pulling Cosigner image " + repository + ":" + strings.TrimPrefix(version, "v") + "…")
		pinned, caps, err := a.resolveImage(c.Context(), docker, repository+":"+strings.TrimPrefix(version, "v"))
		if err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "Installed: %s (%s)\nCandidate: %s (%s)\nStorage schema: 1 (no migration)\n", s.RuntimeVersion, s.Image, caps.Version, pinned)
		if dryRun {
			return nil
		}
		if pinned == s.Image {
			a.progress("This digest is already installed.")
			return nil
		}
		backupPath, err = filepath.Abs(backupPath)
		if err != nil {
			return err
		}
		if rel, err := filepath.Rel(l.home, backupPath); err != nil || filepath.IsLocal(rel) {
			return errors.New("recovery checkpoint must be outside the instance directory")
		}
		password, err := a.recoveryPassword(true)
		if err != nil {
			return err
		}
		defer clear(password)
		if _, err := a.compose(c.Context(), docker, l, s, "0", "unused", "stop", "cosigner"); err != nil {
			return err
		}
		if err := a.writeRecovery(l, s, backupPath, password); err != nil {
			return fmt.Errorf("runtime remains stopped; checkpoint failed: %w", err)
		}
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
			return fmt.Errorf("candidate remains selected; no signing-state rollback was performed; inspect logs and recover explicitly: %w", err)
		}
		return nil
	}}
	c.Flags().String("version", "", "Exact release version (default: newest signed release)")
	c.Flags().String("repository", "", "Image repository to pull the release from (default: the installed image's repository)")
	c.Flags().Bool("dry-run", false, "Download, verify and show the candidate without changing the installation")
	c.Flags().String("backup-out", "", "Encrypted pre-update recovery checkpoint outside the instance")
	return c
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
