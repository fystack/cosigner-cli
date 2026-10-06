package app

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// cosignOK fails before any prompt or pull so operators don't enter secrets
// or wait for a download only to be stopped at verification.
func (a *App) cosignOK(ctx context.Context) error {
	if a.Getenv("COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION") == "1" {
		return nil
	}
	err := a.step("Checking Cosign", func() (string, error) {
		raw, err := a.Runner.Run(ctx, "cosign", []string{"version"}, nil, nil)
		if v := cosignVersion.FindSubmatch(raw); v != nil {
			return "Cosign " + string(v[1]) + " found", err
		}
		return "Cosign found", err
	})
	if err != nil {
		osRelease, _ := os.ReadFile("/etc/os-release")
		return fmt.Errorf("cosign is required to verify Cosigner images. Install it, then run the command again:\n\n%s\n", cosignInstallHint(runtime.GOOS, runtime.GOARCH, string(osRelease)))
	}
	return nil
}

var cosignVersion = regexp.MustCompile(`(?m)^GitVersion:\s*(\S+)`)

func cosignInstallHint(goos, goarch, osRelease string) string {
	const docs = "  # other options: https://docs.sigstore.dev/cosign/system_config/installation/"
	if goos == "darwin" {
		return "  brew install cosign\n" + docs
	}
	distro := map[string]bool{}
	for _, line := range strings.Split(osRelease, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && (key == "ID" || key == "ID_LIKE") {
			for _, id := range strings.Fields(strings.Trim(value, `"'`)) {
				distro[id] = true
			}
		}
	}
	switch {
	case distro["alpine"]:
		return "  sudo apk add cosign\n" + docs
	case distro["arch"]:
		return "  sudo pacman -S cosign\n" + docs
	}
	asset := "cosign-linux-" + goarch
	return "  curl -fsSLO https://github.com/sigstore/cosign/releases/latest/download/" + asset + "\n" +
		"  sudo install -m 0755 " + asset + " /usr/local/bin/cosign && rm " + asset + "\n" + docs
}
