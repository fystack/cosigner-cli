package app

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// componentVersion is one entry of `version --json`.
type componentVersion struct {
	Version         string `json:"version"`
	Commit          string `json:"commit,omitempty"`
	Image           string `json:"image,omitempty"`
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"update_available,omitempty"`
}

type versionReport struct {
	CLI     componentVersion  `json:"cli"`
	Runtime *componentVersion `json:"runtime,omitempty"`
}

func (a *App) versionCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "version",
		Short: "Print the cosigner-cli and Cosigner runtime versions",
		Long: `Print the version of cosigner-cli (this tool) and of the Cosigner runtime installed
in the instance directory. They are released separately: "update" updates the
runtime and "self-update" updates the CLI.`,
		Example: `  cosigner-cli version
  cosigner-cli version --check         # also look up the newest releases
  cosigner-cli version --check --json`,
		RunE: a.version,
	}
	c.Flags().Bool("check", false, "Also look up the newest CLI and runtime releases (needs network)")
	c.Flags().Bool("json", false, "Print JSON")
	return c
}

func (a *App) version(c *cobra.Command, _ []string) error {
	report := versionReport{CLI: componentVersion{Version: a.Version, Commit: a.Commit}}
	var s Settings
	var settingsErr error
	if home, err := a.home(c); err == nil && fileExists(filepath.Join(home, "cosigner-cli.yaml")) {
		if s, settingsErr = loadSettings(home); settingsErr == nil {
			report.Runtime = &componentVersion{Version: vtag(s.RuntimeVersion), Image: s.Image}
		}
	}
	if check, _ := c.Flags().GetBool("check"); check {
		ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
		defer cancel()
		runtimeLatest, cliLatest := a.latestReleases(ctx, s)
		if cliLatest != "" {
			report.CLI.Latest = vtag(cliLatest)
			report.CLI.UpdateAvailable = stableVersionAfter(cliLatest, a.Version)
		}
		if report.Runtime != nil && runtimeLatest != "" {
			report.Runtime.Latest = vtag(runtimeLatest)
			report.Runtime.UpdateAvailable = stableVersionAfter(runtimeLatest, s.RuntimeVersion)
		}
	}
	if asJSON, _ := c.Flags().GetBool("json"); asJSON {
		return writeJSON(a.Out, report)
	}
	// install.sh parses the first line; keep it "cosigner-cli <version> (commit <commit>)".
	fmt.Fprintf(a.Out, "cosigner-cli %s (commit %s)%s\n", a.Version, a.Commit, latestNote(report.CLI, "self-update"))
	switch {
	case report.Runtime != nil:
		fmt.Fprintf(a.Out, "runtime      %s (%s)%s\n", report.Runtime.Version, report.Runtime.Image, latestNote(*report.Runtime, "update"))
	case settingsErr != nil:
		fmt.Fprintf(a.Out, "runtime      unknown (%v)\n", settingsErr)
	default:
		fmt.Fprintln(a.Out, "runtime      not installed here (pass --home or set COSIGNER_HOME)")
	}
	return nil
}

func latestNote(v componentVersion, command string) string {
	switch {
	case v.UpdateAvailable:
		return fmt.Sprintf("  ← %s available: run `cosigner-cli %s`", v.Latest, command)
	case v.Latest != "":
		return "  (latest)"
	}
	return ""
}

// environmentHelp is the `cosigner-cli help environment` topic.
func environmentHelp() *cobra.Command {
	return &cobra.Command{
		Use:   "environment",
		Short: "Environment variables cosigner-cli reads",
		Long: `Environment variables cosigner-cli reads.

Instance
  COSIGNER_HOME                    Instance directory, like --home (default: current directory)
  COSIGNER_BACKUP_DIR              Folder for archives that update and backup write when no
                                   path is given (default: <home>/backups)

Storage passphrase (manual profile: up, start, restart)
  COSIGNER_PASSWORD_FD             Read the passphrase from this open descriptor (>= 3), for
                                   example COSIGNER_PASSWORD_FD=3 3<passphrase-file
  COSIGNER_PASSWORD                The passphrase itself. Prefer COSIGNER_PASSWORD_FD: values in
                                   the environment are visible to other processes of this user.

Recovery password (backup, restore, update)
  COSIGNER_RECOVERY_PASSWORD_FD    Read the recovery password from this open descriptor (>= 3)
  COSIGNER_RECOVERY_PASSWORD       The recovery password itself

Update checks
  COSIGNER_NO_UPDATE_CHECK=1       Do not look for CLI or runtime updates after start, restart,
                                   status and doctor

Development only
  COSIGNER_SKIP_IMAGE_SIGNATURE_VERIFICATION=1
                                   Run runtime images without checking their signature. Never
                                   set this on a host that holds real key shares. It does not
                                   apply to self-update.

Without a terminal, commands never prompt: they fail and say which variable or flag
(such as --yes) to set.`,
	}
}
