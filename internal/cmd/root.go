package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"github.com/crawlsnap/crawlsnap-cli/internal/build"
	"github.com/crawlsnap/crawlsnap-cli/internal/output"
)

// Main is the process entry point. It wires the command tree, runs it through
// fang (styled help/errors/manpages), and exits with a meaningful code.
func Main() {
	root := newRootCmd()
	version, commit, _ := build.Resolve()

	err := fang.Execute(
		context.Background(),
		root,
		fang.WithVersion(version),
		fang.WithCommit(commit),
	)
	os.Exit(exitFromError(err))
}

// newRootCmd builds the root command and attaches the global flags and the full
// subcommand tree.
func newRootCmd() *cobra.Command {
	f := &Factory{}

	cmd := &cobra.Command{
		Use:   "crawlsnap",
		Short: "CrawlSnap — data intelligence from the command line",
		Long: "crawlsnap is the official CLI for the CrawlSnap data intelligence platform.\n\n" +
			"Query threat-intelligence and enrichment APIs (VectorSnap, PulseSnap, SubdoSnap)\n" +
			"directly from your terminal, with human, JSON, and YAML output.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Validate global formatting flags once, before any subcommand runs.
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			_, err := output.ParseFormat(f.OutputFlag)
			return err
		},
		// Bare `crawlsnap` shows the banner; anything else here is an unknown
		// command (a known subcommand would have been dispatched instead).
		RunE: func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				printBanner(c.OutOrStdout(), bannerColorEnabled(f))
				return nil
			}
			return fmt.Errorf("unknown command %q for %q\nRun 'crawlsnap --help' for usage", args[0], c.CommandPath())
		},
	}

	pf := cmd.PersistentFlags()
	pf.StringVar(&f.ProfileFlag, "profile", "", "configuration profile to use")
	pf.StringVar(&f.APIKeyFlag, "api-key", "", "API key (overrides profile/env)")
	pf.StringVar(&f.BaseURLFlag, "base-url", "", "API base URL override")
	pf.StringVarP(&f.OutputFlag, "output", "o", "human", "output format: human, json, yaml")
	pf.StringVarP(&f.QueryFlag, "query", "q", "", "jq expression to filter the result")
	pf.BoolVar(&f.NoColor, "no-color", false, "disable colored output")
	pf.BoolVar(&f.Quiet, "quiet", false, "suppress spinner and status messages")
	pf.BoolVar(&f.Full, "full", false, "show the complete response instead of a summary card")
	pf.DurationVar(&f.Timeout, "timeout", 30*time.Second, "per-request timeout")

	cmd.AddCommand(
		newAuthCmd(f),
		newVectorSnapCmd(f),
		newPulseSnapCmd(f),
		newSubdoSnapCmd(f),
		newLookupCmd(f),
		newVersionCmd(),
	)
	return cmd
}
