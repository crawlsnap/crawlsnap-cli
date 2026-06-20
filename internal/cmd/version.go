package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crawlsnap/crawlsnap-cli/internal/build"
)

// newVersionCmd prints detailed build information.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version, commit, and build date",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			version, commit, date := build.Resolve()
			fmt.Fprintf(c.OutOrStdout(), "crawlsnap %s\ncommit: %s\nbuilt:  %s\n", version, commit, date)
			return nil
		},
	}
}
