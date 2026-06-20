package cmd

import (
	"fmt"

	"github.com/crawlsnap/crawlsnap-go/models"
	"github.com/spf13/cobra"
)

// newSubdoSnapCmd builds the `subdosnap scan` command for subdomain enumeration.
// By default it returns the first page; --all follows the cursor and aggregates
// every subdomain.
func newSubdoSnapCmd(f *Factory) *cobra.Command {
	var all bool

	scan := &cobra.Command{
		Use:   "scan <domain>",
		Short: "Enumerate subdomains for a domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			p, err := f.Printer()
			if err != nil {
				return err
			}
			client, err := f.Client()
			if err != nil {
				return err
			}
			ctx := c.Context()
			domain := args[0]

			if !all {
				stop := p.Spinner(fmt.Sprintf("Scanning subdomains of %s…", domain))
				data, err := client.SubdoSnap.Scan(ctx, domain)
				stop()
				if err != nil {
					return err
				}
				return p.Result(data)
			}

			// --all: stream every page via the SDK iterator into one aggregate.
			stop := p.Spinner(fmt.Sprintf("Scanning all subdomains of %s…", domain))
			subs := make([]map[string]any, 0, 128)
			var iterErr error
			for sub, err := range client.SubdoSnap.ScanIter(ctx, domain) {
				if err != nil {
					iterErr = err
					break
				}
				subs = append(subs, sub)
			}
			stop()
			if iterErr != nil {
				return iterErr
			}
			p.Info("Found %d subdomains for %s", len(subs), domain)
			return p.Result(models.SubdoSnapScanData{
				SearchType: "subdomain",
				Subdomains: subs,
			})
		},
	}
	scan.Flags().BoolVar(&all, "all", false, "follow the cursor and return every subdomain")

	cmd := &cobra.Command{
		Use:     "subdosnap",
		Aliases: []string{"sub"},
		Short:   "Subdomain enumeration",
	}
	cmd.AddCommand(scan)
	return cmd
}
