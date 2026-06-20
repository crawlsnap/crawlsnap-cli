package cmd

import (
	"context"

	crawlsnap "github.com/crawlsnap/crawlsnap-go"
	"github.com/spf13/cobra"
)

// newVectorSnapCmd builds the `vectorsnap` command group: IoC reputation
// enrichment for url, hash, ip, and domain indicators.
func newVectorSnapCmd(f *Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vectorsnap",
		Aliases: []string{"vs"},
		Short:   "IoC reputation enrichment (url, hash, ip, domain)",
	}
	cmd.AddCommand(
		newIndicatorCmd(f, "ip", "Reputation for an IP address", "VectorSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.VectorSnap.IP(ctx, q) }),
		newIndicatorCmd(f, "domain", "Reputation for a domain", "VectorSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) {
				return c.VectorSnap.Domain(ctx, q)
			}),
		newIndicatorCmd(f, "url", "Reputation for a URL", "VectorSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.VectorSnap.URL(ctx, q) }),
		newIndicatorCmd(f, "hash", "Reputation for a file hash", "VectorSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) {
				return c.VectorSnap.Hash(ctx, q)
			}),
	)
	return cmd
}

// newPulseSnapCmd builds the `pulsesnap` command group: threat-intelligence
// pulse enrichment for url, hash, ip, and domain indicators.
func newPulseSnapCmd(f *Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pulsesnap",
		Aliases: []string{"ps"},
		Short:   "Threat-intelligence pulse enrichment (url, hash, ip, domain)",
	}
	cmd.AddCommand(
		newIndicatorCmd(f, "ip", "Pulse enrichment for an IP address", "PulseSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.PulseSnap.IP(ctx, q) }),
		newIndicatorCmd(f, "domain", "Pulse enrichment for a domain", "PulseSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) {
				return c.PulseSnap.Domain(ctx, q)
			}),
		newIndicatorCmd(f, "url", "Pulse enrichment for a URL", "PulseSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.PulseSnap.URL(ctx, q) }),
		newIndicatorCmd(f, "hash", "Pulse enrichment for a file hash", "PulseSnap",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.PulseSnap.Hash(ctx, q) }),
	)
	return cmd
}
