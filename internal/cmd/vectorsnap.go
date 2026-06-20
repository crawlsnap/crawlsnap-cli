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
		newIndicatorCmd(f, "ip", "Reputation for an IP address", "VectorSnap", "vectorsnap.ip",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.VectorSnap.IP(ctx, q) }),
		newIndicatorCmd(f, "domain", "Reputation for a domain", "VectorSnap", "vectorsnap.domain",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) {
				return c.VectorSnap.Domain(ctx, q)
			}),
		newIndicatorCmd(f, "url", "Reputation for a URL", "VectorSnap", "vectorsnap.url",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.VectorSnap.URL(ctx, q) }),
		newIndicatorCmd(f, "hash", "Reputation for a file hash", "VectorSnap", "vectorsnap.hash",
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
		newIndicatorCmd(f, "ip", "Pulse enrichment for an IP address", "PulseSnap", "pulsesnap.ip",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.PulseSnap.IP(ctx, q) }),
		newIndicatorCmd(f, "domain", "Pulse enrichment for a domain", "PulseSnap", "pulsesnap.domain",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) {
				return c.PulseSnap.Domain(ctx, q)
			}),
		newIndicatorCmd(f, "url", "Pulse enrichment for a URL", "PulseSnap", "pulsesnap.url",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.PulseSnap.URL(ctx, q) }),
		newIndicatorCmd(f, "hash", "Pulse enrichment for a file hash", "PulseSnap", "pulsesnap.hash",
			func(ctx context.Context, c *crawlsnap.Client, q string) (any, error) { return c.PulseSnap.Hash(ctx, q) }),
	)
	return cmd
}
