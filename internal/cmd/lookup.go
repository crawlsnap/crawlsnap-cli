package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	crawlsnap "github.com/crawlsnap/crawlsnap-go"
	"github.com/spf13/cobra"
)

// indicatorKind is a detected indicator type.
type indicatorKind string

const (
	kindIP      indicatorKind = "ip"
	kindURL     indicatorKind = "url"
	kindHash    indicatorKind = "hash"
	kindDomain  indicatorKind = "domain"
	kindUnknown indicatorKind = "unknown"
)

var (
	hashRe   = regexp.MustCompile(`^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$`)
	domainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// detectIndicator classifies an indicator string. Order matters: URLs and IPs
// are unambiguous, hashes are fixed-width hex, domains are the catch-all.
func detectIndicator(s string) indicatorKind {
	switch {
	case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"):
		return kindURL
	case net.ParseIP(s) != nil:
		return kindIP
	case hashRe.MatchString(s):
		return kindHash
	case domainRe.MatchString(s):
		return kindDomain
	default:
		return kindUnknown
	}
}

// allLookupProducts lists the products lookup can query, in display order.
var allLookupProducts = []string{"vectorsnap", "pulsesnap"}

// newLookupCmd builds the smart `lookup` command: it detects the indicator type
// and enriches it across the selected products in one shot.
func newLookupCmd(f *Factory) *cobra.Command {
	var products []string

	cmd := &cobra.Command{
		Use:   "lookup <indicator>",
		Short: "Auto-detect an indicator and enrich it across products",
		Long: "lookup detects whether the indicator is an ip, domain, url, or hash and\n" +
			"queries the selected products, returning their results together.\n\n" +
			"By default it queries every product (--products). The public API has no\n" +
			"entitlement endpoint, so a product you are not subscribed to is reported as\n" +
			"\"skipped\" rather than failing. Each successful product call consumes credits;\n" +
			"restrict with --products to avoid spending on products you do not need.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			selected, err := parseProducts(products)
			if err != nil {
				return err
			}
			p, err := f.Printer()
			if err != nil {
				return err
			}
			client, err := f.Client()
			if err != nil {
				return err
			}
			indicator := args[0]
			kind := detectIndicator(indicator)
			if kind == kindUnknown {
				return fmt.Errorf("could not detect indicator type for %q (expected ip, domain, url, or hash)", indicator)
			}
			ctx := c.Context()

			stop := p.Spinner(fmt.Sprintf("Looking up %s (%s)…", indicator, kind))
			result := map[string]any{"indicator": indicator, "kind": string(kind)}
			var firstErr error
			success := 0
			for _, prod := range allLookupProducts {
				if !selected[prod] {
					continue
				}
				var data any
				var callErr error
				switch prod {
				case "vectorsnap":
					data, callErr = vectorLookup(ctx, client, kind, indicator)
				case "pulsesnap":
					data, callErr = pulseLookup(ctx, client, kind, indicator)
				}
				display, real := classifyOutcome(data, callErr)
				result[prod] = display
				if callErr == nil {
					success++
				}
				if firstErr == nil && callErr != nil {
					firstErr = real // prefer a real error; subscription "skips" leave this nil
				}
			}
			stop()

			if err := p.Result(result, "lookup"); err != nil {
				return err
			}
			// Non-zero exit only when nothing succeeded.
			if success == 0 && firstErr != nil {
				return firstErr
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&products, "products", allLookupProducts,
		"products to query (vectorsnap, pulsesnap)")
	return cmd
}

// parseProducts validates the --products selection into a set.
func parseProducts(in []string) (map[string]bool, error) {
	valid := map[string]bool{"vectorsnap": true, "pulsesnap": true}
	out := map[string]bool{}
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if !valid[p] {
			return nil, fmt.Errorf("unknown product %q (valid: vectorsnap, pulsesnap)", p)
		}
		out[p] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no products selected")
	}
	return out, nil
}

// classifyOutcome shapes a per-product result. A "not subscribed" (403) is a
// soft skip, not a failure; other errors are surfaced and counted.
func classifyOutcome(data any, err error) (display any, real error) {
	if err == nil {
		return data, nil
	}
	var sub *crawlsnap.SubscriptionInactiveError
	if errors.As(err, &sub) {
		return map[string]any{"skipped": "not subscribed to this product"}, nil
	}
	return map[string]any{"error": err.Error()}, err
}

// vectorLookup runs the VectorSnap method matching the detected kind.
func vectorLookup(ctx context.Context, c *crawlsnap.Client, kind indicatorKind, q string) (any, error) {
	switch kind {
	case kindIP:
		return c.VectorSnap.IP(ctx, q)
	case kindDomain:
		return c.VectorSnap.Domain(ctx, q)
	case kindURL:
		return c.VectorSnap.URL(ctx, q)
	case kindHash:
		return c.VectorSnap.Hash(ctx, q)
	default:
		return nil, fmt.Errorf("unsupported indicator kind %q", kind)
	}
}

// pulseLookup runs the PulseSnap method matching the detected kind.
func pulseLookup(ctx context.Context, c *crawlsnap.Client, kind indicatorKind, q string) (any, error) {
	switch kind {
	case kindIP:
		return c.PulseSnap.IP(ctx, q)
	case kindDomain:
		return c.PulseSnap.Domain(ctx, q)
	case kindURL:
		return c.PulseSnap.URL(ctx, q)
	case kindHash:
		return c.PulseSnap.Hash(ctx, q)
	default:
		return nil, fmt.Errorf("unsupported indicator kind %q", kind)
	}
}

// resultOrError shapes a per-product outcome for the combined output.
func resultOrError(data any, err error) any {
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return data
}
