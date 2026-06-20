package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	crawlsnap "github.com/crawlsnap/crawlsnap-go"
	"github.com/spf13/cobra"
)

// indicatorRunner performs a single lookup against the SDK and returns the typed
// payload as an untyped value for the printer.
type indicatorRunner func(ctx context.Context, client *crawlsnap.Client, query string) (any, error)

// newIndicatorCmd builds a leaf command that takes one or more indicators (or
// "-" to read them from stdin) and runs them through run. view selects the
// curated summary card (e.g. "vectorsnap.ip").
func newIndicatorCmd(f *Factory, use, short, label, view string, run indicatorRunner) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <indicator>...",
		Short: short,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return runIndicator(c, f, label, view, args, run)
		},
	}
}

// batchItem is one result in a multi-indicator run.
type batchItem struct {
	Query string `json:"query"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// runIndicator resolves the queries, runs each with a spinner, and prints the
// result. A single query prints its payload directly; multiple queries print a
// list of {query, data|error} items and the process still exits non-zero if any
// failed.
func runIndicator(cmd *cobra.Command, f *Factory, label, view string, args []string, run indicatorRunner) error {
	p, err := f.Printer()
	if err != nil {
		return err
	}
	client, err := f.Client()
	if err != nil {
		return err
	}
	queries, err := resolveQueries(args)
	if err != nil {
		return err
	}
	ctx := cmd.Context()

	if len(queries) == 1 {
		stop := p.Spinner(fmt.Sprintf("Querying %s for %s…", label, queries[0]))
		data, err := run(ctx, client, queries[0])
		stop()
		if err != nil {
			return err
		}
		return p.Result(data, view)
	}

	results := make([]batchItem, 0, len(queries))
	var firstErr error
	for _, q := range queries {
		stop := p.Spinner(fmt.Sprintf("Querying %s for %s…", label, q))
		data, err := run(ctx, client, q)
		stop()
		item := batchItem{Query: q}
		if err != nil {
			item.Error = err.Error()
			if firstErr == nil {
				firstErr = err
			}
		} else {
			item.Data = data
		}
		results = append(results, item)
	}
	if err := p.Result(results, ""); err != nil {
		return err
	}
	return firstErr
}

// resolveQueries expands a single "-" argument into the lines of stdin;
// otherwise it returns the args verbatim. Blank lines are skipped.
func resolveQueries(args []string) ([]string, error) {
	if len(args) == 1 && args[0] == "-" {
		var lines []string
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("no indicators provided on stdin")
		}
		return lines, nil
	}
	return args, nil
}
