// Package output renders command results in the user's chosen format (human,
// json, yaml), optionally filtered with a jq expression, and provides styled
// status messages and a spinner on stderr. stdout carries machine-readable
// result data only; all decoration goes to stderr so piping stays clean.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/itchyny/gojq"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Format is an output encoding for result data.
type Format string

const (
	FormatHuman Format = "human"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// ParseFormat validates and normalizes an --output value.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatHuman, FormatJSON, FormatYAML:
		return Format(s), nil
	case "":
		return FormatHuman, nil
	default:
		return "", fmt.Errorf("invalid output format %q (want: human, json, yaml)", s)
	}
}

// Options configure a Printer.
type Options struct {
	Format  Format
	Query   string // optional jq expression applied to result data
	NoColor bool
	Quiet   bool // suppress spinner and status messages
	Full    bool // render the full data tree instead of a curated card
}

// Printer renders results and status to the given writers.
type Printer struct {
	out   io.Writer
	err   io.Writer
	opts  Options
	color bool
}

// NewPrinter builds a Printer. Color is enabled only when not disabled, NO_COLOR
// is unset, and stdout is a terminal.
func NewPrinter(out, err io.Writer, opts Options) *Printer {
	color := !opts.NoColor && os.Getenv("NO_COLOR") == "" && isTerminal(out)
	return &Printer{out: out, err: err, opts: opts, color: color}
}

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Result renders the command's payload. data is any JSON-serializable value
// (typically an SDK response struct). view names a curated card renderer
// (e.g. "vectorsnap.ip"); pass "" for none. When a query is set it is applied
// first and curated cards are skipped (the shape no longer matches).
func (p *Printer) Result(data any, view string) error {
	v, err := toGeneric(data)
	if err != nil {
		return err
	}
	if p.opts.Query != "" {
		v, err = applyQuery(p.opts.Query, v)
		if err != nil {
			return err
		}
	}
	switch p.opts.Format {
	case FormatJSON:
		return p.writeJSON(v)
	case FormatYAML:
		return p.writeYAML(v)
	default:
		// Curated card when one exists for this view and the user has not asked
		// for the full tree or applied a query.
		if view != "" && !p.opts.Full && p.opts.Query == "" && hasCard(view) {
			if cards := cardBuilders[view](v); len(cards) > 0 {
				return p.renderCards(cards)
			}
		}
		return p.writeHuman(v)
	}
}

// toGeneric round-trips data through JSON into map/slice/scalar values so every
// renderer works against one uniform shape.
func toGeneric(data any) (any, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	return v, nil
}

// applyQuery runs a jq expression over the value. A single output is returned
// unwrapped; multiple outputs are collected into a slice.
func applyQuery(expr string, v any) (any, error) {
	q, err := gojq.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid --query %q: %w", expr, err)
	}
	var results []any
	iter := q.Run(v)
	for {
		out, ok := iter.Next()
		if !ok {
			break
		}
		if e, ok := out.(error); ok {
			return nil, fmt.Errorf("query error: %w", e)
		}
		results = append(results, out)
	}
	switch len(results) {
	case 0:
		return nil, nil
	case 1:
		return results[0], nil
	default:
		return results, nil
	}
}

func (p *Printer) writeJSON(v any) error {
	enc := json.NewEncoder(p.out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func (p *Printer) writeYAML(v any) error {
	enc := yaml.NewEncoder(p.out)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(v)
}
