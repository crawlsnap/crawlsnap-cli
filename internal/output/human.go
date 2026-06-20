package output

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
)

// Palette holds the styles used for human output. When color is disabled all
// styles render as plain text.
type palette struct {
	key    lipgloss.Style
	scalar lipgloss.Style
	null   lipgloss.Style
	index  lipgloss.Style
}

func newPalette(color bool) palette {
	if !color {
		plain := lipgloss.NewStyle()
		return palette{key: plain, scalar: plain, null: plain, index: plain}
	}
	return palette{
		key:    lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true),
		scalar: lipgloss.NewStyle().Foreground(lipgloss.Color("15")),
		null:   lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Italic(true),
		index:  lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

// writeHuman renders a generic value as an indented key/value tree.
func (p *Printer) writeHuman(v any) error {
	pal := newPalette(p.color)
	var b strings.Builder
	renderValue(&b, pal, v, 0, true)
	_, err := io.WriteString(p.out, strings.TrimRight(b.String(), "\n")+"\n")
	return err
}

const indentUnit = "  "

// renderValue writes v at the given indent depth. atRoot suppresses a leading
// newline for the top-level container.
func renderValue(b *strings.Builder, pal palette, v any, depth int, atRoot bool) {
	switch t := v.(type) {
	case map[string]any:
		renderMap(b, pal, t, depth, atRoot)
	case []any:
		renderSlice(b, pal, t, depth, atRoot)
	default:
		b.WriteString(pal.scalar.Render(scalarString(pal, v)))
		b.WriteByte('\n')
	}
}

func renderMap(b *strings.Builder, pal palette, m map[string]any, depth int, atRoot bool) {
	if len(m) == 0 {
		b.WriteString(pal.null.Render("(empty)"))
		b.WriteByte('\n')
		return
	}
	if !atRoot {
		b.WriteByte('\n')
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	indent := strings.Repeat(indentUnit, depth)
	for _, k := range keys {
		b.WriteString(indent)
		b.WriteString(pal.key.Render(k + ":"))
		val := m[k]
		if isContainer(val) {
			renderValue(b, pal, val, depth+1, false)
		} else {
			b.WriteByte(' ')
			b.WriteString(scalarString(pal, val))
			b.WriteByte('\n')
		}
	}
}

func renderSlice(b *strings.Builder, pal palette, s []any, depth int, atRoot bool) {
	if len(s) == 0 {
		b.WriteString(pal.null.Render("(none)"))
		b.WriteByte('\n')
		return
	}
	if !atRoot {
		b.WriteByte('\n')
	}
	indent := strings.Repeat(indentUnit, depth)
	for i, item := range s {
		b.WriteString(indent)
		b.WriteString(pal.index.Render("- "))
		if isContainer(item) {
			// Render container inline after the bullet, keeping its first line
			// on the same row by trimming the leading newline it would emit.
			var sub strings.Builder
			renderValue(&sub, pal, item, depth+1, false)
			b.WriteString(strings.TrimLeft(sub.String(), "\n"))
		} else {
			b.WriteString(scalarString(pal, item))
			b.WriteByte('\n')
		}
		_ = i
	}
}

func isContainer(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

// scalarString renders a leaf value, styling nulls distinctly.
func scalarString(pal palette, v any) string {
	switch t := v.(type) {
	case nil:
		return pal.null.Render("null")
	case bool:
		return pal.scalar.Render(strconv.FormatBool(t))
	case string:
		return pal.scalar.Render(t)
	case float64:
		// JSON numbers decode as float64; print integers without a trailing .0.
		if t == float64(int64(t)) {
			return pal.scalar.Render(strconv.FormatInt(int64(t), 10))
		}
		return pal.scalar.Render(strconv.FormatFloat(t, 'f', -1, 64))
	default:
		return pal.scalar.Render(fmt.Sprintf("%v", t))
	}
}
