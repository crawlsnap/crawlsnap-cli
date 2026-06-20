package output

import (
	"fmt"
	"io"
	"sync"
	"time"

	"charm.land/lipgloss/v2"
)

// status styles for stderr messages.
func (p *Printer) styles() (success, warn, errSt, info lipgloss.Style) {
	if !p.color {
		plain := lipgloss.NewStyle()
		return plain, plain, plain, plain
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true),
		lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true),
		lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
}

// Success prints a success line to stderr (suppressed when --quiet).
func (p *Printer) Success(format string, a ...any) {
	if p.opts.Quiet {
		return
	}
	s, _, _, _ := p.styles()
	fmt.Fprintln(p.err, s.Render("✓ ")+fmt.Sprintf(format, a...))
}

// Warn prints a warning line to stderr (always shown, even with --quiet).
func (p *Printer) Warn(format string, a ...any) {
	_, w, _, _ := p.styles()
	fmt.Fprintln(p.err, w.Render("! ")+fmt.Sprintf(format, a...))
}

// Info prints a muted informational line to stderr (suppressed when --quiet).
func (p *Printer) Info(format string, a ...any) {
	if p.opts.Quiet {
		return
	}
	_, _, _, i := p.styles()
	fmt.Fprintln(p.err, i.Render(fmt.Sprintf(format, a...)))
}

// Errorf prints an error line to stderr.
func (p *Printer) Errorf(format string, a ...any) {
	_, _, e, _ := p.styles()
	fmt.Fprintln(p.err, e.Render("✗ ")+fmt.Sprintf(format, a...))
}

// spinnerFrames is a braille spinner.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner starts an animated spinner on stderr and returns a stop function. It
// is a no-op (returning a no-op stop) unless stderr is a TTY and output is not
// quiet — so piped or scripted runs stay silent and uncorrupted.
func (p *Printer) Spinner(msg string) (stop func()) {
	if p.opts.Quiet || !isTerminal(p.err) {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	style := lipgloss.NewStyle()
	if p.color {
		style = style.Foreground(lipgloss.Color("12"))
	}
	go func() {
		ticker := time.NewTicker(90 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-done:
				// Clear the spinner line.
				fmt.Fprint(p.err, "\r\033[K")
				return
			case <-ticker.C:
				frame := style.Render(spinnerFrames[i%len(spinnerFrames)])
				fmt.Fprintf(p.err, "\r%s %s", frame, msg)
				i++
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// Out returns the result writer (stdout), for callers that stream their own output.
func (p *Printer) Out() io.Writer { return p.out }
