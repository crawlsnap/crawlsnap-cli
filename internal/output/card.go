package output

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

// badgeLevel selects the color of a card's verdict badge.
type badgeLevel int

const (
	badgeNeutral badgeLevel = iota
	badgeClean
	badgeSuspicious
	badgeMalicious
	badgeInfo
	badgeError
)

// cardRow is one label/value line in a card body.
type cardRow struct {
	label string
	value string
}

// Card is a curated, human-friendly summary of an API response. The full data
// is always available via --full or -o json.
type Card struct {
	title    string     // top label, e.g. "VectorSnap · IP Reputation"
	heading  string     // primary identity, e.g. "8.8.8.8"
	badge    string     // verdict text, e.g. "CLEAN"
	level    badgeLevel // badge color
	subtitle string     // muted context line under the heading
	rows     []cardRow  // aligned label/value rows
	list     []string   // optional bullet list (e.g. subdomains)
	footer   string     // muted hint, e.g. "10 files · 25 resolutions → --full"
}

func (c *Card) addRow(label, value string) {
	if value == "" {
		return
	}
	c.rows = append(c.rows, cardRow{label, value})
}

// renderCards prints one or more cards to stdout.
func (p *Printer) renderCards(cards []*Card) error {
	var b strings.Builder
	for i, c := range cards {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.renderCard(c))
		b.WriteByte('\n')
	}
	_, err := fmt.Fprint(p.out, b.String())
	return err
}

// renderCard renders a single card: a bordered panel with a colored verdict
// badge, followed by a muted footer line.
func (p *Printer) renderCard(c *Card) string {
	var body strings.Builder

	// Header: title (muted), then heading + badge.
	if c.title != "" {
		body.WriteString(p.cardStyle(styTitle).Render(c.title))
		body.WriteByte('\n')
	}
	headLine := p.cardStyle(styHeading).Render(c.heading)
	if c.badge != "" {
		if p.color {
			headLine += "  " + p.badgeStyle(c.level).Render(" "+c.badge+" ")
		} else {
			headLine += "  [" + c.badge + "]"
		}
	}
	body.WriteString(headLine)
	body.WriteByte('\n')
	if c.subtitle != "" {
		body.WriteString(p.cardStyle(stySubtitle).Render(c.subtitle))
		body.WriteByte('\n')
	}

	// Rows: aligned labels.
	if len(c.rows) > 0 {
		body.WriteByte('\n')
		w := 0
		for _, r := range c.rows {
			if len(r.label) > w {
				w = len(r.label)
			}
		}
		for _, r := range c.rows {
			label := p.cardStyle(styLabel).Render(padRight(r.label, w))
			body.WriteString(label + "  " + p.cardStyle(styValue).Render(r.value) + "\n")
		}
	}

	// Optional bullet list.
	if len(c.list) > 0 {
		body.WriteByte('\n')
		for _, item := range c.list {
			body.WriteString(p.cardStyle(styMuted).Render("  • ") + p.cardStyle(styValue).Render(item) + "\n")
		}
	}

	content := strings.TrimRight(body.String(), "\n")
	boxed := p.boxStyle(c.level).Render(content)

	if c.footer != "" {
		boxed += "\n" + p.cardStyle(styMuted).Render(c.footer)
	}
	return boxed
}

// style identifiers for card text.
type cardStyleID int

const (
	styTitle cardStyleID = iota
	styHeading
	stySubtitle
	styLabel
	styValue
	styMuted
)

func (p *Printer) cardStyle(id cardStyleID) lipgloss.Style {
	if !p.color {
		return lipgloss.NewStyle()
	}
	switch id {
	case styTitle:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Bold(true)
	case styHeading:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Bold(true)
	case stySubtitle:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	case styLabel:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	case styValue:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	case styMuted:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Italic(true)
	default:
		return lipgloss.NewStyle()
	}
}

// badgeStyle returns the style for a verdict badge.
func (p *Printer) badgeStyle(level badgeLevel) lipgloss.Style {
	if !p.color {
		return lipgloss.NewStyle()
	}
	base := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0"))
	switch level {
	case badgeClean:
		return base.Background(lipgloss.Color("10"))
	case badgeSuspicious:
		return base.Background(lipgloss.Color("11"))
	case badgeMalicious, badgeError:
		return base.Background(lipgloss.Color("9"))
	case badgeInfo:
		return base.Background(lipgloss.Color("12"))
	default:
		return base.Background(lipgloss.Color("8"))
	}
}

// boxStyle returns the bordered panel style, tinted by the badge level.
func (p *Printer) boxStyle(level badgeLevel) lipgloss.Style {
	s := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	if !p.color {
		return s
	}
	color := lipgloss.Color("8")
	switch level {
	case badgeClean:
		color = lipgloss.Color("10")
	case badgeSuspicious:
		color = lipgloss.Color("11")
	case badgeMalicious, badgeError:
		color = lipgloss.Color("9")
	case badgeInfo:
		color = lipgloss.Color("12")
	}
	return s.BorderForeground(color)
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}
