package cmd

import (
	"fmt"
	"io"
	"os"

	"charm.land/lipgloss/v2"
	"golang.org/x/term"

	"github.com/crawlsnap/crawlsnap-cli/internal/build"
)

// bannerArt is the "CrawlSnap" wordmark (figlet "slant").
var bannerArt = []string{
	"   ______                    _______",
	"  / ____/________ __      __/ / ___/____  ____ _____",
	" / /   / ___/ __ `/ | /| / / /\\__ \\/ __ \\/ __ `/ __ \\",
	"/ /___/ /  / /_/ /| |/ |/ / /___/ / / / / /_/ / /_/ /",
	"\\____/_/   \\__,_/ |__/|__/_//____/_/ /_/\\__,_/ .___/",
	"                                            /_/",
}

// bannerColors shades the art lines from blue to cyan (ANSI 256).
var bannerColors = []string{"33", "39", "45", "51", "44", "43"}

// printBanner writes the wordmark, tagline, and a quick-start hint to w. It is
// shown only on a bare `crawlsnap` invocation.
func printBanner(w io.Writer, color bool) {
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	for i, line := range bannerArt {
		if color {
			st := lipgloss.NewStyle().Foreground(lipgloss.Color(bannerColors[i%len(bannerColors)])).Bold(true)
			fmt.Fprintln(w, st.Render(line))
		} else {
			fmt.Fprintln(w, line)
		}
	}

	version, _, _ := build.Resolve()
	tagline := "data intelligence from your terminal · " + version
	fmt.Fprintln(w)
	if color {
		fmt.Fprintln(w, muted.Render(tagline))
	} else {
		fmt.Fprintln(w, tagline)
	}

	fmt.Fprintln(w)
	hint := []string{
		"Quick start:",
		"  crawlsnap auth login                 store your API key",
		"  crawlsnap lookup 8.8.8.8             auto-detect & enrich an indicator",
		"  crawlsnap vectorsnap ip 1.1.1.1      reputation for an IP",
		"  crawlsnap --help                     all commands",
	}
	for _, line := range hint {
		if color {
			fmt.Fprintln(w, muted.Render(line))
		} else {
			fmt.Fprintln(w, line)
		}
	}
}

// bannerColorEnabled reports whether the banner should be colored: stdout is a
// terminal, NO_COLOR is unset, and --no-color was not passed.
func bannerColorEnabled(f *Factory) bool {
	if f.NoColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}
