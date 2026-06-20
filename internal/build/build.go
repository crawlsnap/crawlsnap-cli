// Package build holds release metadata injected at link time by GoReleaser
// (-ldflags "-X ...") and falls back to sane defaults for local `go run`/`go build`.
package build

import "runtime/debug"

// These are overwritten at release time via -ldflags. Keep the variable names
// stable: .goreleaser.yaml references them by their full import path.
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Resolve returns the effective version/commit/date, filling any unset value
// from the embedded VCS build info so `go install` builds still report something
// meaningful.
func Resolve() (version, commit, date string) {
	version, commit, date = Version, Commit, Date

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.time":
				if date == "" {
					date = s.Value
				}
			}
		}
		if version == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
	}

	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "none"
	}
	if date == "" {
		date = "unknown"
	}
	return version, commit, date
}
