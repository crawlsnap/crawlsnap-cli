package cmd

import (
	"fmt"
	"os"
	"time"

	crawlsnap "github.com/crawlsnap/crawlsnap-go"

	"github.com/crawlsnap/crawlsnap-cli/internal/auth"
	"github.com/crawlsnap/crawlsnap-cli/internal/config"
	"github.com/crawlsnap/crawlsnap-cli/internal/output"
)

// EnvProfile selects the active profile when --profile is not given.
const EnvProfile = "CRAWLSNAP_PROFILE"

// Factory carries the resolved global options and lazily builds the shared
// dependencies (config, printer, SDK client) that commands need. One Factory is
// created per process and its fields are populated from persistent flags.
type Factory struct {
	ProfileFlag string
	APIKeyFlag  string
	BaseURLFlag string
	OutputFlag  string
	QueryFlag   string
	NoColor     bool
	Quiet       bool
	Full        bool
	Timeout     time.Duration

	cfg *config.Config
}

// Config lazily loads and caches the on-disk config.
func (f *Factory) Config() (*config.Config, error) {
	if f.cfg != nil {
		return f.cfg, nil
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	f.cfg = cfg
	return cfg, nil
}

// Profile resolves the active profile name: --profile > $CRAWLSNAP_PROFILE >
// the config's default.
func (f *Factory) Profile() (string, error) {
	if f.ProfileFlag != "" {
		return f.ProfileFlag, nil
	}
	if v := os.Getenv(EnvProfile); v != "" {
		return v, nil
	}
	cfg, err := f.Config()
	if err != nil {
		return "", err
	}
	return cfg.ResolvedDefault(), nil
}

// Printer builds an output printer from the global formatting flags.
func (f *Factory) Printer() (*output.Printer, error) {
	format, err := output.ParseFormat(f.OutputFlag)
	if err != nil {
		return nil, err
	}
	return output.NewPrinter(os.Stdout, os.Stderr, output.Options{
		Format:  format,
		Query:   f.QueryFlag,
		NoColor: f.NoColor,
		Quiet:   f.Quiet,
		Full:    f.Full,
	}), nil
}

// APIKey resolves the effective key and its source for the active profile,
// honoring the --api-key flag first.
func (f *Factory) APIKey() (key string, src auth.Source, err error) {
	if f.APIKeyFlag != "" {
		return f.APIKeyFlag, auth.SourceFlag, nil
	}
	cfg, err := f.Config()
	if err != nil {
		return "", auth.SourceNone, err
	}
	profile, err := f.Profile()
	if err != nil {
		return "", auth.SourceNone, err
	}
	key, src = auth.Resolve(cfg, profile)
	return key, src, nil
}

// Client builds an authenticated SDK client. It returns a friendly error when
// no credentials are configured, pointing the user at `crawlsnap auth login`.
func (f *Factory) Client() (*crawlsnap.Client, error) {
	key, _, err := f.APIKey()
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, fmt.Errorf("no API key configured: run `crawlsnap auth login` or set %s", auth.EnvAPIKey)
	}

	opts := []crawlsnap.Option{}
	baseURL, err := f.baseURL()
	if err != nil {
		return nil, err
	}
	if baseURL != "" {
		opts = append(opts, crawlsnap.WithBaseURL(baseURL))
	}
	if f.Timeout > 0 {
		opts = append(opts, crawlsnap.WithTimeout(f.Timeout))
	}
	return crawlsnap.NewClient(key, opts...)
}

// baseURL resolves the API host override: --base-url > profile.base_url > "" (SDK default).
func (f *Factory) baseURL() (string, error) {
	if f.BaseURLFlag != "" {
		return f.BaseURLFlag, nil
	}
	cfg, err := f.Config()
	if err != nil {
		return "", err
	}
	profile, err := f.Profile()
	if err != nil {
		return "", err
	}
	if p, ok := cfg.Profiles[profile]; ok {
		return p.BaseURL, nil
	}
	return "", nil
}
