// Package config loads and persists the CLI's on-disk configuration: the set of
// named profiles and which one is the default. Secrets (API keys) live in the OS
// keychain when available (see internal/auth); a key is only written here as a
// fallback when no keychain is reachable.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DefaultProfileName is the profile used when the user does not select one.
const DefaultProfileName = "default"

// Profile is a single named set of connection settings.
type Profile struct {
	// BaseURL overrides the API host for this profile (blank = SDK default).
	BaseURL string `yaml:"base_url,omitempty"`
	// APIKey is a fallback secret store used only when the OS keychain is
	// unavailable. Prefer the keychain; this field stays empty otherwise.
	APIKey string `yaml:"api_key,omitempty"`
}

// Config is the full on-disk document.
type Config struct {
	// DefaultProfile names the profile used absent --profile / $CRAWLSNAP_PROFILE.
	DefaultProfile string `yaml:"default_profile,omitempty"`
	// Profiles maps profile name to its settings.
	Profiles map[string]*Profile `yaml:"profiles,omitempty"`

	path string `yaml:"-"`
}

// Path returns the resolved config file location, honoring $CRAWLSNAP_CONFIG_DIR
// and otherwise using the OS config directory (XDG on Linux,
// ~/Library/Application Support on macOS, %AppData% on Windows).
func Path() (string, error) {
	if dir := os.Getenv("CRAWLSNAP_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.yml"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config dir: %w", err)
	}
	return filepath.Join(base, "crawlsnap", "config.yml"), nil
}

// Load reads the config file, returning an empty (but valid) Config when the
// file does not yet exist.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	cfg := &Config{Profiles: map[string]*Profile{}, path: path}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*Profile{}
	}
	cfg.path = path
	return cfg, nil
}

// Save writes the config file atomically with 0600 permissions, creating the
// parent directory as needed.
func (c *Config) Save() error {
	if c.path == "" {
		p, err := Path()
		if err != nil {
			return err
		}
		c.path = p
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// Profile returns the named profile, creating an empty one in memory if absent
// (it is only persisted on Save).
func (c *Config) Profile(name string) *Profile {
	if name == "" {
		name = c.ResolvedDefault()
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	p, ok := c.Profiles[name]
	if !ok {
		p = &Profile{}
		c.Profiles[name] = p
	}
	return p
}

// ResolvedDefault returns the configured default profile name, falling back to
// the built-in default.
func (c *Config) ResolvedDefault() string {
	if c.DefaultProfile != "" {
		return c.DefaultProfile
	}
	return DefaultProfileName
}

// Names returns the configured profile names.
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	return names
}
