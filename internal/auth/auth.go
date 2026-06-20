// Package auth resolves and stores the CrawlSnap API key. Keys are kept in the
// OS keychain when one is reachable; otherwise they fall back to the config
// file (0600). Resolution order for a request, highest priority first:
//
//  1. --api-key flag            (handled by the caller, see Source.Flag)
//  2. $CRAWLSNAP_API_KEY        (env)
//  3. OS keychain, per profile
//  4. config file, per profile  (fallback secret store)
package auth

import (
	"errors"
	"os"

	"github.com/crawlsnap/crawlsnap-cli/internal/config"
	"github.com/zalando/go-keyring"
)

// keyringService namespaces our secrets in the OS keychain.
const keyringService = "crawlsnap-cli"

// EnvAPIKey is the environment variable consulted for an API key.
const EnvAPIKey = "CRAWLSNAP_API_KEY"

// Source describes where a resolved key came from, for `auth status` output.
type Source string

const (
	SourceNone    Source = "none"
	SourceFlag    Source = "flag"
	SourceEnv     Source = "env"
	SourceKeyring Source = "keychain"
	SourceConfig  Source = "config file"
)

// Resolve returns the API key for the given profile and where it was found,
// applying env > keychain > config-file precedence. The --api-key flag is
// resolved by the caller before this is reached. An empty key with SourceNone
// means no credentials are configured.
func Resolve(cfg *config.Config, profile string) (key string, src Source) {
	if v := os.Getenv(EnvAPIKey); v != "" {
		return v, SourceEnv
	}
	if v, err := keyring.Get(keyringService, profile); err == nil && v != "" {
		return v, SourceKeyring
	}
	if p, ok := cfg.Profiles[profile]; ok && p.APIKey != "" {
		return p.APIKey, SourceConfig
	}
	return "", SourceNone
}

// Store saves the key for a profile. It prefers the OS keychain; if the keychain
// is unavailable it falls back to the config file and reports usedFallback=true
// so the caller can warn the user. cfg is mutated and saved on fallback.
func Store(cfg *config.Config, profile, key string) (usedFallback bool, err error) {
	if kerr := keyring.Set(keyringService, profile, key); kerr == nil {
		// Make sure a stale plaintext copy doesn't shadow the keychain.
		if p, ok := cfg.Profiles[profile]; ok && p.APIKey != "" {
			p.APIKey = ""
			if serr := cfg.Save(); serr != nil {
				return false, serr
			}
		}
		return false, nil
	}

	cfg.Profile(profile).APIKey = key
	if serr := cfg.Save(); serr != nil {
		return true, serr
	}
	return true, nil
}

// Delete removes the stored key for a profile from both the keychain and the
// config file. Missing entries are not an error.
func Delete(cfg *config.Config, profile string) error {
	var errs []error
	if err := keyring.Delete(keyringService, profile); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		errs = append(errs, err)
	}
	if p, ok := cfg.Profiles[profile]; ok && p.APIKey != "" {
		p.APIKey = ""
		if err := cfg.Save(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
