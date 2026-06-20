package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/crawlsnap/crawlsnap-cli/internal/auth"
)

// newAuthCmd builds the `auth` command group: login, status, logout.
func newAuthCmd(f *Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication and stored credentials",
	}
	cmd.AddCommand(newAuthLoginCmd(f), newAuthStatusCmd(f), newAuthLogoutCmd(f))
	return cmd
}

func newAuthLoginCmd(f *Factory) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Store an API key for the active profile",
		Long: "Store an API key in the OS keychain (falling back to the config file).\n" +
			"The key is read from --api-key, else from stdin, else prompted interactively.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := f.Printer()
			if err != nil {
				return err
			}
			cfg, err := f.Config()
			if err != nil {
				return err
			}
			profile, err := f.Profile()
			if err != nil {
				return err
			}

			key := f.APIKeyFlag
			if key == "" {
				key, err = readSecret(c, "Enter your CrawlSnap API key: ")
				if err != nil {
					return err
				}
			}
			key = strings.TrimSpace(key)
			if key == "" {
				return fmt.Errorf("no API key provided")
			}

			usedFallback, err := auth.Store(cfg, profile, key)
			if err != nil {
				return fmt.Errorf("store API key: %w", err)
			}
			if usedFallback {
				p.Warn("OS keychain unavailable; key saved to the config file (0600).")
			}
			p.Success("Logged in to profile %q.", profile)
			return nil
		},
	}
}

func newAuthStatusCmd(f *Factory) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the active profile and credential source",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := f.Printer()
			if err != nil {
				return err
			}
			profile, err := f.Profile()
			if err != nil {
				return err
			}
			key, src, err := f.APIKey()
			if err != nil {
				return err
			}
			baseURL, err := f.baseURL()
			if err != nil {
				return err
			}
			if baseURL == "" {
				baseURL = "https://api.crawlsnap.com (default)"
			}

			status := map[string]any{
				"profile":  profile,
				"base_url": baseURL,
			}
			if key == "" {
				status["authenticated"] = false
				status["source"] = string(auth.SourceNone)
			} else {
				status["authenticated"] = true
				status["source"] = string(src)
				status["api_key"] = maskKey(key)
			}
			return p.Result(status)
		},
	}
}

func newAuthLogoutCmd(f *Factory) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored API key for the active profile",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := f.Printer()
			if err != nil {
				return err
			}
			cfg, err := f.Config()
			if err != nil {
				return err
			}
			profile, err := f.Profile()
			if err != nil {
				return err
			}
			if err := auth.Delete(cfg, profile); err != nil {
				return fmt.Errorf("remove API key: %w", err)
			}
			p.Success("Logged out of profile %q.", profile)
			return nil
		},
	}
}

// readSecret reads a secret from the terminal without echo, or from a non-TTY
// stdin one line at a time (for piping).
func readSecret(c *cobra.Command, prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(c.ErrOrStderr(), prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(c.ErrOrStderr())
		if err != nil {
			return "", fmt.Errorf("read API key: %w", err)
		}
		return string(b), nil
	}
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", fmt.Errorf("read API key: %w", err)
		}
		return "", fmt.Errorf("no API key on stdin")
	}
	return sc.Text(), nil
}

// maskKey reveals only the last 4 characters of a key.
func maskKey(key string) string {
	if len(key) <= 4 {
		return strings.Repeat("•", len(key))
	}
	return strings.Repeat("•", 6) + key[len(key)-4:]
}
