# CrawlSnap CLI

Official command-line interface for the [CrawlSnap](https://crawlsnap.com) data
intelligence platform. Query threat-intelligence and enrichment APIs directly
from your terminal, with human, JSON, and YAML output.

Built on the [CrawlSnap Go SDK](https://github.com/crawlsnap/crawlsnap-go).

## Install

### Homebrew (macOS / Linux)

```bash
brew install crawlsnap/tap/crawlsnap
```

### Scoop (Windows)

```powershell
scoop bucket add crawlsnap https://github.com/crawlsnap/scoop-bucket
scoop install crawlsnap
```

### Install script (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/crawlsnap/crawlsnap-cli/main/install.sh | sh
```

### From source

```bash
go install github.com/crawlsnap/crawlsnap-cli@latest
```

Or download a prebuilt binary from the [releases page](https://github.com/crawlsnap/crawlsnap-cli/releases).

## Authentication

Get an API key from your CrawlSnap dashboard, then:

```bash
crawlsnap auth login          # prompts for the key, stores it in your OS keychain
crawlsnap auth status         # show the active profile and credential source
crawlsnap auth logout
```

The key is resolved in this order: `--api-key` flag → `CRAWLSNAP_API_KEY`
environment variable → OS keychain → config file. The keychain is preferred;
when unavailable, the key is written to `config.yml` with `0600` permissions.

## Usage

```bash
# VectorSnap — IoC reputation enrichment
crawlsnap vectorsnap ip 8.8.8.8
crawlsnap vectorsnap domain example.com
crawlsnap vectorsnap url https://example.com/login
crawlsnap vectorsnap hash d41d8cd98f00b204e9800998ecf8427e

# PulseSnap — threat-intelligence pulse enrichment
crawlsnap pulsesnap ip 1.1.1.1

# SubdoSnap — subdomain enumeration
crawlsnap subdosnap scan example.com          # first page
crawlsnap subdosnap scan example.com --all    # follow the cursor, return all

# lookup — auto-detect the indicator type and query every product
crawlsnap lookup 8.8.8.8
crawlsnap lookup example.com
```

### Batch input

Pass `-` to read indicators from stdin (one per line), or list several at once:

```bash
cat ips.txt | crawlsnap vectorsnap ip -
crawlsnap vectorsnap domain example.com test.com acme.io
```

### Output formats and filtering

```bash
crawlsnap -o json vectorsnap ip 8.8.8.8                 # raw JSON (great for jq pipelines)
crawlsnap -o yaml pulsesnap domain example.com          # YAML
crawlsnap -q '.reputation' vectorsnap ip 8.8.8.8        # filter with a jq expression
```

Color is enabled automatically on a terminal and disabled when piped; honor
`NO_COLOR` or pass `--no-color`. A spinner shows on stderr during requests and
never corrupts piped stdout.

## Global flags

| Flag | Description |
|---|---|
| `--profile` | configuration profile (also `CRAWLSNAP_PROFILE`) |
| `--api-key` | API key override |
| `--base-url` | API host override (staging / self-host) |
| `-o, --output` | `human` (default), `json`, or `yaml` |
| `-q, --query` | jq expression applied to the result |
| `--no-color` | disable colored output |
| `--quiet` | suppress spinner and status messages |
| `--timeout` | per-request timeout (default `30s`) |

## Profiles

Multiple environments are supported via named profiles in
`config.yml` (under your OS config dir, or `$CRAWLSNAP_CONFIG_DIR`):

```bash
crawlsnap --profile staging auth login
crawlsnap --profile staging vectorsnap ip 8.8.8.8
```

## Exit codes

Designed for scripting:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic error |
| 3 | bad request (invalid indicator) |
| 4 | authentication error |
| 5 | quota exceeded |
| 6 | rate limited |
| 7 | not found (no data for the indicator) |
| 8 | subscription inactive |
| 10 | server error |
| 11 | request timed out |
| 12 | connection error |

## Shell completion

```bash
crawlsnap completion bash   # or zsh, fish, powershell
```

## License

MIT — see [LICENSE](LICENSE).
