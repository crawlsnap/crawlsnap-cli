#!/bin/sh
# CrawlSnap CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/crawlsnap/crawlsnap-cli/main/install.sh | sh
#
# Environment overrides:
#   CRAWLSNAP_VERSION   release tag to install (default: latest)
#   CRAWLSNAP_BIN_DIR   install directory (default: /usr/local/bin, or ~/.local/bin without write access)
set -eu

REPO="crawlsnap/crawlsnap-cli"
BINARY="crawlsnap"

err() { printf 'error: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }
need uname
need tar

# Pick a downloader.
if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1"; }
  dlo() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO- "$1"; }
  dlo() { wget -qO "$2" "$1"; }
else
  err "need curl or wget"
fi

# Detect OS.
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux) os=linux ;;
  darwin) os=darwin ;;
  *) err "unsupported OS: $os (use Homebrew, Scoop, or download from the releases page)" ;;
esac

# Detect arch.
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

# Resolve version.
version="${CRAWLSNAP_VERSION:-}"
if [ -z "$version" ]; then
  info "Resolving latest release…"
  version=$(dl "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/')
  [ -n "$version" ] || err "could not determine latest version; set CRAWLSNAP_VERSION"
fi
# Archive names are versioned without the leading "v".
ver_no_v="${version#v}"

asset="${BINARY}_${ver_no_v}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${version}/${asset}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

info "Downloading ${asset}…"
dlo "$url" "$tmp/$asset" || err "download failed: $url"
tar -xzf "$tmp/$asset" -C "$tmp" || err "extract failed"
[ -f "$tmp/$BINARY" ] || err "binary not found in archive"
chmod +x "$tmp/$BINARY"

# Choose an install dir.
bindir="${CRAWLSNAP_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    bindir=/usr/local/bin
  else
    bindir="$HOME/.local/bin"
  fi
fi
mkdir -p "$bindir"

if mv "$tmp/$BINARY" "$bindir/$BINARY" 2>/dev/null; then
  :
elif command -v sudo >/dev/null 2>&1; then
  info "Elevating with sudo to install into $bindir…"
  sudo mv "$tmp/$BINARY" "$bindir/$BINARY"
else
  err "cannot write to $bindir; set CRAWLSNAP_BIN_DIR to a writable path"
fi

info ""
info "Installed ${BINARY} ${version} to ${bindir}/${BINARY}"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) info "Note: $bindir is not on your PATH. Add it to use '${BINARY}' directly." ;;
esac
