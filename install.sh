#!/bin/sh
# Hakscan installer — one-liner:
#   curl -fsSL https://raw.githubusercontent.com/slayzbsss/Hakscan/main/install.sh | bash
#
# Downloads the latest prebuilt Hakscan binary for your OS/arch and installs it
# to a directory already on your PATH. No Go toolchain required.
#
# Options (env vars):
#   HAKSCAN_VERSION=v4.6     install a specific version instead of the latest
#   HAKSCAN_INSTALL_DIR=...  force the install directory

set -eu

REPO="slayzbsss/Hakscan"
BIN="hakscan"

err()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$1"; }

# --- dependencies ---------------------------------------------------------
command -v curl >/dev/null 2>&1 || err "curl is required but not installed."
command -v tar  >/dev/null 2>&1 || err "tar is required but not installed."

# --- detect OS ------------------------------------------------------------
os=$(uname -s)
case "$os" in
  Linux)  os="linux" ;;
  Darwin) os="darwin" ;;
  *) err "unsupported OS '$os'. On Windows, download the .zip from https://github.com/$REPO/releases/latest" ;;
esac

# --- detect arch ----------------------------------------------------------
arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture '$arch'." ;;
esac

# --- resolve version ------------------------------------------------------
if [ "${HAKSCAN_VERSION:-}" = "" ]; then
  info "Resolving latest release..."
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name":' | head -n1 | cut -d'"' -f4)
  [ -n "$tag" ] || err "could not resolve the latest version from GitHub."
else
  tag="$HAKSCAN_VERSION"
fi
ver=${tag#v}   # strip leading 'v' -> matches asset filename
info "Installing hakscan $tag ($os/$arch)"

# --- download + extract ---------------------------------------------------
asset="${BIN}_${ver}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$asset"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

info "Downloading $asset"
curl -fSL --progress-bar "$url" -o "$tmp/$asset" \
  || err "download failed: $url"
tar -xzf "$tmp/$asset" -C "$tmp" \
  || err "failed to extract $asset"
[ -f "$tmp/$BIN" ] || err "binary '$BIN' not found inside the archive."
chmod +x "$tmp/$BIN"

# --- choose install dir ---------------------------------------------------
if [ "${HAKSCAN_INSTALL_DIR:-}" != "" ]; then
  dir="$HAKSCAN_INSTALL_DIR"
  mkdir -p "$dir"
  mv "$tmp/$BIN" "$dir/$BIN"
elif [ -w /usr/local/bin ]; then
  dir="/usr/local/bin"
  mv "$tmp/$BIN" "$dir/$BIN"
elif command -v sudo >/dev/null 2>&1; then
  dir="/usr/local/bin"
  info "Installing to $dir (sudo)"
  sudo mv "$tmp/$BIN" "$dir/$BIN"
else
  dir="$HOME/.local/bin"
  mkdir -p "$dir"
  mv "$tmp/$BIN" "$dir/$BIN"
fi

# --- done -----------------------------------------------------------------
info "Installed to $dir/$BIN"

# warn if the chosen dir is not on PATH
case ":$PATH:" in
  *":$dir:"*) ;;
  *) printf '\033[33mnote:\033[0m %s is not on your PATH. Add it with:\n  export PATH="%s:$PATH"\n' "$dir" "$dir" ;;
esac

if command -v hakscan >/dev/null 2>&1; then
  info "$(hakscan version 2>/dev/null || echo "hakscan ready")"
  printf '\033[32m✓ Hakscan installed. Run: hakscan -h\033[0m\n'
else
  printf '\033[32m✓ Installed. Open a new shell (or fix PATH above), then run: hakscan -h\033[0m\n'
fi
