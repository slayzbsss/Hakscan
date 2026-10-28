#!/usr/bin/env bash
# Build native Hakscan binaries (Go) - like nuclei. No runtime dependencies.
set -e
cd "$(dirname "$0")"
mkdir -p dist
b(){ GOOS=$1 GOARCH=$2 go build -trimpath -ldflags="-s -w" -o "dist/$3" . && echo "  dist/$3"; }
echo "Building..."
b linux   amd64 hakscan-linux-amd64
b linux   arm64 hakscan-linux-arm64
b darwin  amd64 hakscan-darwin-amd64
b darwin  arm64 hakscan-darwin-arm64
b windows amd64 hakscan-windows-amd64.exe
( cd dist && sha256sum * > SHA256SUMS )
echo "Done -> dist/"
