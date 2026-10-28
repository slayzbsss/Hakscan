#!/usr/bin/env bash
# Build a standalone single-file Hakscan binary (like nuclei) with PyInstaller.
# Result: dist/hakscan  (no Python needed to run it)
set -e
cd "$(dirname "$0")"
python3 -m venv .buildenv
./.buildenv/bin/pip install -q --upgrade pip pyinstaller pyyaml
./.buildenv/bin/pyinstaller --onefile --name hakscan --hidden-import yaml --console hakscan.py
echo
echo "Done -> dist/hakscan"
./dist/hakscan version
