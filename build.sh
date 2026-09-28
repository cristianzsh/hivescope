#!/usr/bin/env bash

set -e
cd "$(dirname "$0")"

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt pyinstaller

python3 -m PyInstaller --noconfirm --clean --onefile --windowed \
    --name HiveScope \
    --collect-submodules Crypto \
    --icon "hivescope/assets/icon.png" \
    --add-data "hivescope/assets/icon.png:hivescope/assets" \
    --add-data "hivescope/assets/icon.ico:hivescope/assets" \
    HiveScope.py

echo
echo "Build complete -> dist/HiveScope"
