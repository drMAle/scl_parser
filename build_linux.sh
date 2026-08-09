#!/bin/bash

set -e

echo "========================================"
echo "SCL Analyzer - Linux Build"
echo "========================================"

echo
echo "[1/4] Creating virtual environment..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi

echo
echo "[2/4] Activating virtual environment..."

source .venv/bin/activate

echo
echo "[3/4] Installing dependencies..."

python -m pip install --upgrade pip
pip install -r requirements.txt

echo
echo "[4/4] Building executable..."

pyinstaller \
    --noconfirm \
    --clean \
    --onefile \
    --windowed \
    --name SCLAnalyzer \
    main.py

echo
echo "========================================"
echo "Build completed."
echo "Executable:"
echo "dist/SCLAnalyzer"
echo "========================================"
