#!/bin/bash
# One-step setup of aif-insights on a Mac:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/BrainMatterStudios/AIFactory/main/insights/install.sh)"
# Installs pipx if needed (via Homebrew), installs aif-insights, then runs the
# interactive `aif-insights setup`. Set AIF_INSIGHTS_REF to install another branch.
set -euo pipefail

REF="${AIF_INSIGHTS_REF:-main}"
SPEC="aif-insights[r2] @ git+https://github.com/BrainMatterStudios/AIFactory@${REF}#subdirectory=insights"

if ! command -v pipx >/dev/null 2>&1; then
  if ! command -v brew >/dev/null 2>&1; then
    echo "pipx is missing and Homebrew is not installed. Install Homebrew from https://brew.sh, then rerun." >&2
    exit 1
  fi
  echo "Installing pipx with Homebrew…"
  brew install pipx
  pipx ensurepath >/dev/null
fi

echo "Installing aif-insights from ${REF}…"
pipx install --force "$SPEC"

BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
exec "$BIN/aif-insights" setup
