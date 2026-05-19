#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Installing GistSafe...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create virtual environment
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

# Install package in editable mode
echo -e "${GREEN}Installing GistSafe and dependencies...${NC}"
pip install -e "$SCRIPT_DIR"

# Create .env if missing
ENV_FILE="$SCRIPT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    echo "# Add your GitHub token here" > "$ENV_FILE"
    echo "GITHUB_TOKEN=" >> "$ENV_FILE"
    echo -e "${YELLOW}Please add your GitHub token to $ENV_FILE${NC}"
fi

echo -e "\n${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}To start using GistSafe:${NC}"
echo -e "1. Add your GitHub token to $ENV_FILE"
echo -e "2. Run: gistsafe --help"

# Test the installation
if command -v gistsafe &>/dev/null; then
    echo -e "${GREEN}✓ gistsafe command is available${NC}"
else
    echo -e "${YELLOW}Note: gistsafe may not be on PATH yet. Restart your shell or run:${NC}"
    echo -e "  source $VENV_DIR/bin/activate"
fi
