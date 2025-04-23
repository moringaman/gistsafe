#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Installing GistSafe...${NC}"

# Detect the shell
SHELL_NAME=$(basename "$SHELL")
SHELL_CONFIG_FILE=""
case "$SHELL_NAME" in
    "bash")
        SHELL_CONFIG_FILE="$HOME/.bashrc"
        ;;
    "zsh")
        SHELL_CONFIG_FILE="$HOME/.zshrc"
        ;;
    *)
        echo -e "${RED}Unsupported shell: $SHELL_NAME${NC}"
        echo -e "${YELLOW}Please manually add the GistSafe installation directory to your PATH${NC}"
        ;;
esac

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create virtual environment directory if it doesn't exist
VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${GREEN}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install requirements
echo -e "${GREEN}Installing dependencies...${NC}"
pip install -r requirements.txt

# Create bin directory if it doesn't exist
mkdir -p "$SCRIPT_DIR/bin"

# Create wrapper script
WRAPPER_SCRIPT="$SCRIPT_DIR/bin/gistsafe"
cat > "$WRAPPER_SCRIPT" << EOL
#!/bin/bash
SCRIPT_DIR="\$( cd "\$( dirname "\${BASH_SOURCE[0]}" )" && pwd )"
VENV_DIR="\$(dirname \$SCRIPT_DIR)/.venv"
source "\$VENV_DIR/bin/activate"
python "\$(dirname \$SCRIPT_DIR)/gistsafe.py" "\$@"
EOL

# Make wrapper script executable
chmod +x "$WRAPPER_SCRIPT"

# Add to PATH if not already there
if [ -n "$SHELL_CONFIG_FILE" ]; then
    if ! grep -q "export PATH=\"$SCRIPT_DIR/bin:\$PATH\"" "$SHELL_CONFIG_FILE"; then
        echo -e "${GREEN}Adding GistSafe to PATH...${NC}"
        echo "" >> "$SHELL_CONFIG_FILE"
        echo "# GistSafe PATH" >> "$SHELL_CONFIG_FILE"
        echo "export PATH=\"$SCRIPT_DIR/bin:\$PATH\"" >> "$SHELL_CONFIG_FILE"
        
        echo -e "${GREEN}GistSafe has been installed successfully!${NC}"
        echo -e "${YELLOW}Please run: source $SHELL_CONFIG_FILE${NC}"
    else
        echo -e "${GREEN}GistSafe is already in PATH${NC}"
    fi
else
    echo -e "${YELLOW}Please add the following line to your shell configuration:${NC}"
    echo "export PATH=\"$SCRIPT_DIR/bin:\$PATH\""
fi

# Create .env file if it doesn't exist
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
echo -e "2. Run: source $SHELL_CONFIG_FILE"
echo -e "3. Try: gistsafe --help" 