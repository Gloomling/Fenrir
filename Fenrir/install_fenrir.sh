#!/bin/bash
#
# Fenrir All-in-One Installer
# This script clones the Fenrir repository, installs prerequisites, sets up the
# environment, and makes the 'fenrir' command available system-wide.
#
# Usage:
# 1. Save this script as install_fenrir.sh
# 2. Make it executable: chmod +x install_fenrir.sh
# 3. Run it: ./install_fenrir.sh


# --- Style Functions ---
bold=$(tput bold)
normal=$(tput sgr0)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
red=$(tput setaf 1)

# --- Configuration ---
REPO_URL="https://github.com/kj-droid/Project_fenrirv2.git"
PROJECT_DIR="Project_fenrirv2"
COMMAND_NAME="fenrir"

echo "${bold}${green}--- Starting Fenrir Installation ---${normal}"

# 1. Check for and install prerequisite system commands
echo -e "\n${yellow}Step 1: Checking for system prerequisites (git, poetry, nmap, tkinter)...${normal}"

# Standard Apt Dependencies
echo "Updating system and installing base dependencies..."
sudo apt-get update
sudo apt-get install -y git curl nmap python3-tk python3-pip

# 2. Check for Poetry
if ! command -v poetry &> /dev/null; then
    echo "Poetry not found. Installing..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "Poetry is already installed."
fi

# 3. Clone the repository
if [ -d "$PROJECT_DIR" ]; then
    echo -e "\n${yellow}Project directory exists. Skipping clone.${normal}"
else
    echo -e "\n${yellow}Step 2: Cloning repository...${normal}"
    git clone "$REPO_URL"
    cd "$PROJECT_DIR" || exit
fi

# 3. Navigate into the project directory
cd "$PROJECT_DIR" || exit

# --- NEW: AUTOMATED ENVIRONMENT FIXES ---
echo -e "\n${yellow}Step 3: Patching Python version constraints for compatibility...${normal}"

# Use sed to change (>=3.10, <3.13) to (>=3.10) to allow Python 3.13+
if [ -f "pyproject.toml" ]; then
    sed -i 's/python = ">=3.10, <3.13"/python = ">=3.10"/' pyproject.toml
    echo "${green}Version constraint patched for Python 3.13+.${normal}"
fi

echo -e "\n${yellow}Step 4: Building the virtual environment automatically...${normal}"
# Configure poetry to create the env inside the project folder for easier management
poetry config virtualenvs.in-project true
poetry install --no-interaction

# Add the specific dependencies we discussed earlier
poetry add nvdlib "androguard<4.0" python-nmap --no-interaction
# ---------------------------------------

# 4. Install specific Python dependencies via Poetry
# This fixes the 'androguard' and 'nvdlib' issues globally within the project env
echo -e "\n${yellow}Step 3: Injecting extra dependencies (nvdlib, androguard v3)...${normal}"

# We use 'poetry add' to ensure these are locked into the Fenrir environment
# We specify androguard < 4.0 to fix the 'bytecodes' error
poetry add nvdlib "androguard<4.0" python-nmap

# 5. Run the existing update/install script
echo -e "\n${yellow}Step 4: Running project setup script...${normal}"
if [ -f "update_fenrir.sh" ]; then
    chmod +x update_fenrir.sh
    ./update_fenrir.sh
else
    echo "${bold}${red}Error: 'update_fenrir.sh' not found.${normal}"
    exit 1
fi

# 6. Create the system-wide command
echo -e "\n${yellow}Step 5: Creating the system-wide '${COMMAND_NAME}' command...${normal}"
RUN_SCRIPT_PATH="$(pwd)/run.sh"
INSTALL_PATH="/usr/local/bin/$COMMAND_NAME"

[ -L "$INSTALL_PATH" ] && sudo rm "$INSTALL_PATH"
sudo ln -s "$RUN_SCRIPT_PATH" "$INSTALL_PATH"

# 7. Final Summary
echo -e "\n${bold}${green}--- Fenrir Installation Complete! ---${normal}"
echo "Dependencies installed: nmap, python3-tk, nvdlib, androguard (v3.x)."
echo "You can now run: ${bold}${COMMAND_NAME} --gui${normal}"
