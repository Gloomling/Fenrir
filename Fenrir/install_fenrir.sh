#!/bin/bash
# Fenrir All-in-One Installer

# --- Style Functions ---
bold=$(tput bold); 
normal=$(tput sgr0); 
green=$(tput setaf 2); 
yellow=$(tput setaf 3); 
red=$(tput setaf 1)

# --- Configuration ---
REPO_URL="https://github.com/kj-droid/Project_fenrirv2.git"
PROJECT_DIR="Project_fenrirv2"
COMMAND_NAME="fenrir"

echo "${bold}${green}--- Starting Fenrir Installation ---${normal}"

# 1. System Prerequisites
echo -e "\n${yellow}Step 1: Installing system prerequisites...${normal}"
sudo apt-get update
sudo apt-get install -y git curl nmap python3-tk python3-pip python3-full

# 2. Poetry Installation
if ! command -v poetry &> /dev/null; then
    echo "Poetry not found. Installing..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "Poetry is already installed."
fi

# 3. Clone Repository
if [ -d "$PROJECT_DIR" ]; then
    echo -e "\n${yellow}Project directory exists. Updating...${normal}"
    cd "$PROJECT_DIR" && git pull && cd ..
else
    echo -e "\n${yellow}Step 2: Cloning repository...${normal}"
    git clone "$REPO_URL"
fi

cd "$PROJECT_DIR" || exit

# 4. Patch Python Version & Build Environment
echo -e "\n${yellow}Step 3: Auto-patching Python 3.13 constraints & building env...${normal}"
# This removes the <3.13 cap that causes your error
if [ -f "pyproject.toml" ]; then
    sed -i 's/python = ">=3.10, <3.13"/python = ">=3.10"/' pyproject.toml
fi

poetry config virtualenvs.in-project true
poetry install --no-interaction

# 5. Inject Scanning Dependencies
echo -e "\n${yellow}Step 4: Injecting scanning modules (nvdlib, androguard v3)...${normal}"
poetry add nvdlib "androguard<4.0" python-nmap --no-interaction

# 6. Set up System Command
echo -e "\n${yellow}Step 5: Creating system-wide '${COMMAND_NAME}' command...${normal}"
chmod +x run.sh
INSTALL_PATH="/usr/local/bin/$COMMAND_NAME"
sudo ln -sf "$(pwd)/run.sh" "$INSTALL_PATH"

echo -e "\n${bold}${green}--- Installation Complete! Run: ${COMMAND_NAME} --gui ---${normal}"
