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

# --- Style Functions for better output ---
bold=$(tput bold)
normal=$(tput sgr0)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
red=$(tput setaf 1)

# --- Configuration ---
# !!! IMPORTANT !!!
# Replace this URL with the actual URL of your Fenrir GitHub repository.
REPO_URL="https://github.com/kj-droid/Project_fenrirv2.git"
PROJECT_DIR="Project_fenrirv2"
COMMAND_NAME="fenrir"

echo "${bold}${green}--- Starting Fenrir Installation ---${normal}"

# 1. Check for and install prerequisite commands
echo "\n${yellow}Step 1: Checking for prerequisites (git, poetry)...${normal}"

# Check for Git
if ! command -v git &> /dev/null; then
    echo "Git not found. Attempting to install..."
    sudo apt-get update && sudo apt-get install git -y
    if [ $? -ne 0 ]; then
        echo "${bold}${red}Fatal Error: Failed to install git. Please install it manually and run this script again.${normal}"
        exit 1
    fi
    echo "${green}Git installed successfully.${normal}"
else
    echo "Git is already installed."
fi

# Check for Poetry
if ! command -v poetry &> /dev/null; then
    echo "Poetry not found. Attempting to install..."
    # Poetry installer requires curl
    if ! command -v curl &> /dev/null; then
        echo "curl not found. Attempting to install..."
        sudo apt-get update && sudo apt-get install curl -y
        if [ $? -ne 0 ]; then
            echo "${bold}${red}Fatal Error: Failed to install curl. Please install it manually and run this script again.${normal}"
            exit 1
        fi
    fi
    curl -sSL https://install.python-poetry.org | python3 -
    if [ $? -ne 0 ]; then
        echo "${bold}${red}Fatal Error: Failed to install Poetry. Please try installing it manually from https://python-poetry.org/docs/${normal}"
        exit 1
    fi
    # Add poetry to the current session's PATH to ensure it's found immediately
    export PATH="$HOME/.local/bin:$PATH"
    echo "${green}Poetry installed successfully.${normal}"
else
    echo "Poetry is already installed."
fi


# 2. Clone the repository
if [ -d "$PROJECT_DIR" ]; then
    echo "\n${yellow}Project directory '${PROJECT_DIR}' already exists. Skipping clone.${normal}"
else
    echo "\n${yellow}Step 2: Cloning repository from GitHub...${normal}"
    git clone "$REPO_URL"
    if [ $? -ne 0 ]; then
        echo "${bold}${red}Error: 'git clone' failed. Please check the repository URL and your connection.${normal}"
        exit 1
    fi
fi

# 3. Navigate into the project directory
cd "$PROJECT_DIR" || exit

# 4. Run the update/install script
echo "\n${yellow}Step 3: Setting up environment and installing dependencies...${normal}"
# Ensure the update script is executable
if [ -f "update_fenrir.sh" ]; then
    chmod +x update_fenrir.sh
    ./update_fenrir.sh
    if [ $? -ne 0 ]; then
        echo "${bold}${red}Error: The update script failed. Please check the output above for errors.${normal}"
        exit 1
    fi
else
    echo "${bold}${red}Error: 'update_fenrir.sh' not found in the repository.${normal}"
    exit 1
fi

# 5. Create the system-wide command
echo "\n${yellow}Step 4: Creating the system-wide '${COMMAND_NAME}' command...${normal}"
RUN_SCRIPT_PATH="$(pwd)/run.sh"
INSTALL_PATH="/usr/local/bin/$COMMAND_NAME"

if [ -L "$INSTALL_PATH" ]; then
    echo "Command '${COMMAND_NAME}' already exists. Removing old link."
    sudo rm "$INSTALL_PATH"
fi

echo "Creating symbolic link from ${RUN_SCRIPT_PATH} to ${INSTALL_PATH}"
# Use sudo to create the link in a system-wide directory
sudo ln -s "$RUN_SCRIPT_PATH" "$INSTALL_PATH"

if [ $? -ne 0 ]; then
    echo "${bold}${red}Error: Failed to create symbolic link. This usually requires sudo privileges.${normal}"
    echo "Please try running the command again with sudo, or create the link manually:"
    echo "sudo ln -s ${RUN_SCRIPT_PATH} ${INSTALL_PATH}"
    exit 1
fi

echo "Symbolic link created successfully."

# 6. Final Summary
echo "\n${bold}${green}--- Fenrir Installation Complete! ---${normal}"
echo "You can now run the scanner from anywhere on your system by simply typing:"
echo "${bold}${COMMAND_NAME} --help${normal}"
