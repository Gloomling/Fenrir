#!/bin/bash
#
# Fenrir Updater Script (Robust Version)
# This script automates updating Fenrir by finding and using the correct
# Python interpreter from the project's virtual environment.
#
# Usage: ./update_fenrir.sh

# --- Style Functions for better output ---
bold=$(tput bold)
normal=$(tput sgr0)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
red=$(tput setaf 1)

# --- Error Logging ---
error_log=""

echo "${bold}${green}--- Starting Fenrir Update ---${normal}"

# 1. Check for prerequisite commands
if ! command -v git &> /dev/null || ! command -v poetry &> /dev/null; then
    echo -e "${bold}${red}Fatal Error: 'git' or 'poetry' is not installed. Please install them to continue.${normal}"
    exit 1
fi

# 2. Fetch latest changes from the repository
echo -e "\n${yellow}Step 1: Pulling latest changes from Git...${normal}"
git pull
if [ $? -ne 0 ]; then
    echo -e "${bold}${yellow}Warning: 'git pull' failed. This might be because you are not in a git repository. Continuing...${normal}"
    error_log+=" - 'git pull' failed to fetch updates.\n"
else
    echo "Git pull successful."
fi

# 3. Configure the project to use a compatible Python version
echo -e "\n${yellow}Step 2: Configuring project's Python 3.12 environment...${normal}"
poetry env use python3.12 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${bold}${red}Error: Could not configure the Python 3.12 environment.${normal}"
    echo "Please ensure Python 3.12 is installed and accessible."
    error_log+=" - Failed to set Python 3.12 for the project.\n"
fi

# 4. Activate the virtual environment for this script's session
VENV_PATH=$(poetry env info --path)
if [ -d "$VENV_PATH" ]; then
    echo "Activating virtual environment for installation..."
    export PATH="$VENV_PATH/bin:$PATH"
else
    echo -e "${bold}${red}Error: Could not find the virtual environment path.${normal}"
    error_log+=" - Virtual environment not found.\n"
fi


# 5. Lock and Install dependencies
echo -e "\n${yellow}Step 3: Resolving and installing dependencies...${normal}"
# Now that the PATH is set, the correct python and poetry commands will be used.
poetry lock
if [ $? -ne 0 ]; then
    echo -e "${bold}${red}Error: 'poetry lock' failed. There is a dependency conflict in pyproject.toml.${normal}"
    error_log+=" - 'poetry lock' failed to resolve dependencies.\n"
else
    echo "Dependencies locked successfully. Now installing..."
    poetry install
    if [ $? -ne 0 ]; then
        echo -e "${bold}${red}Error: 'poetry install' failed. The application may not be runnable.${normal}"
        error_log+=" - 'poetry install' failed.\n"
    fi
fi

# 6. Create a robust runner script
echo -e "\n${yellow}Step 4: Creating a reliable run script (run.sh)...${normal}"
cat << EOF > run.sh
#!/bin/bash
# This script runs the Fenrir application using the correct virtual environment.
"$(poetry env info --path)/bin/python" -m fenrir.cli "\$@"
EOF
chmod +x run.sh
echo "Created 'run.sh'. Use this to start the application."


# 7. Final Summary
echo -e "\n${bold}${green}--- Fenrir Update Process Finished ---${normal}"

if [ -n "$error_log" ]; then
    echo -e "${bold}${red}Update completed with errors. Please review the summary below:${normal}"
    echo -e "${red}${error_log}${normal}"
    echo "The application might be in an unstable state."
else
    echo -e "${bold}${green}Fenrir has been successfully updated!${normal}"
    echo "You can now run the scanner with: ${bold}./run.sh --help${normal}"
fi
