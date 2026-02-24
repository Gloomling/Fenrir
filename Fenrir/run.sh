#!/bin/bash
#
# Fenrir Runner Script
# This script runs the Fenrir application using the correct Python interpreter
# from the project's Poetry virtual environment, bypassing any system path issues.
#
# It passes all command-line arguments directly to the Fenrir CLI.
# Example: ./run.sh --gui
# Example: ./run.sh 192.168.56.103 -sV

# Find the full path to the python executable inside the virtual environment
PYTHON_EXEC=$(poetry env info --path)/bin/python

# Check if the executable exists
if [ ! -f "$PYTHON_EXEC" ]; then
    echo "Error: Could not find the Python executable in the virtual environment."
    echo "Please run './update_fenrir.sh' first to set up the environment."
    exit 1
fi

# Run the Fenrir CLI module with the correct python, passing all arguments
"$PYTHON_EXEC" -m fenrir.cli "$@"
