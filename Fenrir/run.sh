#!/bin/bash
# Find the actual directory where Fenrir is installed, even if called via symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
PROJECT_ROOT="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

# Move to the project root so Poetry can find pyproject.toml
cd "$PROJECT_ROOT"

# Run the application
poetry run python3 -m fenrir.cli "$@"
