#!/bin/bash
# --- Fenrir Ultimate Launcher ---

# 1. Setup paths
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
PROJECT_ROOT="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
cd "$PROJECT_ROOT"

# 2. Patch pyproject.toml
if [ -f "pyproject.toml" ]; then
    sed -i 's/python = ">=3.10, <3.1[0-9]"/python = ">=3.10"/' pyproject.toml
    sed -i 's/nvdlib = "\^1.1.1"/nvdlib = "*"/' pyproject.toml
    sed -i '/bleak =/d' pyproject.toml
fi

# 3. Environment check
if [ ! -d ".venv" ]; then
    echo "First-time setup: Building environment..."
    poetry config virtualenvs.in-project true
    poetry run pip install --upgrade pip
    poetry run pip install colorama nvdlib "androguard<4.0" python-nmap \
                           requests python-dotenv aiodns python-whois \
                           httpx paramiko scapy beautifulsoup4
fi

# 4. SILENCE WARNINGS: Create a fake bleak module so IotScanner doesn't complain
mkdir -p .venv/lib/python3.13/site-packages/bleak
touch .venv/lib/python3.13/site-packages/bleak/__init__.py

# 5. CODE PATCHES
# Fix the AttributeError by using a lambda for the after() call
sed -i 's/self.after(100, self.process_log_queue)/self.after(100, lambda: self.process_log_queue())/g' fenrir/fenrir_gui.py 2>/dev/null
sed -i 's/self.root.after(100, self.process_log_queue)/self.after(100, lambda: self.process_log_queue())/g' fenrir/fenrir_gui.py 2>/dev/null
# Fix LogRecord string error
sed -i 's/record + "\\n"/str(record) + "\\n"/g' fenrir/fenrir_gui.py 2>/dev/null

echo "Starting Fenrir..."
poetry run python3 -m fenrir.cli "$@"
