#!/usr/bin/env bash
# =============================================================================
# Fenrir Security Scanner — update_fenrir.sh
# Updates dependencies using system Python directly. No virtual environment.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[fenrir]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*"; }

echo ""
info "=== Fenrir Update ==="
echo ""

# ── Ensure no venv is active ──────────────────────────────────────────────────
deactivate 2>/dev/null || true
unset VIRTUAL_ENV
unset VIRTUAL_ENV_PROMPT

# ── Confirm Python version ────────────────────────────────────────────────────
PYTHON=$(python3 --version 2>&1)
info "Using: $PYTHON at $(which python3)"

# ── Step 1: Git pull ──────────────────────────────────────────────────────────
info "Step 1: Pulling latest changes from Git..."
if git pull origin main; then
    success "Git pull successful."
else
    warn "Git pull failed or nothing to pull — continuing with local files."
fi

# ── Step 2: Install/update dependencies ───────────────────────────────────────
info "Step 2: Installing dependencies with system pip..."

pip3 install -e . --break-system-packages --quiet && \
    success "Package installed (editable)." || \
    err "pip install failed — check pyproject.toml for conflicts."

# ── Step 3: Verify import ─────────────────────────────────────────────────────
info "Step 3: Verifying Fenrir can be imported..."
if python3 -c "from fenrir.modules import MODULE_REGISTRY; print(f'  Modules: {len(MODULE_REGISTRY)}')" 2>&1; then
    success "Import OK."
else
    err "Import failed — check the errors above."
fi

# ── Step 4: Write run.sh ──────────────────────────────────────────────────────
info "Step 4: Writing run.sh..."
cat > "$SCRIPT_DIR/run.sh" << 'RUNSCRIPT'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
deactivate 2>/dev/null || true
unset VIRTUAL_ENV
unset VIRTUAL_ENV_PROMPT
exec python3 -m fenrir.cli "$@"
RUNSCRIPT
chmod +x "$SCRIPT_DIR/run.sh"
success "run.sh written."

echo ""
success "Update complete. Launch with:  ./run.sh --gui"
echo ""
