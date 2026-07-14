#!/usr/bin/env bash
# =============================================================================
# Fenrir Security Scanner — update_fenrir.sh
# Pulls latest source from GitHub and reinstalls dependencies.
# Uses system Python directly — no virtual environment.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[fenrir]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*"; }
hdr()     { echo -e "\n${BOLD}$*${NC}"; }

echo ""
hdr "=== Fenrir Update ==="
echo ""

# ── Deactivate any active venv so system Python is used ──────────────────────
deactivate 2>/dev/null || true
unset VIRTUAL_ENV
unset VIRTUAL_ENV_PROMPT

# ── Show Python being used ────────────────────────────────────────────────────
info "Python: $(python3 --version 2>&1)  at $(which python3)"

# ── Step 1: Git update ────────────────────────────────────────────────────────
hdr "Step 1: Pulling latest changes from GitHub"

if [ ! -d "$SCRIPT_DIR/.git" ]; then
    warn "No .git directory found — this is not a git clone."
    warn "To update: manually copy new files into $SCRIPT_DIR"
else
    # Show current state before doing anything
    LOCAL_BRANCH=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    info "Branch: $LOCAL_BRANCH"

    # Fetch from remote so we can compare without modifying anything yet
    info "Fetching from origin..."
    if ! git -C "$SCRIPT_DIR" fetch origin 2>&1; then
        warn "Fetch failed — check your network connection and GitHub credentials."
        warn "Continuing with local files."
    else
        # Show what's changed on the remote since our last pull
        BEHIND=$(git -C "$SCRIPT_DIR" rev-list HEAD..origin/"$LOCAL_BRANCH" --count 2>/dev/null || echo 0)
        AHEAD=$(git -C "$SCRIPT_DIR" rev-list origin/"$LOCAL_BRANCH"..HEAD --count 2>/dev/null || echo 0)

        info "Local is ${AHEAD} commit(s) ahead, ${BEHIND} commit(s) behind remote."

        if [ "$BEHIND" -eq 0 ]; then
            success "Already up to date — no new commits on remote."
        else
            # Check for uncommitted local changes that would block the pull
            if ! git -C "$SCRIPT_DIR" diff --quiet 2>/dev/null || \
               ! git -C "$SCRIPT_DIR" diff --cached --quiet 2>/dev/null; then
                warn "You have uncommitted local changes."
                warn "Stashing them temporarily so the pull can proceed..."
                git -C "$SCRIPT_DIR" stash push -m "fenrir-update-autostash-$(date +%Y%m%d-%H%M%S)"
                STASHED=1
            else
                STASHED=0
            fi

            # Pull: use rebase if ahead, merge otherwise
            if [ "$AHEAD" -gt 0 ]; then
                info "Local has commits not on remote — using rebase..."
                if git -C "$SCRIPT_DIR" pull --rebase origin "$LOCAL_BRANCH"; then
                    success "Rebased successfully."
                else
                    err "Rebase failed. Run: git rebase --abort && git pull origin $LOCAL_BRANCH"
                    # Pop stash before exiting
                    [ "$STASHED" -eq 1 ] && git -C "$SCRIPT_DIR" stash pop 2>/dev/null || true
                    exit 1
                fi
            else
                info "Fast-forwarding to latest..."
                if git -C "$SCRIPT_DIR" pull origin "$LOCAL_BRANCH"; then
                    success "Pull successful."
                else
                    err "Pull failed. Check for merge conflicts:"
                    git -C "$SCRIPT_DIR" status
                    [ "$STASHED" -eq 1 ] && git -C "$SCRIPT_DIR" stash pop 2>/dev/null || true
                    exit 1
                fi
            fi

            # Restore any stashed changes
            if [ "$STASHED" -eq 1 ]; then
                info "Restoring your local changes..."
                git -C "$SCRIPT_DIR" stash pop || \
                    warn "Could not restore stash — run: git stash pop"
            fi

            # Show a summary of what changed
            echo ""
            info "Files changed in this update:"
            git -C "$SCRIPT_DIR" diff --name-only HEAD~"$BEHIND" HEAD 2>/dev/null \
                | sed 's/^/  /' || true
        fi
    fi
fi

# ── Step 2: Clear Python bytecode cache ───────────────────────────────────────
hdr "Step 2: Clearing Python bytecode cache"
find "$SCRIPT_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true
success "__pycache__ cleared — Python will recompile from updated source."

# ── Step 3: Reinstall the Fenrir package ─────────────────────────────────────
hdr "Step 3: Reinstalling Fenrir package"
if pip3 install -e "$SCRIPT_DIR" --break-system-packages --quiet 2>/dev/null; then
    success "Package reinstalled (editable, system Python)."
elif pip3 install -e "$SCRIPT_DIR" --quiet 2>/dev/null; then
    success "Package reinstalled (editable)."
else
    # Last resort: ensure PYTHONPATH covers the project root
    warn "pip editable install failed — adding project root to PYTHONPATH."
    PTHFILE=$(python3 -c "import site; print(site.getusersitepackages())" 2>/dev/null)/fenrir.pth
    mkdir -p "$(dirname "$PTHFILE")"
    echo "$SCRIPT_DIR" > "$PTHFILE"
    warn "Added $SCRIPT_DIR to Python path via $PTHFILE"
fi

# ── Step 4: Verify import ─────────────────────────────────────────────────────
hdr "Step 4: Verifying Fenrir modules"
if python3 -c "
from fenrir.modules import MODULE_REGISTRY
print(f'  Modules loaded: {len(MODULE_REGISTRY)}')
for name in list(MODULE_REGISTRY.keys()):
    print(f'    ✓  {name}')
" 2>&1; then
    success "All modules verified."
else
    err "Module import failed — check the errors above."
    err "Try: python3 -c \"from fenrir.modules import MODULE_REGISTRY\""
    exit 1
fi

# ── Step 5: Rewrite run.sh to ensure it's current ────────────────────────────
hdr "Step 5: Refreshing run.sh"
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
success "run.sh refreshed."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
success "Update complete."
echo -e "  Launch:  ${BOLD}./run.sh --gui${NC}"
echo -e "  CLI:     ${BOLD}./run.sh <target>${NC}"
echo ""
