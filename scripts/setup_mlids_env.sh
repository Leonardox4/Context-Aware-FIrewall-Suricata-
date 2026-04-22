#!/usr/bin/env bash
#
# setup_mlids_env.sh — Reproducible environment setup for the Model2_development ML IDS pipeline.
#
# Prepares an Ubuntu/Debian system to run the pipeline: system packages, Python venv,
# and dependencies from docs/requirements.txt. Idempotent (safe to run multiple times).
#
# Usage: run from Model2_development project root, or from anywhere with:
#   ./scripts/setup_mlids_env.sh
#   bash scripts/setup_mlids_env.sh
#
# Constraints:
#   - Uses docs/requirements.txt exactly for Python deps (do not modify that file).
#   - Does not start or configure Suricata; only ensures the binary is available.
#

set -e

# -----------------------------------------------------------------------------
# Project root and paths
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Project root: one level up from scripts/
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REQUIREMENTS_FILE="$PROJECT_ROOT/docs/requirements.txt"
VENV_DIR="$PROJECT_ROOT/.venv"

cd "$PROJECT_ROOT"

echo "[setup] Project root: $PROJECT_ROOT"

# -----------------------------------------------------------------------------
# 1. Detect OS (Ubuntu/Debian)
# -----------------------------------------------------------------------------
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        ubuntu|debian)
            echo "[setup] Detected $ID"
            ;;
        *)
            echo "[setup] WARNING: This script targets Ubuntu/Debian. You have $ID. Proceeding anyway."
            ;;
    esac
else
    echo "[setup] WARNING: Cannot read /etc/os-release; assuming Debian-like."
fi

# -----------------------------------------------------------------------------
# 2. System dependencies (only those justified by the codebase)
#
# Audit summary:
#   - inference/enforcement_engine.py: calls iptables and nft (optional backends).
#   - Pipeline consumes eve.json produced by Suricata; Suricata not invoked by code.
#   - Python packages: from docs/requirements.txt (numpy, pandas, scikit-learn, etc.).
#   - build-essential: needed for building Python wheels (e.g. numpy).
#   - python3, python3-pip, python3-venv: core for venv and pip install.
#   - iptables: for --enforcement iptables.
#   - nftables: provides nft for --enforcement nftables.
#   - suricata: to produce eve.json; script only ensures binary available.
# -----------------------------------------------------------------------------
install_system_deps() {
    if ! command -v apt-get &>/dev/null; then
        echo "[setup] apt-get not found; skipping system package installation."
        return 0
    fi

    local pkgs=(
        python3
        python3-pip
        python3-venv
        build-essential
        iptables
        nftables
    )

    echo "[setup] Ensuring system packages are installed..."
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update -qq
    sudo apt-get install -y "${pkgs[@]}"
}

install_system_deps

# -----------------------------------------------------------------------------
# 3. Suricata: check and install if missing (do not start or configure)
# -----------------------------------------------------------------------------
if ! command -v suricata &>/dev/null; then
    echo "[setup] Suricata not found. Installing suricata..."
    export DEBIAN_FRONTEND=noninteractive
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y suricata || true
    fi
else
    echo "[setup] Suricata already installed: $(command -v suricata)"
fi

if ! command -v suricata &>/dev/null; then
    echo "[setup] WARNING: Suricata could not be installed. You can still run the pipeline on existing eve.json files."
fi

# -----------------------------------------------------------------------------
# 4. Python version check (recommend 3.8+)
# -----------------------------------------------------------------------------
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0")
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo "0")
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo "0")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo "[setup] WARNING: Python $PYTHON_VERSION detected. Python 3.8+ is recommended."
else
    echo "[setup] Python version: $PYTHON_VERSION"
fi

# -----------------------------------------------------------------------------
# 5. Virtual environment: create if missing or broken (idempotent)
# A copied or relocated .venv can break (e.g. "No module named 'encodings'").
# -----------------------------------------------------------------------------
if [ -d "$VENV_DIR" ]; then
    if ! "$VENV_DIR/bin/python3" -c "import sys" 2>/dev/null; then
        echo "[setup] Existing venv is broken (e.g. copied from another machine). Removing and recreating..."
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "[setup] Creating virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
else
    echo "[setup] Virtual environment already exists and is valid: $VENV_DIR"
fi

# Use the venv's Python by full path for all pip/python calls (avoids PEP 668
# "externally-managed-environment" on Debian/Ubuntu when system python3 is in PATH)
VENV_PYTHON="$VENV_DIR/bin/python3"

# -----------------------------------------------------------------------------
# 6. Python dependencies from docs/requirements.txt exactly
# -----------------------------------------------------------------------------
if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo "[setup] ERROR: $REQUIREMENTS_FILE not found. Cannot install Python dependencies."
    exit 1
fi

echo "[setup] Upgrading pip in venv..."
"$VENV_PYTHON" -m pip install --upgrade pip -q

echo "[setup] Installing Python dependencies from docs/requirements.txt ..."
"$VENV_PYTHON" -m pip install -r "$REQUIREMENTS_FILE"

# -----------------------------------------------------------------------------
# 7. Project validation: required directories
# -----------------------------------------------------------------------------
REQUIRED_DIRS="inference models ingestion utils training"
MISSING=""
for d in $REQUIRED_DIRS; do
    if [ ! -d "$PROJECT_ROOT/$d" ]; then
        MISSING="$MISSING $d"
    fi
done

if [ -n "$MISSING" ]; then
    echo "[setup] ERROR: Required directories are missing:$MISSING"
    exit 1
fi
echo "[setup] Required directories present: inference, models, ingestion, utils, training."

# Optional: artifacts directory (trained models)
if [ ! -d "$PROJECT_ROOT/artifacts" ]; then
    echo "[setup] NOTE: Directory 'artifacts' not found. Create it and add trained models (or run training) before inference."
fi

# -----------------------------------------------------------------------------
# 8. Quick sanity check: Python can load pipeline modules (no sklearn needed for import check)
# -----------------------------------------------------------------------------
echo "[setup] Verifying pipeline imports..."
if "$VENV_PYTHON" -c "
from pathlib import Path
import sys
sys.path.insert(0, '$PROJECT_ROOT')
from ingestion.unified_schema import FEATURE_NAMES
from models.risk_engine import RiskEngine
assert len(FEATURE_NAMES) == 24, 'FEATURE_NAMES length'
print('  ingestion + risk_engine OK')
" 2>/dev/null; then
    echo "[setup] Pipeline module check passed."
else
    echo "[setup] WARNING: Pipeline import check failed (e.g. missing deps). Activate venv and run: $VENV_PYTHON -m pip install -r docs/requirements.txt"
fi

# -----------------------------------------------------------------------------
# 9. Success message and run instructions
# -----------------------------------------------------------------------------
echo ""
echo "------------------------------------------------------------------------------"
echo "Environment ready."
echo "------------------------------------------------------------------------------"
echo ""
echo "Activate with:"
echo "  source .venv/bin/activate"
echo ""
echo "Run ML IDS pipeline:"
echo "  python inference/runtime_scoring.py --help"
echo ""
echo "Example (file-based inference with artifacts in ./artifacts):"
echo "  python inference/runtime_scoring.py --artifacts artifacts --input path/to/eve.json --output-dir logs"
echo ""
echo "Example (real-time tail mode):"
echo "  python inference/runtime_scoring.py --artifacts artifacts --input /var/log/suricata/eve.json --output-dir logs --tail"
echo ""
