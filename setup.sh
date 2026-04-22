#!/usr/bin/env bash
set -euo pipefail

# Model2_development — clean bootstrap for a shipped tree (minimal host assumptions).
#
# Default behavior:
#   - Removes existing .venv (if present) and creates a fresh virtualenv
#   - Upgrades pip, installs docs/requirements.txt + maturin + patchelf
#   - Installs Rust stable via rustup if cargo is missing; otherwise rustup update stable
#   - Builds PyO3 extension (eve_extractor) with maturin develop --release
#
# Optional:
#   --keep-venv     Do not delete .venv (incremental pip / faster re-run)
#   SKIP_BUILD=1    Skip Rust build (Python-only; eve_extractor will be missing)
#
# Host prerequisites:
#   - python3 (3.10+ recommended) — only hard requirement the script cannot install
#
# When SKIP_BUILD=0, a C linker (gcc/clang) is required to build the Rust extension.
# With AUTO_INSTALL_SYSTEM=1 (default on Linux), the script tries to install build tools
# via the distro package manager (apt/dnf/yum/pacman) using sudo when needed.
# Set AUTO_INSTALL_SYSTEM=0 on air-gapped or no-sudo hosts and install packages manually.
#
# rustup is bootstrapped via curl, wget, or Python urllib — curl is not required.
#
# NOTE: Does not download datasets. Keep rust/eve_extractor when exporting the directory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-$MODEL_DIR/.venv}"

RF_EVE=""
RF_LABELS=""
IF_BENIGN_EVE=""

OUT_BASE="${OUT_BASE:-$MODEL_DIR/artifacts/Deployment_bundle}"
FEATURE_IMPORTANCE_CSV="${FEATURE_IMPORTANCE_CSV:-$MODEL_DIR/artifacts/Saved_models/RF/feature_importance.csv}"

CV_FOLDS="${CV_FOLDS:-5}"
TIME_TOLERANCE_SEC="${TIME_TOLERANCE_SEC:-1.0}"

REBUILD_FEATURES="${REBUILD_FEATURES:-1}"
DEDUPE_IDENTITY_KEY="${DEDUPE_IDENTITY_KEY:-1}"
SPLIT_BY_IDENTITY_GROUP="${SPLIT_BY_IDENTITY_GROUP:-1}"
JOIN_WORKERS="${JOIN_WORKERS:-1}"

SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_RF="${SKIP_RF:-1}"
SKIP_IF="${SKIP_IF:-1}"

# 1 = try to install missing OS packages (build-essential, python3-venv, ca-certificates, …)
AUTO_INSTALL_SYSTEM="${AUTO_INSTALL_SYSTEM:-1}"

# Default: wipe .venv for reproducible installs on a fresh machine / shipped zip
KEEP_VENV="${KEEP_VENV:-0}"

function usage() {
  cat <<'EOF'
Usage:
  ./setup.sh [--keep-venv] [other flags...]

  --keep-venv     Preserve existing .venv (skip rm -rf); only run pip install / rust build.

  ./setup.sh --artifacts-dir artifacts/Deployment_bundle
  ./setup.sh --train-rf --train-if --rf-eve ... --rf-labels-csv ... --if-benign-eve ...

Env: VENV_DIR, OUT_BASE, SKIP_BUILD=1, KEEP_VENV=1, AUTO_INSTALL_SYSTEM=0, SKIP_RF, SKIP_IF, etc.
EOF
}

ARTIFACTS_DIR=""
RUN_SCORE_INPUT=""
RUN_SCORE_OUTPUT_DIR=""
FORMAT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rf-eve) RF_EVE="${2:-}"; shift 2 ;;
    --rf-labels-csv) RF_LABELS="${2:-}"; shift 2 ;;
    --if-benign-eve) IF_BENIGN_EVE="${2:-}"; shift 2 ;;
    --out-base) OUT_BASE="${2:-}"; shift 2 ;;
    --feature-importance-csv) FEATURE_IMPORTANCE_CSV="${2:-}"; shift 2 ;;
    --artifacts-dir) ARTIFACTS_DIR="${2:-}"; shift 2 ;;
    --score-input) RUN_SCORE_INPUT="${2:-}"; shift 2 ;;
    --score-output-dir) RUN_SCORE_OUTPUT_DIR="${2:-}"; shift 2 ;;
    --format) FORMAT="${2:-}"; shift 2 ;;
    --train-rf) SKIP_RF=0; shift 1 ;;
    --train-if) SKIP_IF=0; shift 1 ;;
    --skip-rf) SKIP_RF="${2:-1}"; shift 2 ;;
    --skip-if) SKIP_IF="${2:-1}"; shift 2 ;;
    --skip-build) SKIP_BUILD="${2:-1}"; shift 2 ;;
    --keep-venv) KEEP_VENV=1; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$SKIP_RF" -eq 0 ]]; then
  if [[ -z "$RF_EVE" || -z "$RF_LABELS" ]]; then
    echo "ERROR: --rf-eve and --rf-labels-csv are required unless SKIP_RF=1" >&2
    exit 2
  fi
fi

if [[ "$SKIP_IF" -eq 0 ]]; then
  if [[ -z "$IF_BENIGN_EVE" ]]; then
    echo "ERROR: --if-benign-eve is required unless SKIP_IF=1" >&2
    exit 2
  fi
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.10+ and retry." >&2
  exit 2
fi

_have_c_linker() {
  command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1
}

_fetch_https_to_file() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf "$url" -o "$dest"
    return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
    return 0
  fi
  python3 -c "import urllib.request, sys; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])" "$url" "$dest"
}

_run_as_root_apt() {
  if [[ "$(id -u)" -eq 0 ]]; then
    env DEBIAN_FRONTEND=noninteractive "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo env DEBIAN_FRONTEND=noninteractive "$@"
  else
    return 1
  fi
}

_auto_install_apt() {
  [[ "$AUTO_INSTALL_SYSTEM" == 1 ]] || return 1
  command -v apt-get >/dev/null 2>&1 || return 1
  local pkgs=("$@")
  echo "[setup] Installing system packages (apt): ${pkgs[*]}"
  _run_as_root_apt apt-get update -qq && _run_as_root_apt apt-get install -y "${pkgs[@]}"
}

_auto_install_dnf() {
  [[ "$AUTO_INSTALL_SYSTEM" == 1 ]] || return 1
  if command -v dnf >/dev/null 2>&1; then
    echo "[setup] Installing system packages (dnf): $*"
    if [[ "$(id -u)" -eq 0 ]]; then
      dnf install -y "$@"
    else
      sudo dnf install -y "$@"
    fi
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "[setup] Installing system packages (yum): $*"
    if [[ "$(id -u)" -eq 0 ]]; then
      yum install -y "$@"
    else
      sudo yum install -y "$@"
    fi
    return 0
  fi
  return 1
}

_auto_install_pacman() {
  [[ "$AUTO_INSTALL_SYSTEM" == 1 ]] || return 1
  command -v pacman >/dev/null 2>&1 || return 1
  echo "[setup] Installing system packages (pacman): $*"
  if [[ "$(id -u)" -eq 0 ]]; then
    pacman -Sy --noconfirm "$@"
  else
    sudo pacman -Sy --noconfirm "$@"
  fi
}

_ensure_native_build_host() {
  [[ "$SKIP_BUILD" -eq 1 ]] && return 0
  _have_c_linker && return 0

  local id="" id_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    id="${ID:-}"
    id_like="${ID_LIKE:-}"
  fi

  if [[ "$AUTO_INSTALL_SYSTEM" == 1 ]]; then
    case "$id" in
      ubuntu|debian|linuxmint|pop)
        _auto_install_apt build-essential ca-certificates pkg-config curl || true
        ;;
      fedora|rhel|centos|almalinux|rocky|ol)
        _auto_install_dnf gcc gcc-c++ make pkg-config curl ca-certificates || true
        ;;
      arch|manjaro)
        _auto_install_pacman base-devel pkgconf curl ca-certificates || true
        ;;
      *)
        if [[ " $id_like " == *" debian "* ]] || [[ " $id_like " == *" ubuntu "* ]]; then
          _auto_install_apt build-essential ca-certificates pkg-config curl || true
        elif [[ " $id_like " == *" rhel "* ]] || [[ " $id_like " == *" fedora "* ]]; then
          _auto_install_dnf gcc gcc-c++ make pkg-config curl ca-certificates || true
        elif [[ " $id_like " == *" arch "* ]]; then
          _auto_install_pacman base-devel pkgconf curl ca-certificates || true
        fi
        ;;
    esac
  fi

  if _have_c_linker; then
    echo "[setup] C linker available for Rust/native build"
    return 0
  fi

  echo "ERROR: No C compiler/linker (cc, gcc, or clang) in PATH — required to build eve_extractor." >&2
  echo "  Set AUTO_INSTALL_SYSTEM=1 (default) and re-run with sudo available, or install manually:" >&2
  echo "    Debian/Ubuntu: sudo apt-get install -y build-essential pkg-config ca-certificates" >&2
  echo "    Fedora/RHEL:   sudo dnf install -y gcc gcc-c++ make pkg-config" >&2
  echo "    Arch:          sudo pacman -Sy base-devel pkgconf" >&2
  echo "    macOS:         xcode-select --install" >&2
  exit 2
}

_ensure_venv_or_install() {
  local venv_target="$1"
  if python3 -m venv "$venv_target" 2>/dev/null; then
    rm -rf "$venv_target"
    return 0
  fi
  echo "[setup] python3 -m venv failed; trying to fix (common on minimal Debian/Ubuntu)..." >&2
  if [[ "$AUTO_INSTALL_SYSTEM" == 1 ]]; then
    _auto_install_apt python3-venv python3-full ca-certificates || true
  fi
  if python3 -m venv "$venv_target" 2>/dev/null; then
    rm -rf "$venv_target"
    return 0
  fi
  return 1
}

_ensure_native_build_host

if [[ "$KEEP_VENV" -ne 1 ]]; then
  if [[ -e "$VENV_DIR" ]]; then
    echo "[setup] Removing existing venv for clean install: $VENV_DIR"
    rm -rf "$VENV_DIR"
  fi
fi

if [[ ! -d "$VENV_DIR" ]]; then
  echo "[setup] Creating virtualenv: $VENV_DIR"
  _venv_probe="$(mktemp -d)"
  if ! _ensure_venv_or_install "$_venv_probe/e"; then
    rm -rf "$_venv_probe"
    echo "ERROR: Could not create a venv. On Debian/Ubuntu install: sudo apt install python3-venv" >&2
    exit 2
  fi
  rm -rf "$_venv_probe"
  python3 -m venv "$VENV_DIR"
else
  echo "[setup] Reusing existing venv (--keep-venv): $VENV_DIR"
fi
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "[setup] Upgrading pip / setuptools / wheel"
python -m pip install -U pip setuptools wheel

echo "[setup] Installing Python dependencies from docs/requirements.txt"
python -m pip install -r "$MODEL_DIR/docs/requirements.txt"

echo "[setup] Installing build tools (maturin, patchelf for Linux RPATH)"
python -m pip install "maturin>=1.5,<2"
python -m pip install patchelf || echo "[setup] WARN: patchelf pip wheel failed; try: sudo apt install patchelf" >&2

echo "[setup] Verifying core imports"
python - <<'PY'
import numpy, pandas, sklearn, lightgbm, joblib, pyarrow
import lightgbm as lgb
print("[setup] LGBM OK", getattr(lgb, "__version__", "?"))
PY

_ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    echo "[setup] Rust already on PATH; updating stable toolchain"
    if command -v rustup >/dev/null 2>&1; then
      rustup self update 2>/dev/null || true
      rustup update stable
      rustup default stable
    fi
    return 0
  fi

  local rustup_init
  rustup_init="$(mktemp)"
  echo "[setup] Fetching rustup installer (curl, wget, or Python HTTPS)"
  if ! _fetch_https_to_file "https://sh.rustup.rs" "$rustup_init"; then
    rm -f "$rustup_init"
    echo "ERROR: Could not download https://sh.rustup.rs. Install ca-certificates, or curl/wget, or fix Python SSL." >&2
    exit 2
  fi

  echo "[setup] Installing Rust via rustup (non-interactive, stable default)"
  if ! sh "$rustup_init" -y --default-toolchain stable; then
    rm -f "$rustup_init"
    echo "ERROR: rustup installer failed." >&2
    exit 2
  fi
  rm -f "$rustup_init"
  # shellcheck disable=SC1090
  if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
  fi
  export PATH="${HOME}/.cargo/bin:${PATH}"

  if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: rustup installed but cargo not on PATH. Run: source \"\$HOME/.cargo/env\"" >&2
    exit 2
  fi
}

# MSRV driven by crates (e.g. indexmap 2.13, Arrow 53); not the same as distro rustc 1.75.
RUSTC_MIN_VERSION="1.82.0"
EVE_CRATE_DIR="$MODEL_DIR/rust/eve_extractor"

_check_rustc_for_eve_extractor() {
  if ! command -v rustc >/dev/null 2>&1; then
    echo "ERROR: rustc not on PATH after Rust setup." >&2
    return 1
  fi
  # rust-toolchain.toml in eve_extractor makes rustup select `stable` when cwd is this crate
  local current
  current=$(cd "$EVE_CRATE_DIR" && rustc -V 2>/dev/null | sed -n 's/rustc \([0-9.]*\).*/\1/p')
  if [[ -z "$current" ]]; then
    echo "ERROR: could not read rustc version in $EVE_CRATE_DIR" >&2
    return 1
  fi
  # OK iff min version sorts first (i.e. current >= RUSTC_MIN_VERSION)
  if [[ "$(printf '%s\n' "$RUSTC_MIN_VERSION" "$current" | sort -V | head -n1)" != "$RUSTC_MIN_VERSION" ]]; then
    echo "ERROR: rustc $current is too old for eve_extractor dependencies (need >= $RUSTC_MIN_VERSION)." >&2
    echo "  Distro packages (e.g. Debian rustc 1.75) are often too old. Use rustup: https://rustup.rs" >&2
    echo "  Then:  rustup update stable" >&2
    echo "  This crate ships rust/eve_extractor/rust-toolchain.toml (channel = stable) so builds use a current compiler." >&2
    if ! command -v rustup >/dev/null 2>&1; then
      echo "  No rustup in PATH — install it so Cargo can install the pinned toolchain." >&2
    fi
    return 1
  fi
  echo "[setup] rustc OK for eve_extractor: $current (minimum $RUSTC_MIN_VERSION)"
  return 0
}

if [[ "$SKIP_BUILD" -ne 1 ]]; then
  if [[ -d "${HOME}/.cargo/bin" ]]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
  fi

  _ensure_rust

  echo "[setup] Resolving Rust toolchain for $EVE_CRATE_DIR (rust-toolchain.toml may download stable)"
  (cd "$EVE_CRATE_DIR" && (command -v rustup >/dev/null 2>&1 && rustup show 2>/dev/null | head -20 || true))
  _check_rustc_for_eve_extractor || exit 2

  echo "[setup] Building Rust extension eve_extractor (release)"
  (cd "$EVE_CRATE_DIR" && maturin develop --release)

  echo "[setup] Verifying eve_extractor import"
  python - <<'PY'
import eve_extractor
assert hasattr(eve_extractor, "RustUnifiedExtractor"), "RustUnifiedExtractor missing"
assert int(eve_extractor.N_FEATURES) >= 1, "N_FEATURES missing"
print("[setup] eve_extractor OK", eve_extractor.__file__, "N_FEATURES=", eve_extractor.N_FEATURES)
PY
else
  echo "[setup] SKIP_BUILD=1 — skipping Rust extension (eve_extractor will not be available)"
fi

cd "$MODEL_DIR"

echo "[check] artifacts dir base: $OUT_BASE"
mkdir -p "$OUT_BASE"

if [[ -n "$ARTIFACTS_DIR" ]]; then
  echo "[check] Verifying artifacts in: $ARTIFACTS_DIR"
  if [[ ! -d "$ARTIFACTS_DIR" ]]; then
    echo "ERROR: --artifacts-dir not found: $ARTIFACTS_DIR" >&2
    exit 2
  fi
  required=(isolation_forest.joblib random_forest.joblib scaler.joblib config.joblib)
  for f in "${required[@]}"; do
    if [[ ! -f "$ARTIFACTS_DIR/$f" ]]; then
      echo "ERROR: missing required artifact: $ARTIFACTS_DIR/$f" >&2
      exit 2
    fi
  done
  echo "[check] Artifacts present."
fi

if [[ "$SKIP_RF" -eq 0 ]]; then
  RF_CMD=(python -m training.Randomforest_training_pipeline
    --eve "$RF_EVE"
    --labels-csv "$RF_LABELS"
    --output-dir "$OUT_BASE"
    --cv-folds "$CV_FOLDS"
    --feature-importance-csv "$FEATURE_IMPORTANCE_CSV"
    --join-workers "$JOIN_WORKERS"
    --time-tolerance-sec "$TIME_TOLERANCE_SEC"
  )

  if [[ "$REBUILD_FEATURES" -eq 1 ]]; then
    RF_CMD+=(--rebuild-features)
  fi
  if [[ "$DEDUPE_IDENTITY_KEY" -eq 1 ]]; then
    RF_CMD+=(--dedupe-identity-key)
  fi
  if [[ "$SPLIT_BY_IDENTITY_GROUP" -eq 1 ]]; then
    RF_CMD+=(--split-by-identity-group)
  fi

  echo "[train] Running: ${RF_CMD[*]}"
  "${RF_CMD[@]}"
fi

IF_OUT_DIR="$OUT_BASE/IF"

if [[ "$SKIP_IF" -eq 0 ]]; then
  mkdir -p "$IF_OUT_DIR"

  IF_CMD=(python -m training.Isolationforest_training_pipeline
    --dataset "$IF_BENIGN_EVE"
    --output-dir "$IF_OUT_DIR"
    --features-parquet "$IF_OUT_DIR/if_training_features.parquet"
    --external-scaler "$OUT_BASE/scaler.joblib"
    --reference-config "$OUT_BASE/config.joblib"
  )
  if [[ "$REBUILD_FEATURES" -eq 1 ]]; then
    IF_CMD+=(--rebuild-features)
  fi

  echo "[train] Running: ${IF_CMD[*]}"
  "${IF_CMD[@]}"
fi

if [[ -n "$RUN_SCORE_INPUT" ]]; then
  if [[ -z "$ARTIFACTS_DIR" ]]; then
    echo "ERROR: --artifacts-dir is required when using --score-input" >&2
    exit 2
  fi
  if [[ -z "$RUN_SCORE_OUTPUT_DIR" ]]; then
    RUN_SCORE_OUTPUT_DIR="$MODEL_DIR/logs"
  fi
  echo "[score] Running runtime scoring"
  python -m inference.runtime_scoring \
    --artifacts "$ARTIFACTS_DIR" \
    --input "$RUN_SCORE_INPUT" \
    --output-dir "$RUN_SCORE_OUTPUT_DIR" \
    ${FORMAT:+--format "$FORMAT"}
fi

echo "[done] Setup complete."
echo "[done] Activate with: source \"$VENV_DIR/bin/activate\""
if [[ -n "$ARTIFACTS_DIR" ]]; then
  echo "[done] Artifacts verified: $ARTIFACTS_DIR"
else
  echo "[done] Default RF/IF output base: $OUT_BASE"
fi

