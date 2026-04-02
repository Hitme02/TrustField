#!/usr/bin/env bash
# run.sh — TrustField one-shot setup and launch script
#
# Usage:
#   ./run.sh              # setup (if needed) + start dashboard
#   ./run.sh --test       # setup + run test suite, then start dashboard
#   ./run.sh --demo       # setup + run full pipeline demo, then start dashboard
#   ./run.sh --test-only  # setup + run tests, exit (no server)
#   ./run.sh --demo-only  # setup + run pipeline demo, exit (no server)
#   ./run.sh --port 8080  # start dashboard on a custom port
#   ./run.sh --help       # show this help

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

# ── Defaults ───────────────────────────────────────────────────────────────
PORT=5000
RUN_TESTS=false
RUN_DEMO=false
SERVER=true

# ── Arg parsing ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test)       RUN_TESTS=true ;;
    --demo)       RUN_DEMO=true ;;
    --test-only)  RUN_TESTS=true; SERVER=false ;;
    --demo-only)  RUN_DEMO=true;  SERVER=false ;;
    --port|-p)    PORT="$2"; shift ;;
    --help|-h)
      sed -n '3,12p' "$0" | sed 's/^# //'
      exit 0 ;;
    *)
      echo -e "${RED}Unknown option: $1${RST}" >&2
      exit 1 ;;
  esac
  shift
done

# ── Helpers ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info()    { echo -e "${CYN}▶${RST} $*"; }
success() { echo -e "${GRN}✓${RST} $*"; }
warn()    { echo -e "${YLW}⚠${RST} $*"; }
die()     { echo -e "${RED}✗${RST} $*" >&2; exit 1; }
divider() { echo -e "${DIM}────────────────────────────────────────────────${RST}"; }

# ── Banner ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYN}  ████████╗██████╗ ██╗   ██╗███████╗████████╗${RST}"
echo -e "${CYN}     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝${RST}"
echo -e "${CYN}     ██║   ██████╔╝██║   ██║███████╗   ██║   ${RST}"
echo -e "${CYN}     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ${RST}"
echo -e "${CYN}     ██║   ██║  ██║╚██████╔╝███████║   ██║   ${RST}"
echo -e "${CYN}     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ${RST}"
echo -e "${DIM}  Trust Propagation & Containment System${RST}"
echo -e "${DIM}  RV College of Engineering — Team PS-11${RST}"
echo ""
divider

# ── Step 1: Python version check ───────────────────────────────────────────
info "Checking Python version…"
if ! command -v python3 &>/dev/null; then
  die "python3 not found. Install Python 3.10 or higher."
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJ=$(python3 -c 'import sys; print(sys.version_info.major)')
PY_MIN=$(python3 -c 'import sys; print(sys.version_info.minor)')

if [[ "$PY_MAJ" -lt 3 ]] || { [[ "$PY_MAJ" -eq 3 ]] && [[ "$PY_MIN" -lt 10 ]]; }; then
  die "Python 3.10+ required. Found: $PY_VER"
fi
success "Python $PY_VER"

# ── Step 2: Virtual environment ────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
  info "Creating virtual environment at .venv …"
  python3 -m venv "$VENV_DIR"
  success "Virtual environment created"
else
  success "Virtual environment already exists"
fi

# Activate
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
success "Virtual environment activated"

# ── Step 3: Install / sync dependencies ────────────────────────────────────
info "Installing dependencies from requirements.txt …"
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
success "Dependencies installed"
divider

# ── Step 4: Optional — run tests ───────────────────────────────────────────
if [[ "$RUN_TESTS" == true ]]; then
  info "Running test suite…"
  echo ""
  cd "$SCRIPT_DIR"
  if PYTHONPATH=. pytest tests/ -q --tb=short; then
    success "All tests passed"
  else
    warn "Some tests failed (check output above)"
  fi
  echo ""
  divider
fi

# ── Step 5: Optional — run full pipeline demo ──────────────────────────────
if [[ "$RUN_DEMO" == true ]]; then
  info "Running full pipeline demo (all 4 topologies)…"
  echo ""
  cd "$SCRIPT_DIR"
  PYTHONPATH=. python demos/demo_full_pipeline.py
  success "Demo complete — outputs written to out/"
  echo ""
  divider
fi

# ── Step 6: Start dashboard server ─────────────────────────────────────────
if [[ "$SERVER" == true ]]; then
  info "Starting TrustField dashboard on port $PORT …"
  echo ""
  echo -e "  ${GRN}Open:${RST}  http://127.0.0.1:${PORT}"
  echo ""
  echo -e "  ${DIM}Tabs:   HUB · CHAIN · DENSE · MIXED — synthetic topologies${RST}"
  echo -e "  ${DIM}        SIM — live simulated infrastructure${RST}"
  echo ""
  echo -e "  ${DIM}SIM tab controls:${RST}"
  echo -e "  ${DIM}  INFRA  → open infrastructure editor (add/remove nodes & policies)${RST}"
  echo -e "  ${DIM}  RUN    → run full 6-module pipeline analysis${RST}"
  echo -e "  ${DIM}  Click node → ⚡ SIMULATE BREACH → run from that entry point${RST}"
  echo ""
  echo -e "  ${DIM}Press Ctrl+C to stop${RST}"
  divider
  echo ""
  cd "$SCRIPT_DIR"
  PYTHONPATH=. python server.py --port "$PORT"
fi
