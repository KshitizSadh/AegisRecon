#!/usr/bin/env bash
#
# install.sh — one-shot installer for AegisRecon on Linux and macOS.
#
# Creates an isolated virtualenv, installs the package (plus optional dev /
# ProjectDiscovery tooling), and can run the offline test suite or a smoke test.
#
# Supports: Debian/Ubuntu/Kali, Parrot OS, RHEL/Fedora, Arch, macOS (Homebrew),
# and any distro where `python3` plus a venv module are available.
#
# Usage:
#   ./install.sh                 # venv + package + tests (also Go tools when Go is present)
#   ./install.sh --with-tools    # force-install ProjectDiscovery binaries via Go
#   ./install.sh --no-tools      # skip Go binaries even if Go is installed
#   ./install.sh --skip-tests    # install only
#   ./install.sh --no-dev        # install without the dev/test extra
#   ./install.sh --add-to-path   # append Go bin to ~/.bashrc (for --with-tools)
#
# See docs/INSTALL.md for the full manual guide.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$REPO_DIR/.venv}"
GO_BIN="$HOME/go/bin"

# Auto-install ProjectDiscovery/gitleaks binaries when Go is available, unless
# the user explicitly opts out with --no-tools. This avoids the confusing
# "binary not found on PATH" failures after a fresh install.
WITH_TOOLS=auto
ADD_TO_PATH=0
SKIP_TESTS=0
WITH_DEV=1

usage() {
    sed -n '3,18p' "${BASH_SOURCE[0]}"
    exit 0
}

for arg in "$@"; do
    case "$arg" in
        --with-tools) WITH_TOOLS=1 ;;
        --no-tools) WITH_TOOLS=0 ;;
        --add-to-path) ADD_TO_PATH=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        --no-dev) WITH_DEV=0 ;;
        --help | -h) usage ;;
        *) echo "install.sh: unknown option '$arg'" >&2; usage ;;
    esac
done

log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# -- dependency installation -------------------------------------------------
install_system_python() {
    case "$(uname -s)" in
        Darwin)
            if ! command -v brew >/dev/null 2>&1; then
                die "Homebrew not found. Install it: https://brew.sh (or pre-install python3)."
            fi
            log "Installing python@3 via Homebrew"
            brew install python@3 git
            ;;
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                log "Installing system packages (apt)"
                sudo apt-get update -y
                sudo apt-get install -y python3 python3-venv python3-pip git
            elif command -v dnf >/dev/null 2>&1; then
                log "Installing system packages (dnf)"
                sudo dnf install -y python3 python3-pip git
            elif command -v pacman >/dev/null 2>&1; then
                log "Installing system packages (pacman)"
                sudo pacman -Sy --noconfirm python python-pip git
            else
                warn "Unsupported package manager — assuming python3 + git already exist."
                command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.10+ first."
            fi
            ;;
        *)
            die "Unsupported OS '$(uname -s)'. Supported: Linux and macOS."
            ;;
    esac
}

# -- ProjectDiscovery binaries + gitleaks (httpx, subfinder, naabu, katana, dnsx, nuclei) --
install_pd_tools() {
    command -v go >/dev/null 2>&1 || die "Go not found. Install Go (https://go.dev/dl) or retry without --with-tools."
    log "Installing ProjectDiscovery binaries via Go (this can take a few minutes)"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/subfinder/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/gitleaks/gitleaks/v8@latest

    if [ "$ADD_TO_PATH" -eq 1 ]; then
        if ! grep -qF "go/bin" "$HOME/.bashrc" 2>/dev/null; then
            log "Adding '$GO_BIN' to ~/.bashrc"
            printf '\nexport PATH="%s:$PATH"\n' "$GO_BIN" >> "$HOME/.bashrc"
        fi
    fi
    warn "Ensure $GO_BIN is on your PATH for this session:"
    echo "    export PATH=\"$GO_BIN:\$PATH\""
}

# Detect the Python 'httpx[cli]' console script shadowing the Packaged Go binary.
# The optional [api] extra pulls in the Python httpx library, whose 'httpx' CLI
# entry point can precede ~/go/bin/httpx on PATH and break probe run.
warn_httpx_collision() {
    if ! command -v httpx >/dev/null 2>&1; then
        return
    fi
    local resolved head
    resolved="$(command -v httpx)"
    head="$(head -c 2 "$resolved" 2>/dev/null || true)"
    if [ "$head" = "#!" ] && head -n 1 "$resolved" 2>/dev/null | grep -qi python; then
        warn "Detected the Python \`httpx\` client at $resolved — it will shadow the Go binary."
        echo "    Ensure $GO_BIN comes before the venv on PATH (e.g. export PATH=\"$GO_BIN:\$PATH\"),"
        echo "    or set AEGISRECON_HTTPX_BIN to the ProjectDiscovery httpx path."
    fi
}

# -- Python virtualenv + package ---------------------------------------------
install_python_env() {
    command -v python3 >/dev/null 2>&1 || die "python3 not found."
    PY3="$(command -v python3)"
    MAJOR="$(python3 -c 'import sys; print(sys.version_info.major)')"
    MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
    if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]; }; then
        die "Python 3.10+ required (found ${MAJOR}.${MINOR})."
    fi

    log "Creating virtualenv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    python -m pip install --upgrade pip

    if [ "$WITH_DEV" -eq 1 ]; then
        log "Installing package with dev/test extras"
        pip install -e ".[dev]"
    else
        log "Installing package (runtime only)"
        pip install -e "."
    fi
}

# -- verification ------------------------------------------------------------
run_tests() {
    log "Running AegisRecon test suite"
    ( cd "$REPO_DIR" && python -m pytest -q )
}

smoke() {
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    log "Smoke test against a throwaway data dir ($tmp_dir)"
    ( cd "$REPO_DIR" && \
        AEGISRECON_DATA_DIR="$tmp_dir" aegisrecon init && \
        AEGISRECON_DATA_DIR="$tmp_dir" aegisrecon program create "Smoke Lab" --org "installer" && \
        AEGISRECON_DATA_DIR="$tmp_dir" aegisrecon scope add "Smoke Lab" example.test --wildcard && \
        AEGISRECON_DATA_DIR="$tmp_dir" aegisrecon finding list "Smoke Lab" )
    rm -rf "$tmp_dir"
}

# -- main --------------------------------------------------------------------
cd "$REPO_DIR"
[ -f pyproject.toml ] || die "pyproject.toml not found — run this from the repo root."

log "Installing AegisRecon from $REPO_DIR"
install_system_python
install_python_env

if [ "$WITH_TOOLS" = "auto" ]; then
    if command -v go >/dev/null 2>&1; then
        log "Go detected — installing ProjectDiscovery/gitleaks binaries"
        install_pd_tools
    else
        log "Go not found — skipping optional binaries (run 'aegisrecon tools install' later)"
    fi
elif [ "$WITH_TOOLS" -eq 1 ]; then
    install_pd_tools
fi
warn_httpx_collision

if [ "$SKIP_TESTS" -eq 0 ]; then
    run_tests
fi

log "Installation complete."
cat <<'EOF'
─────────────────────────────────────────────────────────────
 Next steps:
   • Activate the environment:
        source .venv/bin/activate
   • If you installed Go tools (--with-tools), put them on PATH first:
        export PATH="$HOME/go/bin:$PATH"     # keep Go httpx ahead of the venv
   • Start a real engagement:
        export AEGISRECON_DATA_DIR=~/aegisrecon-lab
        aegisrecon init
        aegisrecon program create "My Lab" --org "me"
        aegisrecon scope add "My Lab" example.com --wildcard
        aegisrecon recon run "My Lab"
   • See docs/INSTALL.md for the full guide (Kali-focused).

 Authorized-use reminder: only ever add domains you are
 explicitly authorized to test. AegisRecon enforces scope
 before anything is probed or stored.
─────────────────────────────────────────────────────────────
EOF