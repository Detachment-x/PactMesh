#!/usr/bin/env bash
# PactMesh installer for Linux x86_64.
# Downloads the latest release, installs binaries, grants network capabilities,
# and points you at `pactmesh quickstart` for first-run setup.
set -euo pipefail

REPO="Detachment-x/PactMesh"
GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; RES='\033[0m'

INSTALL_PATH="/opt/pactmesh"
GH_PROXY="https://ghfast.top/"
USE_GH_PROXY=false
COMMAND="install"

HELP() {
  cat <<EOF
PactMesh installer (Linux x86_64)

Usage: ./install.sh [command] [path] [options]

Commands:
  install     Install or overwrite PactMesh (default)
  uninstall   Remove PactMesh binaries and symlinks
  help        Show this message

Options:
  --gh-proxy [URL]   Route GitHub downloads through a proxy (default: ${GH_PROXY})
  --no-gh-proxy      Download directly from GitHub (default)

Examples:
  sudo ./install.sh install
  sudo ./install.sh install /usr/local/lib/pactmesh
  sudo ./install.sh install --gh-proxy        # use the bundled CN proxy
  sudo ./install.sh uninstall
EOF
}

# ---- argument parsing -------------------------------------------------------
if [[ $# -gt 0 && ( "$1" == "install" || "$1" == "uninstall" || "$1" == "help" ) ]]; then
  COMMAND="$1"; shift
fi
if [[ "$COMMAND" == "help" ]]; then HELP; exit 0; fi
if [[ $# -ge 1 && "$1" != --* ]]; then INSTALL_PATH="${1%/}"; shift; fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gh-proxy) USE_GH_PROXY=true; [[ $# -ge 2 && "$2" != --* ]] && { GH_PROXY="$2"; shift; } ;;
    --no-gh-proxy) USE_GH_PROXY=false ;;
    *) echo -e "${RED}Unknown option: $1${RES}"; exit 1 ;;
  esac
  shift
done

# ---- preflight --------------------------------------------------------------
if [[ "$(id -u)" != "0" ]]; then
  echo -e "${RED}This script must run as root (use sudo).${RES}"; exit 1
fi
ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" ]]; then
  echo -e "${RED}Unsupported architecture: ${ARCH}. Prebuilt releases cover Linux x86_64 only.${RES}"
  echo -e "Build from source instead: https://github.com/${REPO}"
  exit 1
fi
for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo -e "${RED}Error: ${tool} is required.${RES}"; exit 1; }
done

BIN_DIR="/usr/local/bin"
ASSET="pactmesh-linux-x86_64.tar.gz"

uninstall() {
  echo -e "${YELLOW}Removing PactMesh...${RES}"
  if command -v pactmesh >/dev/null 2>&1; then
    pactmesh service uninstall >/dev/null 2>&1 || true
  fi
  rm -f "${BIN_DIR}/pactmesh" "${BIN_DIR}/pactmesh-core"
  rm -rf "${INSTALL_PATH}"
  echo -e "${GREEN}PactMesh binaries removed.${RES}"
  echo -e "Trust-domain data in ~/.config/privateNetwork was left untouched."
}

install() {
  local base url tmp
  base="https://github.com/${REPO}/releases/latest/download/${ASSET}"
  if $USE_GH_PROXY; then url="${GH_PROXY%/}/${base}"; else url="$base"; fi

  echo -e "${GREEN}Downloading ${ASSET}...${RES}\n  ${url}"
  tmp="$(mktemp -d /tmp/pactmesh-install.XXXXXX)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fL --progress-bar -o "${tmp}/${ASSET}" "$url"

  echo -e "${GREEN}Installing to ${INSTALL_PATH}...${RES}"
  mkdir -p "${INSTALL_PATH}"
  tar -xzf "${tmp}/${ASSET}" -C "${tmp}"
  # accept either a flat archive or one nested under a top-level dir
  local core cli
  core="$(find "$tmp" -type f -name pactmesh-core | head -1)"
  cli="$(find "$tmp" -type f -name pactmesh | head -1)"
  [[ -n "$core" && -n "$cli" ]] || { echo -e "${RED}Archive did not contain pactmesh/pactmesh-core.${RES}"; exit 1; }
  install -m 0755 "$cli"  "${INSTALL_PATH}/pactmesh"
  install -m 0755 "$core" "${INSTALL_PATH}/pactmesh-core"
  ln -sf "${INSTALL_PATH}/pactmesh"      "${BIN_DIR}/pactmesh"
  ln -sf "${INSTALL_PATH}/pactmesh-core" "${BIN_DIR}/pactmesh-core"

  # Grant the daemon raw-socket + TUN capabilities so it runs without sudo.
  if command -v setcap >/dev/null 2>&1; then
    if setcap cap_net_admin,cap_net_raw+ep "${INSTALL_PATH}/pactmesh-core"; then
      echo -e "${GREEN}Granted cap_net_admin,cap_net_raw to pactmesh-core.${RES}"
    else
      echo -e "${YELLOW}setcap failed; run pactmesh-core as root or via 'pactmesh service install'.${RES}"
    fi
  else
    echo -e "${YELLOW}setcap not found; install libcap2-bin, or run via 'pactmesh service install' (root).${RES}"
  fi

  echo -e "\n${GREEN}PactMesh installed.${RES}  Version: $("${INSTALL_PATH}/pactmesh" --version 2>/dev/null || echo unknown)\n"
  cat <<EOF
Next steps:
  1. First-run setup (creates your network and opens the web console):
       ${GREEN}pactmesh quickstart${RES}
     then open the printed http://127.0.0.1:15810/?token=... URL.

  2. Optional — run the daemon as a system service (root):
       ${GREEN}sudo pactmesh service install && sudo pactmesh service start${RES}

  Docs: https://github.com/${REPO}
EOF
}

case "$COMMAND" in
  install)   install ;;
  uninstall) uninstall ;;
  *)         HELP; exit 1 ;;
esac
