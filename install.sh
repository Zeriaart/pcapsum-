#!/bin/bash
# ─────────────────────────────────────────────────────────
# pcapsum installer for Kali / Debian / Ubuntu
# Run:  chmod +x install.sh && sudo ./install.sh
# ─────────────────────────────────────────────────────────
set -e

RED='\033[1;31m'
GRN='\033[1;32m'
CYN='\033[1;36m'
RST='\033[0m'

ok()   { echo -e "  ${GRN}[+]${RST} $1"; }
info() { echo -e "  ${CYN}[*]${RST} $1"; }
fail() { echo -e "  ${RED}[-]${RST} $1"; exit 1; }

# ── Must be root ──
if [ "$(id -u)" -ne 0 ]; then
    fail "Run with sudo:  sudo ./install.sh"
fi

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
INSTALL_DIR="/opt/pcap-analyzer"
BIN_LINK="/usr/local/bin/pcapsum"

echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${CYN}  pcapsum installer${RST}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""

# ── 1. Install tshark if missing ──
if ! command -v tshark &>/dev/null; then
    info "Installing tshark..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark wireshark-common >/dev/null 2>&1
    ok "tshark installed"
else
    ok "tshark found: $(which tshark)"
fi

# ── 2. Ensure python3 exists ──
if ! command -v python3 &>/dev/null; then
    info "Installing python3..."
    apt-get install -y -qq python3 >/dev/null 2>&1
    ok "python3 installed"
else
    ok "python3 found: $(python3 --version)"
fi

# ── 3. Copy files to /opt/pcap-analyzer ──
info "Installing to ${INSTALL_DIR}..."
rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cp "${SCRIPT_DIR}/pcap-analyzer.py" "${INSTALL_DIR}/pcap-analyzer.py"
chmod 755 "${INSTALL_DIR}/pcap-analyzer.py"
ok "Copied pcap-analyzer.py"

# ── 4. Create launcher in /opt ──
cat > "${INSTALL_DIR}/pcapsum" << 'LAUNCHER'
#!/bin/bash
exec python3 /opt/pcap-analyzer/pcap-analyzer.py "$@"
LAUNCHER
chmod 755 "${INSTALL_DIR}/pcapsum"

# ── 5. Symlink to /usr/local/bin ──
rm -f "${BIN_LINK}"
ln -s "${INSTALL_DIR}/pcapsum" "${BIN_LINK}"
ok "Symlinked ${BIN_LINK} -> ${INSTALL_DIR}/pcapsum"

# ── 6. Fix line endings (in case copied from Windows) ──
if command -v sed &>/dev/null; then
    sed -i 's/\r$//' "${INSTALL_DIR}/pcap-analyzer.py" "${INSTALL_DIR}/pcapsum"
    ok "Fixed line endings"
fi

# ── 7. Verify ──
echo ""
if command -v pcapsum &>/dev/null; then
    ok "Install complete!  Run from anywhere:"
    echo ""
    echo -e "    ${GRN}pcapsum capture.pcap${RST}          # full analysis"
    echo -e "    ${GRN}pcapsum -q capture.pcap${RST}       # quick mode"
    echo -e "    ${GRN}pcapsum -f capture.pcap${RST}       # flag hunt"
    echo -e "    ${GRN}pcapsum -s 0 capture.pcap${RST}     # follow stream 0"
    echo -e "    ${GRN}pcapsum -e http capture.pcap${RST}  # export HTTP objects"
    echo -e "    ${GRN}pcapsum --help${RST}                # all options"
    echo ""
else
    fail "Something went wrong — pcapsum not in PATH"
fi
