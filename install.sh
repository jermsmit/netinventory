#!/usr/bin/env bash
# install.sh — NetInventory installer
# Run as root: sudo bash install.sh

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[ "$EUID" -ne 0 ] && error "Please run as root: sudo bash install.sh"

# ── Config ────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/netinventory"
DATA_DIR="/var/lib/netinventory"
SERVICE_FILE="/etc/systemd/system/netinventory.service"

echo ""
echo "  ╔═══════════════════════════════════╗"
echo "  ║       NetInventory Installer      ║"
echo "  ╚═══════════════════════════════════╝"
echo ""

# ── Detect subnet automatically ───────────────────────────────────────────
AUTO_SUBNET=$(ip route | awk '/proto kernel/ && !/via/ {print $1}' | head -1)
DEFAULT_SUBNET="${AUTO_SUBNET:-192.168.1.0/24}"

read -rp "  Subnet to scan [${DEFAULT_SUBNET}]: " SUBNET
SUBNET="${SUBNET:-$DEFAULT_SUBNET}"

read -rp "  Web dashboard port [8080]: " PORT
PORT="${PORT:-8080}"

read -rp "  Scan interval in seconds [300]: " INTERVAL
INTERVAL="${INTERVAL:-300}"

echo ""

# ── Install dependencies ──────────────────────────────────────────────────
info "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq nmap python3 python3-venv python3-full

# ── Copy files ────────────────────────────────────────────────────────────
info "Installing to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/templates" "${DATA_DIR}"

cp app.py          "${INSTALL_DIR}/"
cp -r templates/   "${INSTALL_DIR}/"
[ -f oui.txt ] && cp oui.txt "${INSTALL_DIR}/" && info "OUI file copied"

# ── Create virtualenv & install Flask inside it ───────────────────────────
VENV_DIR="${INSTALL_DIR}/venv"
info "Creating Python virtualenv at ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet flask
info "Flask installed into virtualenv"

# ── Write service file ────────────────────────────────────────────────────
info "Creating systemd service..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=NetInventory - Home Network Scanner & Dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="NETINV_SUBNET=${SUBNET}"
Environment="NETINV_PORT=${PORT}"
Environment="NETINV_INTERVAL=${INTERVAL}"
Environment="NETINV_DB=${DATA_DIR}/hosts.db"
Environment="NETINV_LOGLEVEL=INFO"
ExecStart=${VENV_DIR}/bin/python ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netinventory

[Install]
WantedBy=multi-user.target
EOF

# ── Enable & start ────────────────────────────────────────────────────────
info "Enabling and starting service..."
systemctl daemon-reload
systemctl enable netinventory
systemctl restart netinventory

sleep 2

if systemctl is-active --quiet netinventory; then
  HOST_IP=$(hostname -I | awk '{print $1}')
  echo ""
  echo -e "  ${GREEN}✓ NetInventory is running!${NC}"
  echo ""
  echo "  Dashboard:  http://${HOST_IP}:${PORT}"
  echo "  Subnet:     ${SUBNET}"
  echo "  Interval:   ${INTERVAL}s"
  echo ""
  echo "  Useful commands:"
  echo "    journalctl -u netinventory -f    # live logs"
  echo "    systemctl status netinventory    # service status"
  echo "    systemctl restart netinventory   # restart"
  echo "    systemctl stop netinventory      # stop"
  echo ""
else
  error "Service failed to start. Check: journalctl -u netinventory -xe"
fi
