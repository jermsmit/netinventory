#!/usr/bin/env bash
# uninstall.sh — Remove NetInventory

set -e
[ "$EUID" -ne 0 ] && echo "Run as root: sudo bash uninstall.sh" && exit 1

echo "Stopping and removing NetInventory..."

systemctl stop    netinventory 2>/dev/null || true
systemctl disable netinventory 2>/dev/null || true

rm -f  /etc/systemd/system/netinventory.service
rm -rf /opt/netinventory
systemctl daemon-reload

read -rp "Also delete scan database in /var/lib/netinventory? [y/N]: " DEL_DB
if [[ "$DEL_DB" =~ ^[Yy]$ ]]; then
  rm -rf /var/lib/netinventory
  echo "Database removed."
fi

echo "NetInventory uninstalled."
