#!/usr/bin/env bash

set -Eeuo pipefail

SERVICE_NAME="dnfo"
INSTALL_PATH="/usr/local/sbin/dnfo"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

require_root()
{
    if [[ $EUID -ne 0 ]]; then
        echo "Run as root"
        exit 1
    fi
}

require_root

echo "[*] Checking dependencies..."

for cmd in docker nft jq nsenter ip systemctl; do
    command -v "$cmd" >/dev/null || {
        echo "Missing dependency: $cmd"
        exit 1
    }
done

echo "[*] Installing operator..."

install -m 755 dnfo.sh "$INSTALL_PATH"
mkdir -p /var/lib/dnfo/docker
chown root:root /var/lib/dnfo -R
chmod 700 /var/lib/dnfo

echo "[*] Installing systemd unit..."

cat > "$UNIT_FILE" <<'EOF'
[Unit]
Description=Docker Netfilter Firewall Operator

Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

PartOf=docker.service
BindsTo=docker.service

StartLimitIntervalSec=0

[Service]
Type=simple

User=root
Group=root

ExecStartPre=/usr/bin/docker info
ExecStart=/usr/local/sbin/dnfo

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Reloading systemd..."

systemctl daemon-reload

echo "[*] Enabling service..."

systemctl enable dnfo.service

echo "[*] Starting service..."

systemctl restart dnfo.service

echo
echo "Installation complete."
echo
systemctl --no-pager --full status dnfo.service || true
