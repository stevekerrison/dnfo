#!/usr/bin/env bash

set -Eeuo pipefail

systemctl stop dnfo.service || true
systemctl disable dnfo.service || true

rm -f /etc/systemd/system/dnfo.service
rm -f /usr/local/sbin/dnfo

systemctl daemon-reload

echo "DNFO removed."