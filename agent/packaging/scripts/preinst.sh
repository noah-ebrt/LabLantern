#!/bin/sh
# Alte Handinstallation (bis 0.5.x: Binary in /usr/local/bin, Timer in /etc/systemd/system) entfernen.
# Konfiguration und Token in /etc/vulnwatch bleiben erhalten, ein neues enroll ist nicht nötig.
if [ -f /etc/systemd/system/vulnwatch-agent.timer ] || [ -f /etc/systemd/system/vulnwatch-agent.service ]; then
  systemctl disable --now vulnwatch-agent.timer vulnwatch-agent.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/vulnwatch-agent.timer /etc/systemd/system/vulnwatch-agent.service
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -f /usr/local/bin/vulnwatch-agent
exit 0
