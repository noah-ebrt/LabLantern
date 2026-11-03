#!/bin/sh
# Alte Handinstallation (bis 0.5.x: Binary in /usr/local/bin, Timer in /etc/systemd/system) entfernen.
# Konfiguration und Token in /etc/lablantern bleiben erhalten, ein neues enroll ist nicht nötig.
if [ -f /etc/systemd/system/lablantern-agent.timer ] || [ -f /etc/systemd/system/lablantern-agent.service ]; then
  systemctl disable --now lablantern-agent.timer lablantern-agent.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/lablantern-agent.timer /etc/systemd/system/lablantern-agent.service
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -f /usr/local/bin/lablantern-agent
exit 0
