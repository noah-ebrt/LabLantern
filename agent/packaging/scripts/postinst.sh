#!/bin/sh
set -e
getent group lablantern >/dev/null || groupadd --system lablantern
getent passwd lablantern >/dev/null || useradd --system --gid lablantern --home-dir /nonexistent \
  --no-create-home --shell /usr/sbin/nologin lablantern
# Der Daemon darf Token und CA lesen, schreiben darf nur root.
if [ -d /etc/lablantern ]; then
  chown root:lablantern /etc/lablantern
  chmod 0750 /etc/lablantern
  if [ -f /etc/lablantern/agent.json ]; then
    chown root:lablantern /etc/lablantern/agent.json
    chmod 0640 /etc/lablantern/agent.json
  fi
fi
systemd-tmpfiles --create /usr/lib/tmpfiles.d/lablantern.conf
systemctl daemon-reload
systemctl enable lablantern-collect.path lablantern-action.path lablantern-agentd.service >/dev/null 2>&1
systemctl restart lablantern-collect.path lablantern-action.path lablantern-agentd.service
exit 0
