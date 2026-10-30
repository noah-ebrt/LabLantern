#!/bin/sh
set -e
getent group vulnwatch >/dev/null || groupadd --system vulnwatch
getent passwd vulnwatch >/dev/null || useradd --system --gid vulnwatch --home-dir /nonexistent \
  --no-create-home --shell /usr/sbin/nologin vulnwatch
# Der Daemon darf Token und CA lesen, schreiben darf nur root.
if [ -d /etc/vulnwatch ]; then
  chown root:vulnwatch /etc/vulnwatch
  chmod 0750 /etc/vulnwatch
  if [ -f /etc/vulnwatch/agent.json ]; then
    chown root:vulnwatch /etc/vulnwatch/agent.json
    chmod 0640 /etc/vulnwatch/agent.json
  fi
fi
systemd-tmpfiles --create /usr/lib/tmpfiles.d/vulnwatch.conf
systemctl daemon-reload
systemctl enable vulnwatch-collect.path vulnwatch-action.path vulnwatch-agentd.service >/dev/null 2>&1
systemctl restart vulnwatch-collect.path vulnwatch-action.path vulnwatch-agentd.service
exit 0
