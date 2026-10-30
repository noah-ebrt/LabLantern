#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
# Vollständig entfernen (deb: purge, rpm: 0): Token, CA, Passkey-Liste, Zustand und den Dienstbenutzer
if [ "$1" = "purge" ] || [ "$1" = "0" ]; then
  rm -rf /etc/vulnwatch /run/vulnwatch /run/vulnwatch-out /var/lib/vulnwatch-action
  userdel vulnwatch >/dev/null 2>&1 || true
  groupdel vulnwatch >/dev/null 2>&1 || true
fi
exit 0
