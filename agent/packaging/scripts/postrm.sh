#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
# Vollständig entfernen (deb: purge, rpm: 0): Token, CA, Passkey-Liste, Zustand und den Dienstbenutzer
if [ "$1" = "purge" ] || [ "$1" = "0" ]; then
  rm -rf /etc/lablantern /run/lablantern /run/lablantern-out /var/lib/lablantern-action
  userdel lablantern >/dev/null 2>&1 || true
  groupdel lablantern >/dev/null 2>&1 || true
fi
exit 0
