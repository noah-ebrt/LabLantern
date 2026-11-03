#!/bin/sh
# Nur beim Entfernen stoppen (deb: remove, rpm: 0), beim Upgrade übernimmt postinst den Neustart.
case "$1" in
  remove|0) systemctl disable --now lablantern-agentd.service lablantern-collect.path lablantern-action.path >/dev/null 2>&1 || true ;;
esac
exit 0
