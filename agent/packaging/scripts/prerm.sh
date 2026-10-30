#!/bin/sh
# Nur beim Entfernen stoppen (deb: remove, rpm: 0), beim Upgrade übernimmt postinst den Neustart.
case "$1" in
  remove|0) systemctl disable --now vulnwatch-agentd.service vulnwatch-collect.path vulnwatch-action.path >/dev/null 2>&1 || true ;;
esac
exit 0
