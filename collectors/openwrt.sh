#!/bin/sh
# shellcheck disable=SC2154 # Variablen aus der Versionsdatei des Systems
# LabLantern collector for OpenWrt: release and installed packages (opkg, or apk from 24.10 on).
# Needs curl (opkg install curl, or apk add curl). Setup: the command from "+ Add host → Other device".
# Cron (crontab -e, then /etc/init.d/cron restart):
#   23 * * * * /usr/bin/lablantern-openwrt.sh
set -eu
D=${LL_DIR:-/etc/lablantern-collector}
# shellcheck source=/dev/null # setzt DISTRIB_RELEASE
. /etc/openwrt_release

esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }

packages() {   # "name version" je Zeile
	if command -v opkg >/dev/null 2>&1; then
		opkg list-installed | awk '{print $1, $3}'
	else
		apk list --installed | sed -n 's/^\(.*\)-\([^-]*-r[0-9]*\) .*/\1 \2/p'
	fi
}
eco=opkg
command -v opkg >/dev/null 2>&1 || eco=apk

H=$(mktemp)
trap 'rm -f "$H"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$(cat "$D/token")" > "$H"
{
	printf '{"schema":"v1","os":{"id":"openwrt","name":"OpenWrt","version":"%s"},"packages":[' \
		"$(printf %s "$DISTRIB_RELEASE" | esc)"
	packages | esc | awk -v e="$eco" '{printf "%s{\"ecosystem\":\"%s\",\"name\":\"%s\",\"version\":\"%s\"}", (NR > 1 ? "," : ""), e, $1, $2}'
	printf ']}'
} | curl -fsS --cacert "$D/ca.crt" -H @"$H" --data-binary @- "$(cat "$D/url")/api/collector/v1/report"
