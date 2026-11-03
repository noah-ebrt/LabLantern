#!/bin/sh
# shellcheck disable=SC2154 # Variablen aus der Versionsdatei des Systems
# LabLantern collector for Synology DSM: DSM version, installed packages and running containers
# (Container Manager). Image SBOMs only if syft is installed. Run as root. Setup: the command from
# "+ Add host → Other device". Cron: Control Panel → Task Scheduler → Scheduled Task → User-defined script,
# user root, hourly, command: sh /volume1/lablantern/synology.sh
set -eu
D=${LL_DIR:-/etc/lablantern-collector}
# shellcheck source=/dev/null # setzt productversion, buildnumber
. /etc.defaults/VERSION
PATH=$PATH:/usr/local/bin

esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }

packages() {   # "name version" je Zeile, aus den INFO-Dateien der Pakete
	for info in /var/packages/*/INFO; do
		name=$(sed -n 's/^package="\(.*\)"$/\1/p' "$info")
		ver=$(sed -n 's/^version="\(.*\)"$/\1/p' "$info")
		[ -n "$name" ] && [ -n "$ver" ] && printf '%s %s\n' "$name" "$ver"
	done
	return 0
}

containers() {   # höchstens 50, wie die API erlaubt
	command -v docker >/dev/null 2>&1 || return 0
	n=0
	for id in $(docker ps -q | head -n 50); do
		# shellcheck disable=SC2046 # Name, Image und ID trennen
		set -- $(docker inspect -f '{{.Name}} {{.Config.Image}} {{.Image}}' "$id")
		digests=$(docker image inspect -f '{{range .RepoDigests}}"{{.}}",{{end}}' "$3" | sed 's/,$//')
		[ "$n" -gt 0 ] && printf ','
		printf '{"name":"%s","image":"%s","image_id":"%s","repo_digests":[%s]' "${1#/}" "$(printf %s "$2" | esc)" "$3" "$digests"
		command -v syft >/dev/null 2>&1 && printf ',"sbom":%s' "$(syft -q "docker:$3" -o cyclonedx-json)"
		printf '}'
		n=$((n + 1))
	done
}

H=$(mktemp)
trap 'rm -f "$H"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$(cat "$D/token")" > "$H"
{
	printf '{"schema":"v1","os":{"id":"dsm","name":"Synology DSM","version":"%s-%s"},"packages":[' \
		"$(printf %s "$productversion" | esc)" "$buildnumber"
	packages | esc | awk '{printf "%s{\"ecosystem\":\"synology\",\"name\":\"%s\",\"version\":\"%s\"}", (NR > 1 ? "," : ""), $1, $2}'
	printf '],"containers":['
	containers
	printf ']}'
} | curl -fsS --cacert "$D/ca.crt" -H @"$H" --data-binary @- "$(cat "$D/url")/api/collector/v1/report"
