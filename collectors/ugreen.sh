#!/bin/sh
# vulnwatch collector for UGREEN NAS (UGOS Pro, Debian-based): OS version, Debian packages (dpkg) and running
# containers (Docker app). The packages are checked against Debian's advisories. Image SBOMs only if syft is installed.
# Run as root (sudo -i after SSH login; enable SSH under Control Panel → Terminal). Setup: the command from
# "+ Add host → Other device". Keep the script on a data volume, a firmware update may reset the system disk:
#   export VW_DIR=/volume1/vulnwatch   (before the setup command, and in the cron line)
# Cron (crontab -e as root):
#   17 * * * * VW_DIR=/volume1/vulnwatch sh /volume1/vulnwatch/ugreen.sh
set -eu
D=${VW_DIR:-/etc/vulnwatch-collector}
# shellcheck source=/dev/null # setzt ID, VERSION_ID, PRETTY_NAME
. /etc/os-release

esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }

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

ugos=$(cat /etc/ugreen-version 2>/dev/null || true)   # UGOS-Version, falls das System sie dort ablegt
H=$(mktemp)
trap 'rm -f "$H"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$(cat "$D/token")" > "$H"
{
	printf '{"schema":"v1","os":{"id":"%s","name":"%s","version":"%s"},"packages":[' \
		"$(printf %s "${ID:-debian}" | tr -cd 'a-z0-9._-')" "$(printf 'UGOS Pro%s (%s)' "${ugos:+ $ugos}" "${PRETTY_NAME:-Debian}" | esc)" \
		"$(printf %s "${VERSION_ID:-?}" | esc)"
	dpkg-query -W -f='${Package} ${Version}\n' | esc |
		awk '{printf "%s{\"ecosystem\":\"deb\",\"name\":\"%s\",\"version\":\"%s\"}", (NR > 1 ? "," : ""), $1, $2}'
	printf '],"containers":['
	containers
	printf ']}'
} | curl -fsS --cacert "$D/ca.crt" -H @"$H" --data-binary @- "$(cat "$D/url")/api/collector/v1/report"
