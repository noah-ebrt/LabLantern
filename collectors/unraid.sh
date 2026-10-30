#!/bin/sh
# shellcheck disable=SC2154 # Variablen aus der Versionsdatei des Systems
# vulnwatch collector for Unraid: version, Slackware packages and running Docker containers.
# Image SBOMs only if syft is installed (otherwise the image scan shows n/a). Setup: the command from
# "+ Add host → Other device", run with VW_DIR=/boot/config/vulnwatch (/etc does not survive a reboot).
# Cron: User Scripts plugin, custom schedule "23 * * * *", script: sh /boot/config/vulnwatch/unraid.sh
set -eu
D=${VW_DIR:-/boot/config/vulnwatch}
# shellcheck source=/dev/null # setzt version
. /etc/unraid-version

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

H=$(mktemp)
trap 'rm -f "$H"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$(cat "$D/token")" > "$H"
{
	printf '{"schema":"v1","os":{"id":"unraid","name":"Unraid","version":"%s"},"packages":[' "$(printf %s "$version" | esc)"
	# /var/log/packages/<name>-<version>-<arch>-<build>
	# shellcheck disable=SC2012 # Paketnamen haben keine Leerzeichen
	ls /var/log/packages | esc | awk -F- '{n = $1; for (i = 2; i <= NF - 3; i++) n = n "-" $i
		printf "%s{\"ecosystem\":\"slackware\",\"name\":\"%s\",\"version\":\"%s-%s-%s\"}", (NR > 1 ? "," : ""), n, $(NF-2), $(NF-1), $NF}'
	printf '],"containers":['
	containers
	printf ']}'
} | curl -fsS --cacert "$D/ca.crt" -H @"$H" --data-binary @- "$(cat "$D/url")/api/collector/v1/report"
