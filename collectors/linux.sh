#!/bin/sh
# LabLantern collector for a Linux server where the agent is not wanted: OS version, installed packages (dpkg, rpm or
# apk) and running Docker containers. Debian/Ubuntu and rpm packages are sent with their source package, so they are
# checked like an agent's. Image SBOMs only if syft is installed. Also runs on TrueNAS SCALE.
# Setup: the command from "+ Add host → Other device". The server must reach LabLantern under the address in
# $LL_DIR/url; for a server outside your network see "Servers outside your network" in collectors/README.md.
# Root is only needed for Docker; without containers any user that can read $LL_DIR will do.
# On TrueNAS a system update replaces /etc: keep directory and script on a pool,
#   export LL_DIR=/mnt/tank/lablantern   (before the setup command, and in the cron job)
# Cron (crontab -e as root; on TrueNAS: System → Advanced Settings → Cron Jobs):
#   17 * * * * sh /usr/local/sbin/lablantern-linux.sh
set -eu
D=${LL_DIR:-/etc/lablantern-collector}
# shellcheck source=/dev/null # setzt ID, VERSION_ID, PRETTY_NAME
. "${LL_OS_RELEASE:-/etc/os-release}"
os_id=$(printf %s "${ID:-}" | tr -cd 'a-z0-9._-')

esc() { sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Eingabe: Name, Version, Architektur, Quellpaket[, Quellversion, Status], durch Tab getrennt. Die purl hat dieselbe
# Form wie die des Agenten (server/app/sbom.py, purl_for): Ohne Quellpaket fände der Abgleich z. B. libssl3 nicht
# unter openssl.
PKG_AWK='
function enc(s,   i, c, o) {
	o = ""
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		o = o (c ~ /[A-Za-z0-9._~-]/ ? c : hex[c])
	}
	return o
}
BEGIN {
	for (i = 33; i < 127; i++) hex[sprintf("%c", i)] = sprintf("%%%02X", i)
	eco = ENVIRON["LL_ECO"]; ns = ENVIRON["LL_NS"]; distro = ENVIRON["LL_DISTRO"]
}
$1 == "" || $2 == "" || $0 ~ /["\\]/ { next }
eco == "deb" && $6 !~ / installed$/ { next }
eco == "rpm" && $1 == "gpg-pubkey" { next }
{
	up = ""
	if (eco == "deb" && $4 != "" && ($4 != $1 || ($5 != "" && $5 != $2))) up = ($5 != "" && $5 != $2) ? $4 "@" $5 : $4
	if (eco == "rpm" && $4 != "(none)") up = $4
	printf "%s{\"ecosystem\":\"%s\",\"name\":\"%s\",\"version\":\"%s\"", (n++ ? "," : ""), eco, $1, $2
	if (eco != "apk" && ns != "" && ($1 $2 $3 up) ~ /^[!-~]*$/) {
		purl = "pkg:" eco "/" enc(ns) "/" enc($1) "@" enc($2) "?" ($3 != "" ? "arch=" enc($3) "&" : "") \
			"distro=" enc(distro) (up != "" ? "&upstream=" enc(up) : "")
		if (length(purl) <= 500) printf ",\"purl\":\"%s\"", purl
	}
	printf "}"
}'

pkg_json() { LC_ALL=C LL_ECO=$1 LL_NS=$os_id LL_DISTRO=$os_id${VERSION_ID:+-$VERSION_ID} awk -F'\t' "$PKG_AWK"; }

packages() {   # dieselbe Reihenfolge wie der Agent: dpkg vor rpm
	if command -v dpkg-query >/dev/null 2>&1; then
		# shellcheck disable=SC2016 # Platzhalter von dpkg-query, keine Shell-Variablen
		dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Status}\n' | pkg_json deb
	elif command -v rpm >/dev/null 2>&1; then
		rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' | pkg_json rpm
	elif command -v apk >/dev/null 2>&1; then
		apk list --installed 2>/dev/null | sed -n 's/^\(.*\)-\([^-]*-r[0-9]*\) .*/\1 \2/p' | tr ' ' '\t' | pkg_json apk
	fi
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

name=${PRETTY_NAME:-Linux}
if command -v midclt >/dev/null 2>&1 && [ -r /etc/version ]; then   # TrueNAS: die eigene Version vor die Debian-Basis
	name="TrueNAS $(cat /etc/version) ($name)"
fi
H=$(mktemp)
trap 'rm -f "$H"' EXIT
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$(cat "$D/token")" > "$H"
{
	printf '{"schema":"v1","os":{"id":"%s","name":"%s","version":"%s"},"packages":[' \
		"$os_id" "$(printf %s "$name" | esc)" "$(printf %s "${VERSION_ID:-?}" | esc)"
	packages
	printf '],"containers":['
	containers
	printf ']}'
} | curl -fsS --max-time 300 --cacert "$D/ca.crt" -H @"$H" --data-binary @- "$(cat "$D/url")/api/collector/v1/report"
