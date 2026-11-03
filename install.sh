#!/bin/sh
# Installiert den lablantern-Master mit einem Befehl:
#   curl -fsSL https://raw.githubusercontent.com/noah-ebrt/LabLantern/main/install.sh | sh
# oder aus einem Klon: ./install.sh
# - außerhalb eines Klons wird nach ./lablantern geklont (anderes Ziel: LABLANTERN_DIR)
# - eine vorhandene deploy/.env bleibt unverändert; sonst werden LAN-IP und Name erkannt und, wenn ein Terminal da ist,
#   zur Bestätigung abgefragt (ohne Terminal: LABLANTERN_BIND_IP und LABLANTERN_NAME setzen oder die Erkennung gilt)
# - danach docker compose up -d --build und das Setup-Token aus dem Log
set -eu

repo_url=https://github.com/noah-ebrt/LabLantern.git

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "Docker is not installed: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing (docker compose version)"
docker info >/dev/null 2>&1 || die "cannot talk to Docker: add your user to the docker group or run with sudo"

# Bei curl | sh ist $0 "sh": dann gibt es keinen Klon neben dem Skript
here=$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)
if [ -n "$here" ] && [ -f "$here/deploy/compose.yaml" ]; then
    root=$here
else
    root=${LABLANTERN_DIR:-$PWD/lablantern}
    if [ -f "$root/deploy/compose.yaml" ]; then
        say "Using the existing checkout in $root"
    else
        command -v git >/dev/null 2>&1 || die "git is not installed"
        [ -e "$root" ] && die "$root exists but is not a LabLantern checkout"
        git clone --depth 1 "$repo_url" "$root"
    fi
fi
cd "$root/deploy"

# Fragen gehen an /dev/tty, weil stdin bei curl | sh das Skript selbst ist
ask() {
    if (exec </dev/tty) 2>/dev/null; then
        printf '%s [%s]: ' "$1" "$2" >/dev/tty
        read -r answer </dev/tty || answer=
        printf '%s\n' "${answer:-$2}"
    else
        printf '%s\n' "$2"
    fi
}

if [ -f .env ]; then
    say "Keeping the existing deploy/.env"
else
    detected=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
    ip=${LABLANTERN_BIND_IP:-$(ask "LAN IP of this host (the UI listens only here)" "$detected")}
    name=${LABLANTERN_NAME:-$(ask "DNS name for the master (passkeys need a name)" "lablantern.lan")}
    [ -n "$ip" ] || die "no LAN IP: set LABLANTERN_BIND_IP"
    sed -e "s/^LABLANTERN_BIND_IP=.*/LABLANTERN_BIND_IP=$ip/" \
        -e "s/^LABLANTERN_HOSTNAMES=.*/LABLANTERN_HOSTNAMES=$name,$ip/" .env.example >.env
    say "Wrote deploy/.env (LABLANTERN_BIND_IP=$ip, LABLANTERN_HOSTNAMES=$name,$ip)"
fi

say "Building and starting LabLantern; the first build takes a few minutes ..."
docker compose up -d --build

host=$(sed -n 's/^LABLANTERN_HOSTNAMES=\([^,]*\).*/\1/p' .env)
port=$(sed -n 's/^LABLANTERN_PORT=\([0-9]*\).*/\1/p' .env)
port=${port:-8443}

# Das Token steht im Log, solange die Einrichtung nicht abgeschlossen ist
token=
i=0
while [ $i -lt 60 ]; do
    token=$(docker compose logs server 2>/dev/null | sed -n 's/.*Setup token: \([^ ]*\).*/\1/p' | tail -n 1)
    [ -n "$token" ] && break
    i=$((i + 1))
    sleep 2
done

say ""
say "lablantern is running: https://$host:$port"
if [ -n "$token" ]; then
    say "Setup token:          $token"
else
    say "No setup token in the log (setup already done?): docker compose logs server"
fi
say ""
say "Next:"
say "  1. Point $host to this host in your router or DNS (or the hosts file of your PC)."
say "  2. Trust the certificate authority: https://$host:$port/ca.crt (passkeys need it)."
say "  3. Open https://$host:$port, enter the setup token, then add a passkey and your first host."
say "Updates later: git pull && docker compose up -d --build --force-recreate in $root/deploy (not during a scan)"
