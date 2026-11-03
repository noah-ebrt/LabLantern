#!/bin/sh
# Installiert den vulnwatch-Master mit einem Befehl:
#   curl -fsSL https://raw.githubusercontent.com/noah-ebrt/vulnwatch/main/install.sh | sh
# oder aus einem Klon: ./install.sh
# - außerhalb eines Klons wird nach ./vulnwatch geklont (anderes Ziel: VULNWATCH_DIR)
# - eine vorhandene deploy/.env bleibt unverändert; sonst werden LAN-IP und Name erkannt und, wenn ein Terminal da ist,
#   zur Bestätigung abgefragt (ohne Terminal: VULNWATCH_BIND_IP und VULNWATCH_NAME setzen oder die Erkennung gilt)
# - danach docker compose up -d --build und das Setup-Token aus dem Log
set -eu

repo_url=https://github.com/noah-ebrt/vulnwatch.git

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
    root=${VULNWATCH_DIR:-$PWD/vulnwatch}
    if [ -f "$root/deploy/compose.yaml" ]; then
        say "Using the existing checkout in $root"
    else
        command -v git >/dev/null 2>&1 || die "git is not installed"
        [ -e "$root" ] && die "$root exists but is not a vulnwatch checkout"
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
    ip=${VULNWATCH_BIND_IP:-$(ask "LAN IP of this host (the UI listens only here)" "$detected")}
    name=${VULNWATCH_NAME:-$(ask "DNS name for the master (passkeys need a name)" "vulnwatch.lan")}
    [ -n "$ip" ] || die "no LAN IP: set VULNWATCH_BIND_IP"
    sed -e "s/^VULNWATCH_BIND_IP=.*/VULNWATCH_BIND_IP=$ip/" \
        -e "s/^VULNWATCH_HOSTNAMES=.*/VULNWATCH_HOSTNAMES=$name,$ip/" .env.example >.env
    say "Wrote deploy/.env (VULNWATCH_BIND_IP=$ip, VULNWATCH_HOSTNAMES=$name,$ip)"
fi

say "Building and starting vulnwatch; the first build takes a few minutes ..."
docker compose up -d --build

host=$(sed -n 's/^VULNWATCH_HOSTNAMES=\([^,]*\).*/\1/p' .env)
port=$(sed -n 's/^VULNWATCH_PORT=\([0-9]*\).*/\1/p' .env)
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
say "vulnwatch is running: https://$host:$port"
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
say "Updates later: git pull && docker compose up -d --build in $root/deploy"
