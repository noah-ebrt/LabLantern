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
ip=$(sed -n 's/^LABLANTERN_BIND_IP=\([0-9.]*\).*/\1/p' .env)
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
# Der Name ist frei gewählt; solange ihn kein DNS kennt, findet ihn auch der Browser nicht
case $host in
    *[!0-9.]*) named=1 ;;
    *) named= ;;
esac
say "LabLantern is running."
say "  By IP:   https://$ip:$port   (works right away)"
[ -n "$named" ] && say "  By name: https://$host:$port   (needed for passkeys, once the name resolves)"
if [ -n "$token" ]; then
    say "Setup token: $token"
else
    say "No setup token in the log (setup already done?): docker compose logs server"
fi

if [ -z "$named" ]; then
    say ""
    say "Note: no DNS name configured (LABLANTERN_HOSTNAMES starts with an IP). Passkeys only work on a name:"
    say "  put one first in $root/deploy/.env, e.g. LABLANTERN_HOSTNAMES=lablantern.lan,$ip, then docker compose up -d"
elif ! getent ahostsv4 "$host" 2>/dev/null | grep -q "^$ip[[:space:]]"; then
    say ""
    say "Note: $host does not resolve to $ip yet, so browsers won't find it. Add a DNS entry $host -> $ip:"
    say "  - AdGuard Home: Filters -> DNS rewrites      - Pi-hole: Local DNS -> DNS Records"
    say "  - your router's local DNS / host names       - or one PC only: the line \"$ip $host\" in its hosts file"
    say "    (Windows: C:\\Windows\\System32\\drivers\\etc\\hosts, macOS/Linux: /etc/hosts)"
    say "  If the name still doesn't open, turn off \"secure DNS\" (DNS over HTTPS) in the browser: it skips your local DNS."
    say "  Until then, use https://$ip:$port for the setup."
fi

say ""
say "Next:"
say "  1. Open https://$ip:$port, enter the setup token, set a password and an authenticator app."
say "  2. Trust the certificate authority: https://$ip:$port/ca.crt (import it as a trusted root; passkeys need it)."
[ -n "$named" ] && say "  3. Switch to https://$host:$port and add a passkey: Settings -> System -> Passkeys." \
    || say "  3. Set a DNS name (see the note above), then add a passkey: Settings -> System -> Passkeys."
say "  4. Add your first host: Systems -> + Add host. Guide: https://github.com/noah-ebrt/LabLantern/blob/main/docs/INSTALL.md"
say "Updates later: git pull && docker compose up -d --build --force-recreate in $root/deploy (not during a scan)"
