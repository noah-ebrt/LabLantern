#!/bin/sh
# Server, Oberfläche, Agent und Worker neu bauen und starten (Ablauf aus AGENTS.md). Aufruf: npm run deploy in web/.
# - server und announce immer mit --force-recreate: ohne blieben beide schon auf dem alten Image
#   („Versions could not be checked … untagged image“). Ein laufender Scan übersteht das, der Worker wiederholt 30 s.
# - der Agent wird nur gebaut und signiert, wenn sich agent/ geändert hat; ein Fehler dort hält den Rest nicht auf.
# - der Worker nur, wenn sich sein Code geändert hat, und nie während eines Laufs: Neuerstellen bricht den Lauf ab.
set -eu
cd "$(dirname "$0")"

docker compose build server worker agent-build
docker compose up -d --no-deps --force-recreate server announce

agent_failed=0
if docker compose up -d agent-sign; then
    echo "Agent build done (the master picks up a new release within a minute)."
else
    agent_failed=1
    echo "Agent build FAILED, hosts keep the current agent: docker compose logs agent-build agent-sign" >&2
fi

# Image-IDs taugen nicht als Vergleich (containerd-Store, Attestierungen): Prüfsumme über die Dateien, die
# Dockerfile.worker kopiert, gegen die beim letzten Neuerstellen gemerkte
inputs=$(grep -E '^COPY [^-]' Dockerfile.worker | sed -E 's/^COPY //; s/ [^ ]+$//')
stamp=$( (cat Dockerfile.worker; cd .. && find $inputs -type f -print0 | sort -z | xargs -0 cat) | sha256sum | cut -c1-64)
if [ "$stamp" = "$(cat .worker-deployed 2>/dev/null)" ] && [ -n "$(docker compose ps -q worker)" ]; then
    echo "Worker unchanged, not recreated."
    exit $agent_failed
fi

active=$(docker compose exec -T server python -c "
import sqlite3
c = sqlite3.connect('file:/data/vulnwatch.db?mode=ro', uri=True)
print(c.execute(\"select count(*) from scan_runs where status in ('collecting', 'queued', 'running')\").fetchone()[0])" </dev/null)
if [ "$active" != "0" ]; then
    echo "A scan run is active: the worker was NOT recreated (it would abort the run)." >&2
    echo "Server and web UI are live. Run npm run deploy again once the run has finished." >&2
    exit 1
fi
docker compose up -d --no-deps --force-recreate worker
echo "$stamp" > .worker-deployed
echo "Worker recreated."
exit $agent_failed
