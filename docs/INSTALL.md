# Install and operate

## 1. Prepare the host

- Linux with Docker Engine and the Compose plugin (`docker compose version`).
- A fixed LAN IP. The master listens only on this address. Do not publish it through a public reverse proxy.
- Optional but recommended: a DNS name for the master, e.g. `vulnwatch.lan`, set in your router or DNS server
  (AdGuard, Pi-hole, …). Passkeys only work on a name. Agents can use either the name or the IP.

## 2. Configure and start

```bash
git clone https://github.com/noah-ebrt/vulnwatch.git vulnwatch
cd vulnwatch/deploy
cp .env.example .env
```

Edit `.env`:

| Variable | Required | Meaning |
| --- | --- | --- |
| `VULNWATCH_BIND_IP` | yes | LAN IP of this host. The stack refuses to start without it. |
| `VULNWATCH_HOSTNAMES` | yes | Comma-separated names and IPs under which browsers and agents reach the master. Certificates are issued only for these. |
| `VULNWATCH_PORT` | no | HTTPS port, default `8443`. |
| `VULNWATCH_SCANNERS` | no | `grype+osv` (default): two scanners. `grype`: light mode, OSV is switched off and loads no databases. Reports show OSV as "off (light mode)", not as an error. Findings only OSV reported are closed without counting as resolved, and come back as new when OSV is switched on again. |
| `VULNWATCH_TAG` | no | Image tag. Set it when you run a second stack on the same host, so the two do not overwrite each other's images. |
| `VULNWATCH_EDGE_SUBNET`, `_PROXY_IP`, `_SERVER_IP` | no | Internal network between proxy and server. Change only on a collision. |

**Memory.** Measured on 31 Oct 2026 on a homelab with 4 hosts and 53 running images (57 SBOMs), each mode scanning
all of them once against the current databases:

| Mode | Worker peak | Full scan |
| --- | --- | --- |
| `grype+osv` (default) | about 1.0 GB | about 28 minutes |
| `grype` (light mode) | about 1.0 GB | about 5 minutes |

Between runs the worker uses almost nothing, the server about 250 MB and the proxy about 50 MB. With OSV, a run
mostly costs time here, not memory. 4 GB of RAM is enough for a setup of this size; the rest of the host's memory
serves as file cache for the scanner databases. One exception: a very large image (a multi-gigabyte build image with
thousands of packages) can push a single Grype process past 25 GB until the kernel stops it. The worker has no
memory limit, so remove stopped build containers you don't want scanned; the deploy script does this for the agent
build.

```bash
docker compose up -d --build
docker compose ps -a                      # proxy, server, worker, announce; agent-* have exited (0)
docker compose logs server | grep "Setup token"
```

The services:

| Service | Does |
| --- | --- |
| `proxy` | Caddy: HTTPS with its own local certificate authority, the only published port |
| `server` | web UI, API for agents, rules, reports, encrypted secret store, scheduler |
| `worker` | runs Grype and OSV-Scanner on SBOMs; has no database, no secrets, only a job API |
| `announce` | announces the master via mDNS (`_vulnwatch._tcp`) so `vulnwatch-agent setup` finds it; host network, no rights |
| `agent-key`, `agent-build`, `agent-sign` | one-shot jobs on every start: build the agent packages from `agent/` when the code changed and sign them with this install's key; no network. The first build takes a few minutes |

## 3. First login

Open `https://<name>:8443`. The setup wizard needs the setup token from the log (it is new on every start until the
setup is done), then an authenticator app (TOTP) and a password. Afterwards:

1. **Settings → System → Passkeys → Add passkey.**
2. Add hosts ([AGENTS.md](AGENTS.md)). The agent packages are built on the first start; until they are ready,
   "Add Linux agent" says so. **Settings → System → Agent release** shows the version and the signing key.

### Trust the certificate authority

Caddy creates its own CA on the first start. Browsers warn until you trust it:

1. Download `https://<name>:8443/ca.crt`.
2. Import it as a trusted root (macOS Keychain, Windows "Trusted Root Certification Authorities", Firefox
   Settings → Certificates, Linux `/usr/local/share/ca-certificates/` + `update-ca-certificates`).

Agents do not need this. The setup command contains the CA fingerprint, and the agent pins it.

## 4. Updates

```bash
cd vulnwatch && git pull
cd deploy
docker compose build server worker
docker compose up -d --force-recreate server announce worker
```

The database schema is extended automatically on start (columns are only added, never removed). Agents update
themselves from the UI (**Systems → Update all**, one passkey touch).

## 5. Backup and restore

Everything lives in Docker volumes (prefixed with the Compose project name, by default `deploy_`):

| Volume | Contents | If lost |
| --- | --- | --- |
| `data` | database, SBOMs, 90-day raw data archive, caches | findings history and configuration are gone |
| `keys` | master key that encrypts the stored secrets | **all stored secrets are unreadable** (re-enter them) |
| `caddy_data` | the certificate authority | **every agent must be set up again** (they pin this CA) |
| `agent_key` | the key that signs your agent packages | agents accept **no more updates** until each is set up again |
| `agent_releases` | built agent packages | rebuilt on the next start |
| `worker_auth`, `grype_cache`, `caddy_config`, `agent_stage`, `agent_gocache` | worker token, scanner databases, build caches | recreated automatically |

Back up `data`, `keys`, `caddy_data` and `agent_key`. Keep a copy of the master key separately (e.g. in your password manager):
a backup of `data` without it is worth little. For a consistent database copy while the stack runs:

```bash
docker compose exec server python -c "import sqlite3; s=sqlite3.connect('/data/vulnwatch.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
```

Restore: stop the stack, copy the volumes back, start it. To move to another host, restore the same volumes there
and point the DNS name to the new IP. Agents follow the name, so nothing changes on the hosts.

## 6. Uninstall

Remove agents first (**Systems → Delete**, the agent uninstalls itself), then `docker compose down -v` in `deploy/`.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Stack does not start, "in .env setzen" | `VULNWATCH_BIND_IP` or `VULNWATCH_HOSTNAMES` missing in `.env` |
| Browser shows a certificate for the wrong name | the name is missing in `VULNWATCH_HOSTNAMES`; add it and recreate `server` |
| Passkeys cannot be added | open the UI by name, not by IP; the name must be in `VULNWATCH_HOSTNAMES` |
| Run fails with "Worker returned no result" | `docker compose logs worker`; the worker needs outbound HTTPS for its databases |
| Coverage shows "Container images: error" after an update | the worker runs an old image: `docker compose up -d --force-recreate worker` |
| Second stack on the same host breaks the first | give it its own `VULNWATCH_TAG`, `VULNWATCH_PORT`, edge subnet and project name (`docker compose -p name`) |
