# vulnwatch

[![CI](https://github.com/noah-ebrt/vulwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/noah-ebrt/vulwatch/actions/workflows/ci.yml)

A self-hosted vulnerability monitor for a homelab or small network. One master collects inventories from small
agents on your Linux hosts, scans host packages and every running container image, rates the findings with fixed
rules and tells you every day what is critical, what is merely outdated and which check could not run. The web UI is
reachable only in your LAN.

- **Agents, no SSH keys:** each host runs a small agent (`.deb` / `.rpm`, amd64 and arm64) that sees Docker and
  Podman (rootful and rootless). It opens no port, sends its inventory to the master and accepts only a fixed list of
  commands. Reboots and agent updates need a passkey
  touch that the agent verifies itself.
- **Your own agent builds:** the master builds the agent from `agent/` in this repository and signs it with a key
  only your install has. Change the agent or `git pull`, rebuild, and one passkey touch updates all hosts.
- **Devices without an agent:** TrueNAS, Home Assistant and Proxmox VE are read through their API, read-only
  (version, pending updates, apps, alerts; for Proxmox also which VMs and LXCs have no agent yet). Unraid, Synology,
  OpenWrt and anything else that can run a small cron script report through the collector API.
- **Two scanners:** Grype (with CISA KEV and EPSS) and OSV-Scanner, offline, over host packages and container images.
- **Versions and end of life:** registry digests for every running image (outdated tag, newer version) and release
  lines from endoflife.date.
- **Exposure:** reads Nginx Proxy Manager, Traefik labels, Cloudflare Tunnel and the port forwards of a FRITZ!Box,
  OPNsense or UniFi router (all read-only) to learn which containers are reachable from the internet, checks proxy
  hostnames against public DNS, and rates their findings higher. It also checks the expiry of the NPM certificates.
- **No silent gaps:** a coverage matrix shows every system × check as ok, finding, queued or error, and every
  exposure source as a check of its own. A canary scan in every run proves the scanner still detects a known
  vulnerability. Findings can be snoozed and hosts excluded, always with a reason and an end date.
- **Reports and alerts:** daily report and immediate alerts through Apprise (mail, ntfy, Telegram, Signal, …),
  optional offsite watchdog (Healthchecks, Uptime Kuma or any URL), optional Prometheus metrics.
- **AI early warning (optional):** global security feeds every two hours plus a daily web search by Claude, narrowed
  to the images, OS and host packages you run. Versions are compared in code. A new hit arrives immediately with
  severity, the command to fix it per host, or the advisory's mitigation when there is no fix yet.

## How it works

```
 Hosts                                   Master (one Docker host in your LAN)
 ┌───────┐  HTTPS, pinned CA, token  ┌──────────────────────────────────────────────┐
 │ agent │ ────────────────────────► │ proxy (Caddy, own CA) → server (UI, API, rules)│ ──► mail / push
 └───────┘                           │                          worker (Grype, OSV)  │ ◄── vulnerability DBs
 Nginx Proxy Manager ◄── read-only ─ │                                               │
                                     └──────────────────────────────────────────────┘
                                                    │ pings
                                                    ▼  offsite watchdog (optional)
```

The worker processes untrusted input (SBOMs) and has no access to the database or the master key. Secrets you enter
(API keys, notification URLs, tokens) are stored encrypted and never shown again. Details: [SECURITY.md](SECURITY.md).

## Requirements

- A Linux host in your LAN with Docker and the Compose plugin, 4 GB RAM or more (8 GB recommended: OSV loads its
  databases into memory; `VULNWATCH_SCANNERS=grype` runs Grype alone and skips OSV), about 5 GB of disk for scanner
  databases and the 90-day raw data archive.
- Outbound HTTPS from that host (vulnerability databases, container registries, endoflife.date).
- A DNS name for the master in your LAN, `vulnwatch.lan` by default: one entry in your router or DNS server
  (AdGuard, Pi-hole, …), or in the hosts file of the machine you browse from. Passkeys need it (browsers refuse them
  on a bare IP address), and passkeys confirm agent updates and reboots. Agents themselves can use the IP.

## Quick start

```bash
git clone https://github.com/noah-ebrt/vulwatch.git vulnwatch && cd vulnwatch/deploy
cp .env.example .env              # set VULNWATCH_BIND_IP and VULNWATCH_HOSTNAMES
docker compose up -d --build      # first build takes a few minutes (it also builds and signs the agent)
docker compose logs server | grep "Setup token"
```

Open `https://<name or IP>:8443` and accept the certificate warning once (or trust the CA, see
[docs/INSTALL.md](docs/INSTALL.md#trust-the-certificate-authority)). The setup wizard asks for the setup token from
the log, then creates your admin account with password and authenticator app.

Then, in this order:

1. **Settings → Passkeys:** add a passkey. It confirms reboots and agent updates and signs the key list your agents
   trust, so add it before the first host. Browsers allow passkeys only on the DNS name with a trusted certificate:
   trust the CA first.
2. **Systems → Add Linux agent:** copy the setup command, run it on the host, compare the pairing code, approve.
3. **Settings → Notification channels:** add a mail or push channel and send a test.
4. Optional: offsite watchdog, Nginx Proxy Manager, Claude API key, Prometheus metrics.

The first full run starts at the scheduled time (default 03:00) or with **Scan now** on the overview. For a first
finding right away: connect one host, press **Scan now**, and watch the pipeline on the overview. The first run also
downloads the scanner databases, later runs reuse them.

**Updating vulnwatch:** `git pull && docker compose up -d --build` in `deploy/`. When the agent changed, **Systems**
offers the new version within a minute; **Update all** installs it on every host with one passkey touch.

## Documentation

| | |
| --- | --- |
| [docs/INSTALL.md](docs/INSTALL.md) | install, DNS and certificates, updates, backup and restore, moving to another host, troubleshooting |
| [docs/AGENTS.md](docs/AGENTS.md) | adding hosts, what an agent collects, commands, updates, removal, changing the agent |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | notifications, schedule and report frequency, snooze and exclusions, offsite watchdog, exposure sources (NPM, Traefik, Cloudflare Tunnel, FRITZ!Box, OPNsense, UniFi), TrueNAS, Home Assistant and Proxmox VE, collector scripts, version check, AI early warning, sharp drop alarm, configuration as JSON, Prometheus, what leaves your network |
| [collectors/README.md](collectors/README.md) | collector scripts for Unraid, Synology and OpenWrt, and the report format for your own |
| [SECURITY.md](SECURITY.md) | threat model: what a compromised master, agent or worker can and cannot do |
| [docs/INTERNALS.md](docs/INTERNALS.md) | architecture and data flow for contributors |

## Development

```bash
# server (Python 3.12)
cd server && python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-dev.txt
.venv/bin/pytest

# web UI (Node 22)
cd web && npm ci && npm test && npm run build

# agent (Go): tests run in the build image, no local Go needed
cd deploy && docker compose build agent-build
```

Dependencies are pinned with hashes and taken at the earliest 7 days after their release (`web/.npmrc`,
`uv pip compile --exclude-newer`). Changing the agent and rolling it out: [docs/AGENTS.md](docs/AGENTS.md#change-the-agent).
Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).

## Status and license

In daily use on a homelab with four hosts. TrueNAS and Home Assistant are covered through read-only connectors,
Windows hosts not yet. vulnwatch is a risk overview and alerting tool for a homelab: no EDR, no patch management.
Support is best effort. Nothing phones home: what leaves your network is listed in
[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md#what-leaves-your-network).

License: [PolyForm Noncommercial 1.0.0](LICENSE.md). Personal, homelab, research and non-profit use, changes and
sharing are free. Commercial use needs a separate license from the author. That makes vulnwatch source-available,
not open source in the OSI sense.
