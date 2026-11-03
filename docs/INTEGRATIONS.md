# Integrations and settings

Everything here is configured under **Settings**. Secrets (passwords, tokens, URLs with keys) are stored encrypted
and never shown again. Each card says whether it is required or optional.

## Schedule

- **Daily full run** (default 03:00): asks every agent for fresh data (waits at most 10 minutes), scans with Grype and
  OSV, checks versions and the AI early warning, rates, and sends the report.
- **Short run** (default every 12 hours, aligned to the daily run): scans the agents' latest data against a fresh
  database. It only notifies when something new is critical or high, or when a check fails.
- **System time zone:** used for the schedule and for every time shown in the UI.

**Scan now** on the overview starts a full run. **Scan latest data** in the pipeline starts a short run.

**Report frequency** (same card): daily, weekly on a chosen weekday, or only on change (new, resolved, reopened or
re-rated findings, or a failed check). Reports can also be paused until a date, e.g. for a holiday; the overview shows
the pause. Alerts and errors are sent the same day whatever is set here: a critical finding never waits a week.

## Snooze findings and exclude from coverage

- **Snooze a finding** (Findings → Snooze): until a date, at most 180 days, with a reason, for this occurrence or for
  the CVE in this component everywhere. A snoozed finding doesn't raise the alarm level but is still counted and
  listed in the report. The snooze ends by itself on its date, when the CVE lands on the CISA KEV list, when the
  rating goes up, or when a fix appears where there was none. A snooze on an image survives its tag updates.
- **Exclude from coverage** (a host's coverage dialog, or a Proxmox guest in the overview): until a date, at most
  180 days, with a reason, e.g. a stopped test VM. It then counts neither as checked nor as a gap and is shown as
  excluded with the reason; on the date it counts again.

## Notification channels (required for alerts)

One channel per Apprise URL. Mail has a form with presets (Gmail, iCloud, Outlook, GMX, WEB.DE, Posteo, custom
SMTP). Anything else Apprise supports works as a URL, e.g. `ntfy://topic`, `tgram://bottoken/chatid`,
`signal://…`. **Send test notification** delivers to every channel.

The report subject says what matters: `[IMMEDIATE ALERT]` (invalid run, failed canary, no data from a host twice in
a row), `[ALERT]` (critical findings), `[ERROR]` (systems not checked), `[WARNING]` (high findings), `[OK]`.

## Offsite watchdog (optional)

A monitor outside your network alerts you when LabLantern itself goes quiet (host off, power or internet gone, a run
stuck). Choose the service once, then paste one URL per check:

| Service | Ping URL | What LabLantern sends |
| --- | --- | --- |
| Healthchecks (self-hosted or healthchecks.io) | `https://…/ping/<uuid>` | start, success, `/fail` with the reason |
| Uptime Kuma | push monitor URL `https://…/api/push/<token>` | `status=up` or `status=down` with a message |
| Custom URL | anything that alerts when requests stop | a POST on success only; silence is the alarm |

Checks: **Heartbeat** (every 1–60 minutes while master and worker are alive), **Daily run**, **Short run**
(optional). The card shows what to set up in the monitor for each check (period, cron, grace).

## Nginx Proxy Manager (optional)

Create a dedicated NPM user without admin rights: item visibility **All items**, Proxy Hosts **View only**,
everything else hidden. NPM itself forces Access Lists and Certificates to view only. Enter the admin URL (port 81),
the user and password, and the host NPM runs on.

LabLantern then reads every 6 hours:

- **Exposure:** proxy targets are mapped to containers by container name or by host IP and published port.
  Findings of internet-exposed containers are rated higher (CVSS 9+ critical, CVSS 7+ with fix high). Targets it
  cannot map are listed. Mark those containers by hand in the host dialog.
- **Public DNS check:** a proxy route only counts as internet-exposed if one of its domains resolves to a public
  address in public DNS (asked via Cloudflare DNS-over-HTTPS). Routes whose names only resolve to LAN addresses, or
  not at all, are listed as "only reachable in the LAN". Names ending in `.lan`, `.home.arpa`, `.local` or
  `.internal` are never sent. If the check fails, the route counts as exposed and NPM shows as an error in the
  coverage matrix. In the NPM card you can mark a name as public or LAN only by hand; that wins over DNS.
- **TLS certificates** of active proxy hosts: under 20 days left is a medium finding (NPM renews at 30 days), under 7
  days or expired is high.

It never reads private keys, access lists or DNS credentials. The user stays read-only, so LabLantern cannot renew or
change certificates.

## Router port forwards: FRITZ!Box, OPNsense, UniFi (optional)

Settings › Versions & exposure. LabLantern reads the port forwards of the router every 6 hours and matches each target
(internal IP and port) to a container or a host service, like the NPM routes. That also covers services that bypass
the proxy (game servers, VPN). A forward without a clear target is listed with the reason, and a failed read is an
error in the coverage matrix while the last known mapping stays.

| Router | Access | Notes |
| --- | --- | --- |
| FRITZ!Box | TR-064 on port 49000, a FRITZ!Box user with "FRITZ!Box settings" | IPv4 only; mark IPv6 releases by hand |
| OPNsense 26.1 or newer | API key and secret of a user with only the privilege for Firewall: NAT: Destination NAT | `GET /api/firewall/d_nat/search_rule`. OPNsense has no read-only variant of that privilege; LabLantern only sends GET requests |
| UniFi OS console, Network 9 or newer | API key of an admin with the role View Only (Settings › Control Plane › Integrations) | `GET /proxy/network/api/s/<site>/rest/portforward` |

OPNsense and UniFi only over HTTPS; the certificate is pinned when you save, as for TrueNAS. Port and target aliases
in OPNsense are not resolved: such rules appear in the list to mark by hand. The OPNsense and UniFi readers were
built from the vendors' API documentation and not yet tested against a real device. pfSense has no comparable API.

## Cloudflare Tunnel (optional)

Create an API token under My Profile › API Tokens with only **Account · Cloudflare Tunnel · Read** for your account,
and enter it with the account ID in Settings, below the router cards. LabLantern then reads, every 6 hours, the public hostnames of
every remotely managed tunnel and maps each origin to a container or host:

- `http://<container>:<port>`: the container with that name (the one next to cloudflared if several hosts have it),
- `http://<IP>:<port>` or `http://<host name>:<port>`: the container or host service on that port,
- `http://localhost:<port>`: the host running the `cloudflare/cloudflared` container.

A tunnel route is public by definition, so there is no DNS check. Tunnels managed with a local `config.yml` have no
readable rules; they are listed as not matched, as are origins LabLantern cannot map. Mark those by hand in the host
dialog. If the API fails, the last mapping stays and Cloudflare Tunnel shows as an error in the coverage matrix.

## Traefik (Docker labels, built in)

Agents report the router labels of their containers (`traefik.enable`, `traefik.http.routers.*`,
`traefik.tcp.routers.*`), never middlewares or services, which often carry credentials. Each `Host()` or `HostSNI()`
name goes through the same public DNS check as NPM, and the container is marked "via Traefik: app.example.com".
In Settings › Exposure › Traefik you can mark an entrypoint such as `lan` as LAN only or always public; a name marked by hand
still wins. Rules that cannot be checked (`HostRegexp`, ``HostSNI(`*`)``, no rule) are listed there too. Only the
Docker provider on the same host is visible; routes from Traefik's file provider are missing.

## Devices without agent: TrueNAS, Home Assistant, Proxmox VE, Synology DSM and OPNsense

Added under **Systems → Add host**, not in the settings: each device becomes a host of its own, with findings, a
row in the coverage matrix and the actions **Test**, **Edit** and **Delete** in the host list. LabLantern only reads,
every 6 hours (and on **Test**). It never writes to the device, and the device never connects to LabLantern.

**TLS:** over HTTPS LabLantern reads the device's certificate when you save and pins its SHA-256 fingerprint
(TrueNAS usually has a self-signed one). The key or token is only sent over a connection with exactly that
certificate. After a certificate change the test fails with "certificate changed"; **Trust new certificate** in the
host list pins the new one. Compare the fingerprint on the device first if you did not change it yourself.

**Coverage:** only the checks the API provides are rated. The others show **N/A** and don't count towards
coverage. A failed or older-than-24-hour read is an error in the matrix, never a silent gap.

**Ratings:** an update on the same release line (the first two numbers equal: 25.04.2.4 → 25.04.2.5,
2026.10.1 → 2026.10.3) is high, a new line is medium, as with container versions.

**Storage:** for TrueNAS, Synology DSM and Proxmox VE LabLantern also reads pools and drives into one common shape:
each pool with its layout (RAIDZ1, 2× MIRROR, SHR …), state and fill level, each drive with model, size, type,
temperature where the API has it, and health. The host's details show them side by side per pool, one disk symbol
per drive (green healthy, yellow warning, red failing, dashed when the API gives no state), with model and
temperature on hover. A failing drive is a finding (high; drive errors or warnings medium). On
TrueNAS that comes from the pool topology (`disk.query`, `disk.temperatures`, `boot.get_state`), on Proxmox from
`/nodes/{node}/disks/list` and `/disks/zfs` (PVEAuditor is enough), on Synology from `SYNO.Storage.CGI.Storage`
(administrators only).

Agent hosts show the same in their details, but only on bare metal: in a VM or container the
drives are virtual or belong to the host, so the agent skips them. Drives come from `lsblk`, ZFS pools from `zpool`,
mdraid from `/proc/mdstat`. Health and temperature need `smartctl` (package `smartmontools`); without it every drive
shows a dashed symbol. Sleeping disks are not woken (`smartctl -n standby`).

### TrueNAS

Prepare on the NAS:

1. Credentials → Users → Add: a user `lablantern` with the role **Read-only Administrator**.
2. An API key for that user. Before TrueNAS 24.10, API keys always have full admin rights; update first if you can.
3. Use `https://` in the URL. TrueNAS revokes a key that was ever sent over plain HTTP, so LabLantern refuses
   `http://` for TrueNAS.

API used (read only):

| | |
| --- | --- |
| Connection | WebSocket `wss://<host>/api/current`, JSON-RPC 2.0. Before 24.10: `wss://<host>/websocket` (older protocol, same methods) |
| Login | `auth.login_with_api_key` |
| Calls | `system.info` (version), `update.status` (25.10+) or `update.check_available` (older), `alert.list`, `app.query` (24.10+) or `chart.release.query` (older) |
| Health and backups | `pool.query`, `pool.scrub.query`, `pool.snapshottask.query`, `replication.query`, `cloudsync.query`, `cloud_backup.query`, `rsynctask.query` |
| Settings | `service.query`, `smb.config`, `ssh.config`, `ftp.config`, `system.general.config`, `auth.twofactor.config`, `user.query` |

Each call in the last two rows is optional: if a version lacks it or the role may not read it, only that check is
missing. `ssh.config` also returns the SSH host private keys; LabLantern keeps only the password switch.

| Finding | Source | Rating |
| --- | --- | --- |
| System update | `update.*` | same line high, new line medium |
| App update | `upgrade_available`, compared by app package version (`version` → `latest_version`); the title shows the app version too | same line high, new line medium |
| Newer app image | `image_updates_available` | high |
| Alert | `alert.list` | CRITICAL/ALERT/EMERGENCY high, ERROR/WARNING medium, INFO and dismissed ones none |
| End of life | installed release line at endoflife.date | high |
| Pool | not healthy (DEGRADED, FAULTED …) high; usage 90 % medium, 95 % high. Missing ZFS features are no finding | |
| Scrub | errors in the last scrub high; older than the scrub task's threshold plus 7 days, never run, or no scrub task medium. After a resilver the scrub age is unknown and not rated | |
| Backup tasks | replication, cloud sync, cloud backup, rsync: last run failed medium; last success older than 2× its schedule plus a day medium, 4× plus three days high (daily: 3 / 7 days, weekly: 15 / 31). Snapshot tasks only when failed. No replication, cloud sync or rsync task at all medium | |
| Settings | SMB1 on while SMB runs high; SSH password login while SSH runs, FTP without TLS while FTP runs, web UI without HTTPS redirect, 2FA off, administrators without 2FA medium | |

After a reboot TrueNAS forgets the last run of some tasks; they stay unrated until they run again. A pending
reboot after an update shows in the **Reboot** column. The installed version and the apps also feed the AI early
warning.

### Home Assistant

Prepare in Home Assistant:

1. Settings → People → Users → Add user: `lablantern`, administrator off.
2. Log in as that user: Profile → Security → Long-lived access tokens → Create token.
3. URL with port, e.g. `http://homeassistant.lan:8123` (or `https://` if Home Assistant serves TLS itself).

API used (read only): `GET /api/states` and `GET /api/config` with `Authorization: Bearer <token>`. Entity IDs
depend on Home Assistant's language, so LabLantern recognises entities by device class, unit and value type, not by
name. From `/api/config` it keeps only the state and the list of integrations, never the location or URLs.

| Finding | Source | Rating |
| --- | --- | --- |
| Update available | `update.*` in state `on` (Core, OS, Supervisor, add-ons, ESPHome, firmware). Skipped versions are off | same line high, new line medium |
| Backup age | timestamps of `sensor.backup_*` (backup integration): the oldest past one is the last success, the newest the last attempt | over 3 days medium, over 7 days or never high; last attempt failed medium; no backup integration medium |
| Recovery/safe mode | `/api/config` → `recovery_mode`, `safe_mode` | high |
| Disk usage | System Monitor `…disk_use_percent…` in %, Supervisor `…_disk_used` / `…_disk_total` | from 90 % medium, from 95 % high |
| Low battery | `device_class: battery`: sensors below 15 %, binary sensors `on` | info |

The loaded integrations (Shelly, Matter, Nuki, Tuya, …) feed the AI early warning, so reports about them are
matched to this Home Assistant. If NPM forwards a domain to the device, its findings are marked internet-exposed.

### Proxmox VE

Read with an API token of a user with the role **PVEAuditor** (read-only, path `/`, privilege separation off). The
guide under **Systems → Add host → Proxmox VE** walks through it. HTTPS only, certificate pinned as above.

| What | From | Rating |
| --- | --- | --- |
| Newer Proxmox VE per node | `pve-manager` in `/nodes/{node}/apt/update` | same line high, new line medium |
| End of life per node | endoflife.date `proxmox-ve` | as for other products |
| Guests without agent | `/cluster/resources?type=vm` | a gap in the coverage |

**Guests:** every VM and LXC is matched to an agent host, first by name (case-insensitive, without the domain), then
by an address: from the LXC configuration (`net0 ip=`), or from the QEMU guest agent if it runs. Matched guests are
covered by their host's row. A running guest without an agent is a gap ("no agent", with its addresses), a stopped
one too ("stopped, not checked") until you exclude it in the overview with a reason and an end date. Templates don't
count. The PVE node itself is Debian: install the agent on it for package CVEs and security updates; the connector
adds the view of the guests and the PVE version.

**Older PVE releases** list pending updates only for tokens with `Sys.Modify`, a write privilege. LabLantern
doesn't ask for it: the version check then shows N/A with that reason, end of life is still checked.

### Synology DSM

DSM has no API tokens and no read-only role, so LabLantern logs in with an account and its password (one session per
read, logged out afterwards; sent as a POST body, never in a URL). The guide under **Systems → Add host → Synology
DSM** walks through it: a dedicated user `lablantern` in the **administrators** group, all applications and shared
folders denied, no 2-factor authentication. Without admin rights LabLantern reads only the version; the update check,
packages and storage show N/A with the reason "not an administrator", never ok. HTTPS only (port 5001), certificate
pinned as above.

| What | From | Rating |
| --- | --- | --- |
| Newer DSM | `SYNO.Core.Upgrade.Server` check | same line high, new line medium |
| Storage pool or volume degraded, crashed | `SYNO.Storage.CGI.Storage` load_info | high; "attention" or "warning" medium |
| Volume full | same | 90 % medium, 95 % high |
| Drive crashed or failing (status or S.M.A.R.T.) | same | high; "warning" medium |
| Installed packages | `SYNO.Core.Package` list | no finding; watched by the AI early warning |

endoflife.date doesn't list DSM, so there is no end-of-life finding. Unknown states of pools, volumes and drives are
shown in the host's details but are no finding. The collector script `collectors/synology.sh` is the alternative
for container images (with syft on the NAS); you can use both, they appear as two hosts. Built from the DSM Web API,
not yet tested against a real NAS.

### OPNsense

Read with an API key and secret of a user with the privilege **System: Firmware** (System → Access → Users → API
keys). The same key also reads the port forwards (see above) if the user has **Firewall: NAT: Destination NAT** too.
HTTPS only, certificate pinned as above.

| What | From | Rating |
| --- | --- | --- |
| Newer OPNsense | `upgrade_packages` of `/api/core/firmware/status` (the core package) | same line high, new line medium |
| Other pending updates (base, kernel, packages) without a core update | same | one finding, medium |
| Major upgrade available | `upgrade_major_version` | medium |
| End of life of the release line | endoflife.date `opnsense` | as for other products |
| Installed plugins | `/api/core/firmware/info` | no finding; watched by the AI early warning (`os-haproxy` as "haproxy") |

OPNsense knows about updates only after it has checked (System → Firmware → Status → Check for updates, or a cron
job). LabLantern doesn't start a check, since that would be a write: until the firewall has checked, the version check
shows N/A with that reason; end of life is still checked. Built from the OPNsense API docs, not yet tested against a
real firewall.

## Other devices: collector scripts

For devices where neither the agent nor an API connector fits (Unraid, UGREEN UGOS Pro, Synology DSM, OpenWrt …), a cron script on the
device reports OS version, packages and containers to LabLantern (`POST /api/collector/v1/report`, one token per
device). LabLantern only receives and never answers with a command. Only what the report provides is rated; the rest
is n/a. Scripts, setup and limits: [`collectors/README.md`](../collectors/README.md). The traffic stays in your
network: the device talks to LabLantern, LabLantern contacts nothing for it.

## Sharp drop alarm

If a host's open scanner findings fall by at least 50 % in one run (and it had at least 20 before), the run report
becomes an immediate alert. A compromised worker or a doctored SBOM can report a host as clean; a large update can
trigger it too, the alert says what to check. Threshold, minimum and on/off under **Settings → Alerts & reports → Alert rules**.

## Configuration as JSON

**Settings → System → Configuration as JSON** shows every setting in one document, also scriptable with
`GET`/`PUT /api/settings/config`. Saving writes each changed section through the same endpoint as the form
(same checks, same audit entry). Secrets appear as `null` and are kept; a text replaces them. Lists
(`notifications`, `appliances`) are complete: an entry missing from the document is removed. Users, passkeys and
agent tokens are not part of it.

## Version check (built in)

Every 6 hours, for every running container image: the registry digest of its tag (outdated image → high) and newer
version tags (newer patch → high, newer line → medium). Release lines of operating systems and images are checked
against endoflife.date (end of life → high). Results appear as findings (filter **Versions & EOL**), in the
**Versions** column of the coverage matrix and per container in the host dialog. **Check now** runs a pass
immediately.

## AI early warning (optional)

Needs an AI provider under **Settings → AI early warning → AI provider**: an Anthropic or OpenAI API key (use a dedicated key with a
spend limit) or an OpenAI-compatible endpoint such as Ollama. Each task (read feeds, web research, vendor check) has
its own provider and model under **Models per task**. Reading feeds works with any provider; web research and the
vendor check need Anthropic or OpenAI, because they use the provider's web search. If a call fails, the task shows the
provider's own error message (key and address removed). There is no automatic fallback to another provider, and
entries that could not be read are marked **needs review**. It watches what you actually run: container
images, operating systems and kernels, network-facing host packages from the agents' SBOMs (Tailscale, OpenSSH,
OpenSSL, Docker, containerd, sudo, glibc, systemd, Samba, CUPS, nginx, Apache, WireGuard, …) and products you add by
hand under **Early warnings → Feeds & products**.

**Feeds**, every 2 hours and with every full run. The defaults are global:

- News: The Hacker News, BleepingComputer, SecurityWeek, heise Security, Help Net Security, The Register, Security
  Affairs, SANS Internet Storm Center
- CERTs and agencies: BSI CERT-Bund (also covers vendors without a feed of their own, such as AVM, Synology, QNAP and
  Ubiquiti), CISA advisories, CERT/CC vulnerability notes
- Disclosures, exploits and research: oss-security, Full Disclosure, Zero Day Initiative, Exploit-DB, watchTowr Labs,
  Socket (malicious npm and PyPI packages)
- Vendors: Tailscale security bulletins, GitLab security releases, OPNsense announcements, Grafana security advisories

Extra feeds cost little: each feed is downloaded, but only matching entries go to the AI. Only entries from
the last 30 days that name one of your products go to the AI. Host packages and operating systems must appear in
the title, because curl or Ubuntu are mentioned in passing all the time. On a vendor's own feed (the feed's domain is
the product's name, e.g. `tailscale.com`) every entry counts.

**Web research**, once a day (on by default, **Research now** starts one): the research model searches the web worldwide for
advisories, security releases and exploitation reports on your products from the last days, so you hear about an
issue before any feed you added carries it. Default model: latest Sonnet (web search needs a capable model). A pass
runs up to 15 searches and costs about $0.20–0.40 with Sonnet (roughly $6–12 a month); Haiku is cheaper but finds less. Results that a feed already brought (same link or CVE) are skipped.

For both, the AI only extracts facts through a fixed schema: affected and fixed versions, CVEs, exploited, public
exploit, the severity the source states, the worst impact, and the mitigations it recommends. Everything after that is code:

| Step | Rule |
| --- | --- |
| Rating | **affected** (installed version in an affected range), **not affected**, or **needs review** (no comparable versions, version unknown, or a distribution build: Ubuntu and Debian backport fixes without changing the upstream version, so the next Grype/OSV scan decides) |
| Severity | **high** when exploited, a public exploit exists, the source says critical, or the flaw gives code execution, root or an authentication bypass and the source does not rate it lower (fresh flaws often have no rating yet); **medium** when the source says high; **info** otherwise. Never above high |
| Steps | per host, from the inventory: `apt`/`dnf`/`apk` command for host packages, `docker compose pull && up -d` in the compose directory (or "change the tag" for pinned versions), OS and kernel upgrades. Without a fixed version, the advisory's mitigations |
| Finding | affected entries become findings with the same severity (filter source **AI**) |
| Alert | sent immediately as `[EARLY WARNING]`, once per entry: affected at medium or high, or needs review at high (e.g. an exploited flaw in a product you run whose fixed version is not known yet) |

The AI never removes or downgrades a finding. Feed and web content is treated as data, never as instructions.

Model for reading feeds: **Latest Haiku (automatic)** by default when Anthropic is configured (with only OpenAI or
your own endpoint, choose a model yourself), or any model your provider offers (Settings → AI early warning
→ Models per task). The same page sets the models for the web research and the vendor check.

### Local models with Ollama

Ollama reads feeds on your own hardware, so nothing leaves your network. On the machine that runs Ollama:

1. Make it listen on the network: `OLLAMA_HOST=0.0.0.0:11434` (for the systemd service: `systemctl edit ollama`, add
   `Environment="OLLAMA_HOST=0.0.0.0:11434"`, restart). Pull a model that supports tool calls, e.g. `ollama pull <model>`.
2. Allow port 11434 in the firewall for the private network only (never expose Ollama to the internet; it has no login).
3. In LabLantern, **Settings → AI early warning → AI provider → OpenAI-compatible**: Base URL `http://<ollama-host>:11434/v1` (note the
   `/v1`), leave the API key empty, **Save**, then **Test**.
4. Under **Models per task** pick the Ollama model for reading feeds.

The base URL is stored like a key (the settings page shows scheme, host, port and path, never credentials or query parameters). Local models are slower (a 27B model needs a minute or more
per entry; LabLantern waits up to 10 minutes for one answer and does not retry) and read less reliably than the hosted ones; they do not offer web search, so research and the vendor
check stay on Anthropic or OpenAI.

## Prometheus metrics (optional)

**Settings → System → Prometheus metrics → Create token** turns on `https://<master>:8443/metrics` and shows the token once,
together with a scrape config. Metrics include open findings by severity and system, coverage and the status of every
check, agent report age and connection, last run result and duration, canary, scanner database age, early warnings,
TLS certificate days left and watchdog pings. No finding details, no secrets.

```yaml
- job_name: lablantern
  scheme: https
  authorization:
    credentials: <token>
  tls_config:
    ca_file: /etc/prometheus/lablantern-ca.crt   # from https://<master>:8443/ca.crt
  static_configs:
    - targets: ['lablantern.lan:8443']
```

## What leaves your network

LabLantern has no telemetry and no update check of its own. These are the outbound connections, all over HTTPS (except a custom AI endpoint, which may be plain `http://` on your network):

| To | When | What is sent |
| --- | --- | --- |
| Grype and OSV-Scanner databases (Anchore, osv.dev) | every run | nothing about you: the worker downloads the databases and scans offline |
| Container registries of your images (Docker Hub, ghcr.io, …) | every run | image names and tags, to compare digests |
| endoflife.date | daily | product names (e.g. `debian`, `postgres`) |
| api.cloudflare.com (with Cloudflare Tunnel connected) | every 6 hours | your API token and account ID; it reads the tunnel list and ingress rules |
| cloudflare-dns.com (with NPM connected) | every 6 hours | the domain names of your proxy routes, except `.lan`, `.home.arpa`, `.local`, `.internal` |
| Security feeds (AI early warning, optional) | every two hours | nothing: plain feed downloads |
| AI provider (Anthropic, OpenAI or your own endpoint; AI early warning, optional) | daily and per new feed entry | product names and versions, never secrets, addresses or host names |
| Your notification channels and offsite watchdog (optional) | per report, alert, ping | the report or alert text, the ping |

Inside the LAN only: agents, collector scripts, Nginx Proxy Manager, FRITZ!Box, OPNsense, UniFi, TrueNAS, Home
Assistant, Proxmox VE and Synology DSM. Building the images and the
agent fetches packages from Docker Hub, PyPI, npm and the Go module proxy, at build time only.
