# Collector scripts

For devices where the LabLantern agent can't run, and for Linux servers where you don't want it. A small script on the device sends its OS version, packages and
running containers to LabLantern on a schedule. LabLantern only receives: the answer is always `{"ok": true}`, never a
command or an update.

| Script | Device | Reports |
|---|---|---|
| `linux.sh` | Any Linux server (Debian, Ubuntu, RHEL family, SUSE, Fedora, Alpine; also TrueNAS SCALE) | OS version, packages from `dpkg`, `rpm` or `apk` (deb and rpm with their source package, as the agent sends them), Docker containers |
| `unraid.sh` | Unraid | Unraid version, Slackware packages (`/var/log/packages`), Docker containers |
| `ugreen.sh` | UGREEN NAS (UGOS Pro) | OS version, Debian packages (`dpkg-query`, checked against Debian's advisories), Docker containers |
| `synology.sh` | Synology DSM | DSM version, installed packages (`/var/packages/*/INFO`), Container Manager containers |
| `openwrt.sh` | OpenWrt | release, `opkg list-installed` (from 24.10 on: `apk list --installed`) |

Each script is POSIX `sh` and needs `curl`. On OpenWrt install it first (`opkg install curl` or `apk add curl`).

## Setup

1. In lablantern: **Systems → + Add host → Other device (collector script)**, enter a name. LabLantern shows a command
   with the device's token, once.
2. Run that command on the device as root. It downloads lablantern's root certificate, checks its fingerprint and
   stores the address, the token and the certificate in `/etc/lablantern-collector`. On Unraid, `/etc` is lost on
   reboot: run `export LL_DIR=/boot/config/lablantern` first (the Unraid script uses that directory by default). On a
   UGREEN NAS a firmware update may reset the system disk: use `export LL_DIR=/volume1/lablantern`.
3. Copy the script to the device and add the schedule from its header (cron, Unraid User Scripts, or the DSM Task
   Scheduler). Hourly is a good interval.

Lost the token? **New token** in the device's row issues a new one; the old one stops working at once.

## Servers outside your network

A collector script only makes outgoing HTTPS requests, so a server elsewhere (a VPS, an offsite backup machine) needs
no open port. It does need a route to LabLantern:

- **Use a routed VPN**, for example WireGuard between the server and your router, so that the server reaches
  LabLantern's LAN address. The setup command then works unchanged.
- If the server reaches LabLantern under a different address, add that address to `LABLANTERN_HOSTNAMES` and recreate
  the `server` container: the certificate is only issued for those names, and the script checks it on every report.
  Then replace the address in the setup command in both places. LabLantern listens on `LABLANTERN_BIND_IP` only, so
  the traffic has to arrive there.
- Don't forward LabLantern's port from the internet for this. Reports use the same port as the web interface.

What protects a report: the token belongs to one device and LabLantern stores only its hash. The script sends it only
over a connection that presents LabLantern's certificate, which the setup command checked by fingerprint. Whoever
takes over the server gets that token and can send false reports for this one device, nothing more: LabLantern never
answers with a command, and **New token** or revoking the device ends it.

LabLantern pings the address the reports come from. Behind a tunnel that translates addresses, that is the tunnel's
address, not the server's.

## What LabLantern rates

Only what the report provides. The rest shows as **n/a** in the coverage matrix:

- **Package CVEs:** checked for deb (Debian, Ubuntu; also UGREEN's UGOS Pro, which is Debian-based), rpm (RHEL family, SUSE, Fedora), apk (Alpine, Wolfi) and
  language packages (npm, pypi, golang, cargo, gem, nuget, composer). There's no vulnerability database for opkg,
  Slackware or Synology packages: they're recorded, and the check shows n/a with that reason.
- **Containers and images:** with `syft` on the device, the scripts send a CycloneDX SBOM per image and LabLantern scans
  it like an agent's. Without it the image scan is n/a ("install syft on the device to scan images"), never ok.
- **TrueNAS SCALE** with `linux.sh`: it is Debian-based, so its packages are checked against Debian's advisories,
  although TrueNAS ships fixes with its own releases. Pools, drives, alerts and backup tasks are read by the TrueNAS
  connector only (see [docs/INTEGRATIONS.md](../docs/INTEGRATIONS.md)), not by the script.
- **Security updates and reboot:** not reported, n/a.
- **No report for more than 24 hours** is an error.

## Writing your own

The format is in [`docs/collector-schema.json`](../docs/collector-schema.json) (JSON Schema, version `v1`). Send it
with `POST /api/collector/v1/report` and `Authorization: Bearer <token>`. Limits: 5 MB, 20 000 packages,
50 containers, one report every 5 minutes (more often gets HTTP 429).
