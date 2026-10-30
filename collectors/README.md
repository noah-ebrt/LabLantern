# Collector scripts

For devices where the vulnwatch agent can't run. A small script on the device sends its OS version, packages and
running containers to vulnwatch on a schedule. vulnwatch only receives: the answer is always `{"ok": true}`, never a
command or an update.

| Script | Device | Reports |
|---|---|---|
| `unraid.sh` | Unraid | Unraid version, Slackware packages (`/var/log/packages`), Docker containers |
| `synology.sh` | Synology DSM | DSM version, installed packages (`/var/packages/*/INFO`), Container Manager containers |
| `openwrt.sh` | OpenWrt | release, `opkg list-installed` (from 24.10 on: `apk list --installed`) |

Each script is POSIX `sh` and needs `curl`. On OpenWrt install it first (`opkg install curl` or `apk add curl`).

## Setup

1. In vulnwatch: **Systems → + Add host → Other device (collector script)**, enter a name. vulnwatch shows a command
   with the device's token, once.
2. Run that command on the device as root. It downloads vulnwatch's root certificate, checks its fingerprint and
   stores the address, the token and the certificate in `/etc/vulnwatch-collector`. On Unraid, `/etc` is lost on
   reboot: run `export VW_DIR=/boot/config/vulnwatch` first (the Unraid script uses that directory by default).
3. Copy the script to the device and add the schedule from its header (cron, Unraid User Scripts, or the DSM Task
   Scheduler). Hourly is a good interval.

Lost the token? **New token** in the device's row issues a new one; the old one stops working at once.

## What vulnwatch rates

Only what the report provides. The rest shows as **n/a** in the coverage matrix:

- **Package CVEs:** checked for deb (Debian, Ubuntu), rpm (RHEL family, SUSE, Fedora), apk (Alpine, Wolfi) and
  language packages (npm, pypi, golang, cargo, gem, nuget, composer). There's no vulnerability database for opkg,
  Slackware or Synology packages: they're recorded, and the check shows n/a with that reason.
- **Containers and images:** with `syft` on the device, the scripts send a CycloneDX SBOM per image and vulnwatch scans
  it like an agent's. Without it the image scan is n/a ("install syft on the device to scan images"), never ok.
- **Security updates and reboot:** not reported, n/a.
- **No report for more than 24 hours** is an error.

## Writing your own

The format is in [`docs/collector-schema.json`](../docs/collector-schema.json) (JSON Schema, version `v1`). Send it
with `POST /api/collector/v1/report` and `Authorization: Bearer <token>`. Limits: 5 MB, 20 000 packages,
50 containers, one report every 5 minutes (more often gets HTTP 429).
