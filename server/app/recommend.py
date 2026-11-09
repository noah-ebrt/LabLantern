"""Empfohlene Maßnahme je Fund (Fundliste): Text und, wo es einen gibt, ein Befehl.

Feste Regeln nach Quelle und Ziel des Funds, keine KI. Befehle sind allgemein gültig: Paketmanager des Hosts, Name
des Pakets, Image oder Compose-Dienst aus dem Fund; nie Pfade oder Eigenheiten einer bestimmten Installation."""
import json
import re

from .earlywarning import PACKAGE_MANAGERS, PORTAINER_DIR, UPGRADE, purge_kernels

KERNEL = re.compile(r"^linux-(image|modules|headers|tools)")
APPLIANCE_TEXT = {
    ("truenas", "host"): "Install the update: TrueNAS → System → Update. Read the release notes first; it reboots the NAS.",
    ("truenas", "app"): "Update the app: TrueNAS → Apps → the app → Update.",
    ("truenas", "alert"): "Open TrueNAS → Alerts, fix the cause, then dismiss the alert.",
    ("homeassistant", "update"): "Install it: Home Assistant → Settings → System → Updates. Core and OS updates restart Home Assistant.",
    ("homeassistant", "backup"): "Check Settings → System → Backups: run a backup now and make sure automatic backups are on and succeed.",
    ("homeassistant", "disk"): "Free space: delete old backups and media, shrink the recorder history (purge_keep_days).",
    ("homeassistant", "battery"): "Replace or charge the battery before the device stops reporting.",
    ("homeassistant", "host"): "Restart Home Assistant normally and check Settings → System → Logs for the integration that failed.",
    ("proxmox", "node"): "Update the node: Datacenter → the node → Updates → Refresh, then Upgrade. Migrate or shut down guests first if the kernel changes.",
    ("truenas", "pool"): "Open Storage → the pool → View Disks, replace the faulted disk and let the resilver finish. Check the backup first.",
    ("truenas", "disk"): "Free space: delete old snapshots (Data Protection → Periodic Snapshot Tasks retention) or add a vdev.",
    ("truenas", "drive"): "Storage → Disks → the disk: run a long S.M.A.R.T. test and replace the drive if errors keep growing.",
    ("proxmox", "pool"): "Run zpool status -v on the node, replace the failed device (zpool replace) and let the resilver finish.",
    ("proxmox", "disk"): "Free space: delete old snapshots and backups on the pool, or move guest disks to other storage.",
    ("proxmox", "drive"): "The node → Disks → the drive → Show S.M.A.R.T. values; replace it and move its data away first.",
    ("synology", "host"): "Install the update: Control Panel → Update & Restore → DSM Update. It restarts the NAS.",
    ("synology", "pool"): "Open Storage Manager, check the pool and its drives and follow its repair steps. Make sure the backup is current first.",
    ("synology", "disk"): "Free space: empty the recycle bins, delete old snapshots (Snapshot Replication) or expand the volume.",
    ("synology", "drive"): "Replace the drive: Storage Manager → the drive → Health Info. Back up first if the pool has no redundancy left.",
    ("opnsense", "host"): "Install the update: System → Firmware → Updates. Read the changelog first; kernel updates reboot the firewall.",
    ("opnsense", "packages"): "Install the pending updates: System → Firmware → Updates.",
    ("opnsense", "major"): "Plan the major upgrade: System → Firmware → Status → Upgrade, after reading the release notes.",
}


def _inventory(sys) -> dict:
    try:
        return json.loads(sys.inventory_json or "{}") if sys else {}
    except ValueError:
        return {}


def _container(inv: dict, ref: str) -> dict:
    return next((c for c in inv.get("containers") or [] if c.get("image") == ref), {})


def image_action(inv: dict, ref: str, status: str | None = None) -> tuple[str, str, str]:
    """(Zustand, Text, Befehl) zum Aktualisieren eines Images. `status` ist das Ergebnis der Registry-Prüfung
    (products/freshness: outdated, newer-version, current, local, unknown, pending; None = nicht geprüft).
    Zustände: update (Pull hilft), tag (neuere Version, Tag ändern), waiting (neuestes Image, Pull ändert nichts),
    rebuild (lokal gebaut), unknown (nicht geprüft: allgemeiner Rat)."""
    c = _container(inv, ref)
    labels = c.get("labels") or {}
    service = labels.get("com.docker.compose.service", "")
    project = labels.get("com.docker.compose.project", "") or service
    portainer = bool(PORTAINER_DIR.match(labels.get("com.docker.compose.project.working_dir", "")))
    by_digest = "@sha256:" in ref
    tag = "" if by_digest else (ref.rsplit(":", 1)[1] if ":" in ref.rsplit("/", 1)[-1] else "latest")
    pinned = by_digest or bool(re.match(r"^v?\d+\.\d+\.\d+", tag))   # pull holt bei festem Tag dasselbe Image
    # Compose-Befehle laufen nur im Verzeichnis des Projekts: dessen Name in den Text, nie der Pfad der Installation
    where = f" Run it in the directory of the Compose project {project}." if service else ""
    if status == "local" or (c and not c.get("repo_digests")):
        return ("rebuild", f"The image {ref} is built locally. Rebuild it on a current base image and redeploy." + where,
                "docker compose build --pull" + (f" {service} && docker compose up -d {service}" if service else ""))
    stack = f" In Portainer: Stacks → {project or 'the stack'} → "
    if status == "current":
        if by_digest:
            return ("waiting", "The image is pinned by digest. Compare it with the newest release and update the digest "
                               "in the Compose file, then recreate the container.", "")
        return ("waiting", "You already run the newest image for this tag, so pulling changes nothing. The maintainer "
                           "has to publish a fixed image; snooze these until then.", "")
    if status == "newer-version" or (pinned and status is None):
        how = (stack + "Editor, change the tag, Update the stack.") if portainer else \
              " Change the tag in the Compose file, then recreate the container." + where
        return ("tag", f"The tag {tag or 'digest'} is pinned, so pulling it again changes nothing. Move to a newer "
                       "version (read its release notes first)." + how, "")
    if portainer:
        return ("update" if status == "outdated" else "unknown",
                "Pull the newer image and recreate the container." + stack + "Pull and redeploy.", "")
    pull = f"docker compose pull {service} && docker compose up -d {service}" if service else f"docker pull {ref}"
    if status == "outdated":
        return ("update", "The registry has a newer image for this tag. Pull it and recreate the container; the next "
                          "scan shows what it fixed." + where, pull)
    return ("unknown", "Pull a newer image (the maintainer has to rebuild it) and recreate the container. The registry "
                       "check has not confirmed a newer image yet." + where, pull)


def recommend(f, sys, image_status: str | None = None) -> dict:
    """{"text": …, "command": …} für einen Fund. `sys` ist das System des Funds (Inventar für Paketmanager und Labels),
    `image_status` das Ergebnis der Registry-Prüfung für sein Image (siehe image_action)."""
    inv = _inventory(sys)
    no_fix = not f.fixed_version
    urgent = "Actively exploited (CISA KEV): do this first. " if f.kev else ""
    if f.source in ("truenas", "homeassistant", "proxmox", "synology", "opnsense") and f.cve_id != "LL-EOL":
        kind = f.target.split(":", 1)[0]
        return {"text": APPLIANCE_TEXT.get((f.source, kind), "Check the device."), "command": ""}
    if f.source == "npm":
        return {"text": "Renew the certificate in Nginx Proxy Manager (SSL Certificates → Renew). If renewal fails, check that "
                        "the domain still points to NPM (HTTP challenge) or that the DNS credentials are valid.", "command": ""}
    if f.source == "ai":
        return {"text": "Follow the steps of the early warning: Early warnings → this report.", "command": ""}
    if f.source == "eol" or f.cve_id == "LL-EOL":
        return {"text": f"{f.component} {f.installed_version} no longer gets security fixes. Plan the move to a supported "
                        "release line" + (f" ({f.fixed_version})" if f.fixed_version else "") + ".", "command": ""}

    if f.target.startswith("image:"):
        ref = f.target.removeprefix("image:")
        state, text, command = image_action(inv, ref, image_status)
        if f.cve_id == "LL-IMAGE-OUTDATED":   # gleicher Tag, neueres Image in der Registry
            return {"text": text, "command": command}
        if f.cve_id == "LL-IMAGE-NEWER":
            return {"text": f"Version {f.fixed_version} is available. Read its release notes, change the image tag, then "
                            "recreate the container.", "command": ""}
        if no_fix:
            return {"text": urgent + f"{f.component} inside the image {ref} has no fixed version yet. Watch for a new "
                            "image; until then avoid exposing the service, or accept the risk with an expiry if the "
                            "component is not used.", "command": ""}
        lead = urgent + f"{f.component} inside the image {ref} is fixed in {f.fixed_version}. "
        if state == "waiting":
            return {"text": lead + f"The newest image for this tag still ships {f.component} {f.installed_version}, so "
                            "pulling changes nothing: the maintainer has to publish a fixed image. Snooze it until then, "
                            "or check whether the component is used at all.", "command": ""}
        return {"text": lead + text, "command": command}

    # Paket auf dem Host
    pm = PACKAGE_MANAGERS.get(inv.get("os_id", ""), "")
    running = re.match(r"^\d+\.\d+\.\d+-\d+", inv.get("kernel") or "")
    version = re.search(r"\d+\.\d+\.\d+-\d+", f.component or "") if KERNEL.match(f.component or "") else None
    if version and running and version.group(0) != running.group(0):
        return {"text": urgent + f"This package belongs to kernel {version.group(0)}, which no longer runs (running: "
                        f"{running.group(0)}). apt autoremove keeps the previous kernel as a fallback, so remove it by "
                        "name once the running kernel works.",
                "command": purge_kernels([version.group(0)]) if pm == "apt" else ""}
    if no_fix:
        return {"text": urgent + f"No fixed {f.component} from the distribution yet. Check whether the package is needed "
                        "(remove it if not), keep the service off the internet, and look again after the next update.",
                "command": ""}
    command = UPGRADE[pm][0].format(pkgs=f.component) if pm in UPGRADE else ""
    reboot = " Reboot afterwards, the kernel only changes on restart." if KERNEL.match(f.component or "") else ""
    return {"text": urgent + f"Update {f.component} to {f.fixed_version} or newer." + reboot, "command": command}
