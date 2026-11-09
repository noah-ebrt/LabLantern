"""Funde je Host gruppiert nach dem, was man tut: ein Image, der Kernel, Host-Pakete mit/ohne Fix, alte Kernel,
Geräte-Hinweise. Jede Gruppe hat eine Maßnahme (Text, Befehl) und einen Zustand, der ehrlich sagt, ob sie hilft:

update   der Befehl behebt die Funde (Paketupdate, neueres Image für den Tag)
tag      neuere Version da, aber fester Tag: Tag ändern
rebuild  lokal gebautes Image: neu bauen
waiting  neuestes Image/kein Fix der Distribution: Pull oder Update ändert nichts
manual   Gerät oder Hinweis: Schritte im Text
unknown  nicht geprüft (Registry-Prüfung fehlt), allgemeiner Rat

Welche Funde ein neues Image wirklich behebt, zeigt erst der nächste Scan; das Upstream-Image wird nicht geladen."""
import re

from sqlalchemy import case, func, select

from .earlywarning import PACKAGE_MANAGERS, UPGRADE, purge_kernels
from .models import Finding, System
from .recommend import APPLIANCE_TEXT, KERNEL, _inventory, image_action

SCANNERS = ("grype", "osv", "both")
APPLIANCES = ("truenas", "homeassistant", "proxmox", "synology", "opnsense")
DESKTOP = re.compile(r"webkit|javascriptcore|mozjs|gnome|gtk|evolution|yelp")
RANK = {"kritisch": 0, "hoch": 1, "mittel": 2, "info": 3}
MAX_PACKAGES = 60


def image_statuses(state: dict | None, system_id: int) -> dict[str, str]:
    """Registry-Status je Image-Referenz aus dem letzten Versionsdurchgang (products.load_state)."""
    rows = ((state or {}).get("systems", {}).get(str(system_id), {}).get("rows")) or []
    return {r["image"]: r.get("status", "") for r in rows if r.get("image")}


def _kernel_version(component: str) -> str:
    m = re.search(r"\d+\.\d+\.\d+-\d+", component or "")
    return m.group(0) if m and KERNEL.match(component or "") else ""


def _bucket(row, running: str) -> str:
    """Gruppe eines Host-Funds (Ziel host)."""
    if row.source not in SCANNERS:
        return "eol" if row.cve_id == "LL-EOL" else row.source
    kernel = _kernel_version(row.component)
    if kernel and running and kernel != running:
        return "oldkernel"
    if kernel or KERNEL.match(row.component or ""):
        return "kernel" if row.fixed_version else "kernel-nofix"
    return "packages" if row.fixed_version else "nofix"


def _empty(key: str, kind: str, title: str, subtitle: str = "", target: str = "") -> dict:
    return {"key": key, "kind": kind, "title": title, "subtitle": subtitle, "target": target, "state": "unknown",
            "text": "", "command": "", "counts": {"kritisch": 0, "hoch": 0, "mittel": 0, "info": 0, "kev": 0,
                                                   "fixable": 0, "total": 0}, "packages": {}, "_versions": set()}


def _add(g: dict, row) -> None:
    c = g["counts"]
    for sev in ("kritisch", "hoch", "mittel", "info"):
        c[sev] += getattr(row, sev)
    c["kev"] += row.kev
    c["fixable"] += row.fixable
    c["total"] += row.n
    key = (row.component, row.installed_version)
    p = g["packages"].setdefault(key, {"component": row.component, "installed_version": row.installed_version,
                                       "fixed_version": "", "count": 0, "severity": "info", "kev": 0})
    p["count"] += row.n
    p["kev"] += row.kev
    if row.fixed_version > p["fixed_version"]:
        p["fixed_version"] = row.fixed_version
    worst = min((s for s in ("kritisch", "hoch", "mittel", "info") if getattr(row, s)), key=RANK.get, default="info")
    if RANK[worst] < RANK[p["severity"]]:
        p["severity"] = worst
    if g["kind"] == "oldkernel":
        g["_versions"].add(_kernel_version(row.component))


def _host_action(g: dict, pm: str, inv: dict) -> None:
    kind, cmds = g["kind"], UPGRADE.get(pm)
    n = g["counts"]["total"]
    if kind == "packages":
        g["state"], g["command"] = "update", cmds[1] if cmds else ""
        g["text"] = (f"The distribution has fixes for these {n} findings. One system update installs all of them."
                     + ("" if cmds else " Use the host's package manager."))
    elif kind == "kernel":
        g["state"], g["command"] = "update", cmds[2] if cmds else ""
        g["text"] = "A fixed kernel is available. Install it and reboot; the kernel only changes on restart."
    elif kind == "kernel-nofix":
        g["state"] = "waiting"
        g["text"] = (f"No fixed kernel from the distribution yet (running {inv.get('kernel') or 'unknown'}). Install "
                     "kernel updates as soon as they arrive and reboot.")
    elif kind == "oldkernel":
        versions = sorted(v for v in g["_versions"] if v)
        g["state"], g["command"] = "update", purge_kernels(versions) if pm == "apt" and versions else ""
        g["text"] = (f"These packages belong to kernel {', '.join(versions)}, which no longer runs. Remove them once "
                     "the running kernel works; apt autoremove keeps the previous kernel on purpose.")
    elif kind == "nofix":
        g["state"] = "waiting"
        desktop = sorted({p["component"] for p in g["packages"].values() if DESKTOP.search(p["component"])})
        g["text"] = ("The distribution has no fix yet for these packages, so an update changes nothing. Remove "
                     "packages the host does not need.")
        if desktop:
            g["text"] += (f" {len(desktop)} of them belong to a desktop (GNOME, WebKit, e.g. {desktop[0]}); on a "
                          "headless server, removing the desktop removes them.")


def host_groups(s, system: System, base_stmt, statuses: dict[str, str], fixable_expr) -> list[dict]:
    """Gruppen eines Hosts. `base_stmt` ist die gefilterte Fundabfrage (select Finding … where …), wie die Liste."""
    inv = _inventory(system)
    pm = PACKAGE_MANAGERS.get(inv.get("os_id", ""), "")
    running = re.match(r"^\d+\.\d+\.\d+-\d+", inv.get("kernel") or "")
    running = running.group(0) if running else ""
    sub = base_stmt.where(Finding.system_id == system.id).subquery()
    fixable_ids = select(Finding.id).where(Finding.system_id == system.id, fixable_expr)
    one = lambda cond: func.sum(case((cond, 1), else_=0))   # noqa: E731
    cols = (sub.c.target, sub.c.source, sub.c.cve_id, sub.c.component, sub.c.installed_version, sub.c.fixed_version)
    rows = s.execute(
        select(*cols, func.count().label("n"), one(sub.c.severity == "kritisch").label("kritisch"),
               one(sub.c.severity == "hoch").label("hoch"), one(sub.c.severity == "mittel").label("mittel"),
               one(sub.c.severity == "info").label("info"), one(sub.c.kev).label("kev"),
               one(sub.c.id.in_(fixable_ids)).label("fixable"))
        .group_by(*cols)).all()

    groups: dict[str, dict] = {}
    containers = {}
    for c in inv.get("containers") or []:
        containers.setdefault(c.get("image", ""), []).append(c.get("name", ""))
    host_titles = {"packages": "Host packages with a fix", "kernel": "Kernel update", "kernel-nofix": "Kernel",
                   "oldkernel": "Old kernels", "nofix": "Host packages without a fix", "eol": "End of life",
                   "ai": "AI early warnings"}
    for row in rows:
        target = row.target
        if target.startswith("image:"):
            ref = target.removeprefix("image:")
            names = containers.get(ref, [])
            g = groups.get(target) or groups.setdefault(target, _empty(
                target, "image", f"Container {', '.join(names)}" if names else f"Image {ref}", ref, target))
        elif target == "host":
            kind = _bucket(row, running)
            g = groups.get(kind) or groups.setdefault(kind, _empty(
                kind, kind, host_titles.get(kind, kind), inv.get("os_name", ""), "host"))
        else:
            kind = target.split(":", 1)[0]
            key = f"{row.source}:{kind}"
            label = {"update": "Updates", "battery": "Batteries", "certificate": "TLS certificates", "config": "Settings",
                     "app": "Apps", "backup": "Backups"}.get(kind, kind.capitalize())
            g = groups.get(key) or groups.setdefault(key, _empty(key, "device", label, row.source, ""))
            g["state"] = "manual"
            g["text"] = APPLIANCE_TEXT.get((row.source, kind), "") or g["text"]
        _add(g, row)

    for g in groups.values():
        if g["kind"] == "image":
            ref = g["subtitle"]
            g["state"], g["text"], g["command"] = image_action(inv, ref, statuses.get(ref))
            names = containers.get(ref, [])
            labels = next((c.get("labels") or {} for c in inv.get("containers") or [] if c.get("image") == ref), {})
            project = labels.get("com.docker.compose.project", "")
            g["subtitle"] = ref + (f" · Compose project {project}" if project else "")
            g["containers"] = names
        elif g["kind"] == "device":
            if g["key"].startswith("npm:"):
                g["text"] = "Renew the certificates in Nginx Proxy Manager (SSL Certificates → Renew)."
            elif not g["text"]:
                g["text"] = "Check the device; each finding below names what to do."
        elif g["kind"] in ("eol", "ai"):
            g["state"] = "manual"
            g["text"] = ("The release line no longer gets security fixes: plan the move to a supported one."
                         if g["kind"] == "eol" else "Follow the steps of the early warning: Early warnings → this report.")
        else:
            _host_action(g, pm, inv)
        pk = sorted(g.pop("packages").values(), key=lambda p: (RANK[p["severity"]], -p["kev"], -p["count"]))
        g["packages"], g["packages_total"] = pk[:MAX_PACKAGES], len(pk)
        g.pop("_versions", None)

    def urgency(g):
        c = g["counts"]
        return (-c["kev"], -c["kritisch"], -c["hoch"], -c["mittel"], g["title"])
    return sorted(groups.values(), key=urgency)


def host_summaries(s, base_stmt, fixable_expr) -> list[dict]:
    """Zahlen je Host für die Ansicht „By host“, mit denselben Filtern wie die Liste."""
    sub = base_stmt.subquery()
    one = lambda cond: func.sum(case((cond, 1), else_=0))   # noqa: E731
    rows = s.execute(
        select(System.id, System.name, func.count(sub.c.id),
               one(sub.c.severity == "kritisch"), one(sub.c.severity == "hoch"), one(sub.c.severity == "mittel"),
               one(sub.c.severity == "info"), one(sub.c.kev),
               one(sub.c.id.in_(select(Finding.id).where(fixable_expr))),
               func.count(func.distinct(case((sub.c.target.like("image:%"), sub.c.target)))))
        .join(sub, sub.c.system_id == System.id).group_by(System.id, System.name)).all()
    out = [{"system_id": sid, "system_name": name, "total": n, "kritisch": k or 0, "hoch": h or 0, "mittel": m or 0,
            "info": i or 0, "kev": kev or 0, "fixable": fx or 0, "images": imgs or 0}
           for sid, name, n, k, h, m, i, kev, fx, imgs in rows]
    return sorted(out, key=lambda r: (-r["kev"], -r["kritisch"], -r["hoch"], -r["mittel"], r["system_name"]))

