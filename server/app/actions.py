"""Nächste Schritte für die Übersicht: was hinter „Action needed“ steckt und was zu tun ist.

Gleiche Regeln wie overview.compute_ampel (jeder Grund für Rot oder Gelb ergibt einen Schritt), dazu konkret je Host
und Ziel: welches Image oder welche Paketgruppe die kritischen Funde trägt, ob es einen Fix gibt, und wie man ihn
einspielt (Paketbefehl, Compose, Portainer, alte Kernel). Reiner Code aus Inventar und Funden, keine KI."""
import json
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select

from .containers import containers_of
from .coverage import SCAN_MAX_AGE_HOURS
from .earlywarning import PACKAGE_MANAGERS, PORTAINER_DIR, UPGRADE, purge_kernels
from .models import EarlyWarning, Finding, ScanRun, System, put_setting, setting

CHECK_NAMES = {"paket_cve": "Package CVEs", "sicherheitsupdates": "Security updates", "reboot": "Reboot",
               "container": "Containers", "images": "Container images", "versionen": "Versions"}
FULL_UPGRADE = {pm: cmds[1] for pm, cmds in UPGRADE.items()}
KERNEL_PKG = re.compile(r"^linux-(?:image|modules|headers|tools|hwe-[\d.]+-tools|hwe-[\d.]+-headers)[-a-z]*-(\d+\.\d+\.\d+-\d+)")
MAX_GROUPS = 5
DONE_KEY = "overview.steps_done"   # {"run_id": letzter Lauf beim Abhaken, "ids": [...]}: gilt bis zum nächsten Lauf


def step_id(title: str) -> str:
    """Gleicher Schritt über Läufe hinweg: Titel ohne Zahlen („22 critical“ und „20 critical“ sind derselbe)."""
    return re.sub(r"\d+", "#", title)[:200]


def apply_done(s, steps: list[dict], last: ScanRun | None) -> list[dict]:
    """Abgehakte Schritte bleiben bis zum nächsten abgeschlossenen Lauf verborgen; danach entscheidet der Lauf:
    behoben, oder der Schritt ist wieder da."""
    done = setting(s, DONE_KEY) or {}
    ids = set(done.get("ids") or []) if last is not None and done.get("run_id") == last.id else set()
    return [{**st, "id": step_id(st["title"]), "done": step_id(st["title"]) in ids} for st in steps]


def mark_done(s, last: ScanRun | None, sid: str, value: bool) -> None:
    done = setting(s, DONE_KEY) or {}
    run_id = last.id if last else None
    ids = set(done.get("ids") or []) if done.get("run_id") == run_id else set()
    ids = ids | {sid} if value else ids - {sid}
    put_setting(s, DONE_KEY, {"run_id": run_id, "ids": sorted(ids)})


def affected_warnings(s, now: datetime) -> list[dict]:
    """Frühwarnungen der letzten 30 Tage, die eigene Systeme betreffen (hoch/mittel), neueste zuerst."""
    since = now - timedelta(days=30)
    hits = s.scalars(select(EarlyWarning).where(EarlyWarning.status == "betroffen", EarlyWarning.created_at >= since,
                                                EarlyWarning.severity.in_(("hoch", "mittel")))
                     .order_by(EarlyWarning.id.desc())).all()
    return [{"id": w.id, "title": w.title, "severity": w.severity,
             "systems": sorted({a["system"] for a in json.loads(w.affected or "[]")})} for w in hits]


def _step(level: str, title: str, detail: str = "", command: str = "", link: dict | None = None,
          cta: str = "", action: str = "") -> dict:
    return {"level": level, "title": title, "detail": detail, "command": command, "link": link, "cta": cta,
            "action": action}


def _findings_link(severity: str, system_id: int | None = None, q: str = "", kev: bool = False) -> dict:
    query = {"severity": severity, **({"system_id": str(system_id)} if system_id else {}), **({"q": q} if q else {}),
             **({"kev": "true"} if kev else {})}
    return {"path": "/funde", "query": query}


def _image_step(sys: System, ref: str) -> tuple[str, str]:
    """(Text, Befehl) zum Aktualisieren eines Images, aus den Compose-Labels des Containers."""
    c = next((c for c in containers_of(sys) if c.get("image") == ref), {})
    labels = c.get("labels") or {}
    tag = ref.rsplit(":", 1)[1] if ":" in ref.rsplit("/", 1)[-1] else "latest"
    workdir, project = labels.get("com.docker.compose.project.working_dir", ""), labels.get("com.docker.compose.project", "")
    if c and not c.get("repo_digests"):
        return "Built locally: rebuild it on a current base image (docker build --pull) and redeploy.", ""
    pinned = bool(re.match(r"^v?\d+\.\d+\.\d+", tag))
    what = "Move to a newer version tag" if pinned else "Pull the newest image"
    if PORTAINER_DIR.match(workdir):
        return f"{what}: in Portainer, Stacks → {project or 'the stack'} → " + (
            "Editor, change the tag, Update the stack." if pinned else "Pull and redeploy."), ""
    service = labels.get("com.docker.compose.service", "")
    if service and not pinned:   # allgemein gültig: im Verzeichnis des Compose-Projekts, ohne dessen Pfad
        return (f"{what} and recreate the container, in the directory of the Compose project {project or service}:",
                f"docker compose pull {service} && docker compose up -d {service}")
    return f"{what} and recreate the container.", ""


def _host_step(s, sys: System, rows: list[tuple]) -> tuple[str, str]:
    """Paketfunde des Hosts: alte Kernelpakete (häufigste Ursache ohne Fix), sonst das Paket-Upgrade."""
    try:
        inv = json.loads(sys.inventory_json or "{}")
    except ValueError:
        inv = {}
    running = re.match(r"^(\d+\.\d+\.\d+-\d+)", inv.get("kernel") or "")
    def old_version(comp):   # Kernel-Version des Pakets, wenn dieser Kernel nicht läuft
        m = KERNEL_PKG.match(comp or "")
        return m.group(1) if m and running and m.group(1) != running.group(1) else ""
    old_kernel = [(v, comp) for comp, *_ in rows if (v := old_version(comp))]
    pm = PACKAGE_MANAGERS.get(inv.get("os_id", ""), "")
    fixable = sum(1 for comp, fix, _ in rows if fix and not old_version(comp))
    if old_kernel and pm == "apt":
        versions = sorted({v for v, _ in old_kernel})
        kernels = ("kernel " if len(versions) == 1 else "kernels ") + ", ".join(versions)
        return (f"{len(old_kernel)} of these are in {len({c for _, c in old_kernel})} packages of {kernels}, which no "
                f"longer {'runs' if len(versions) == 1 else 'run'}. apt autoremove keeps the previous kernel as a "
                "fallback, so remove it by name once the running kernel works"
                + (", then install the updates:" if fixable else ":"),
                purge_kernels(versions) + (" && " + FULL_UPGRADE[pm] if fixable else ""))
    if fixable:
        return "Install the package updates:", FULL_UPGRADE.get(pm, "")
    return "No fixed packages from the distribution yet; check whether the affected packages are needed.", ""


def next_steps(s, counts: dict, cov: dict, last: ScanRun | None, now: datetime) -> list[dict]:
    steps: list[dict] = []
    if last is None:
        return [_step("rot", "No valid run yet", "Start the first full run; it collects fresh data from every agent.",
                      action="scan", cta="Scan now")]
    if last.status == "failed":
        steps.append(_step("rot", f"Run #{last.id} failed", "Open the run to see which step failed.",
                           link={"path": "/laeufe"}, cta="Open runs"))
    if last.canary_status != "ok":
        steps.append(_step("rot", "Scanner self-test failed",
                           "The canary scan did not find its known vulnerability, so results cannot be trusted. "
                           "Check the worker log on the master:",
                           command="docker compose logs --tail 100 worker"))
    if last.finished_at is None or (now - last.finished_at).total_seconds() / 3600 > SCAN_MAX_AGE_HOURS:
        steps.append(_step("rot", "Results are out of date",
                           f"The last valid run is older than {int(SCAN_MAX_AGE_HOURS)} h.", action="scan", cta="Scan now"))
    errors: dict[str, list] = {}
    for sysrow in cov["systems"]:
        for key, c in sysrow["checks"].items():
            if c["status"] == "fehler":
                errors.setdefault(key, []).append(f"{sysrow['system_name']}: {c.get('detail') or 'error'}")
    for key, items in errors.items():
        text = "; ".join(items)
        # Ein mitgelieferter Befehl (z. B. Container neu erstellen) gehört in das Kopierfeld, nicht in den Fließtext
        cmd = re.search(r"cd \S+ && docker compose [^;]+", text)
        if cmd:
            text = text.replace(": " + cmd.group(0), "").replace(cmd.group(0), "")
        steps.append(_step("rot", f"{CHECK_NAMES.get(key, key)} could not be checked", text[:400],
                           command=cmd.group(0).strip() if cmd else "", link={"path": "/systeme"}, cta="Open systems"))

    systems = {sys.id: sys for sys in s.scalars(select(System))}
    for severity, level in (("kritisch", "rot"), ("hoch", "gelb")):
        if not counts.get(severity):
            continue
        fix_n = func.sum(case((Finding.fixed_version != "", 1), else_=0))   # Summe über Vergleiche wäre ein Boolean
        kev_n = func.sum(case((Finding.kev.is_(True), 1), else_=0))
        groups = s.execute(select(Finding.system_id, Finding.target, func.count(Finding.id), fix_n, kev_n)
                           .where(Finding.status == "open", Finding.severity == severity,
                                  Finding.source.in_(("grype", "osv", "both")))
                           .group_by(Finding.system_id, Finding.target)
                           .order_by(kev_n.desc(), func.count(Finding.id).desc())).all()
        if severity == "hoch":   # „hoch“: eine Zusammenfassung, die Einzelheiten stehen in der Fundliste
            fixable = sum(g[3] or 0 for g in groups)
            top = ", ".join(f"{systems[g[0]].name} {g[1].removeprefix('image:')} ({g[2]})"
                            for g in groups[:3] if g[0] in systems)
            steps.append(_step(level, f"{counts['hoch']} high findings, {fixable} with a fix",
                               f"Most of them: {top}." if top else "", link=_findings_link("hoch"), cta="Show high"))
            continue
        for sid, target, n, fixable, kev in groups[:MAX_GROUPS]:
            sys = systems.get(sid)
            if sys is None:
                continue
            where = "host packages" if target == "host" else target.removeprefix("image:")
            facts = f"{n} critical" + (f", {kev} actively exploited (CISA KEV)" if kev else "") + \
                f", {fixable or 0} with a fix"
            if target == "host":
                rows = s.execute(select(Finding.component, Finding.fixed_version, Finding.kev).where(
                    Finding.system_id == sid, Finding.target == "host", Finding.status == "open",
                    Finding.severity == "kritisch")).all()
                text, command = _host_step(s, sys, rows)
            else:
                text, command = _image_step(sys, target.removeprefix("image:"))
            steps.append(_step(level, f"{sys.name} · {where}", f"{facts}. {text}", command=command,
                               link=_findings_link("kritisch", sid, target), cta="Show findings"))
        if len(groups) > MAX_GROUPS:
            rest = sum(g[2] for g in groups[MAX_GROUPS:])
            steps.append(_step(level, f"{rest} more critical findings in {len(groups) - MAX_GROUPS} other places",
                               link=_findings_link("kritisch"), cta="Show all critical"))
        other = counts["kritisch"] - sum(g[2] for g in groups)
        if other > 0:   # Versionen, Zertifikate, Frühwarnung: eigene Quellen mit eigener Erklärung in der Liste
            steps.append(_step(level, f"{other} critical findings from version, certificate or AI checks",
                               link={"path": "/funde", "query": {"severity": "kritisch", "source": "products"}},
                               cta="Show"))

    hits = affected_warnings(s, now)
    if hits:
        names = sorted({n for w in hits for n in w["systems"]})
        steps.append(_step("rot" if any(w["severity"] == "hoch" for w in hits) else "gelb",
                           f"{len(hits)} early warning{'s' if len(hits) > 1 else ''} affect{'' if len(hits) > 1 else 's'} "
                           f"your systems", "; ".join(w["title"][:90] for w in hits[:3]) + (f" ({', '.join(names)})" if names else ""),
                           link={"path": "/fruehwarnungen", "query": {"status": "betroffen"}}, cta="Open early warnings"))

    reboot = [r["system_name"] for r in cov["systems"] if (r["checks"].get("reboot") or {}).get("status") == "fund"]
    if reboot:
        steps.append(_step("gelb", f"Reboot {', '.join(reboot)}", "Installed updates take effect only after a reboot. "
                           "Systems → host → Reboot (passkey).", link={"path": "/systeme"}, cta="Open systems"))
    updates = [r for r in cov["systems"] if (r["checks"].get("sicherheitsupdates") or {}).get("status") == "fund"]
    for r in updates[:MAX_GROUPS]:
        sys = systems.get(r["system_id"])
        pm = PACKAGE_MANAGERS.get(json.loads(sys.inventory_json or "{}").get("os_id", ""), "") if sys else ""
        check = r["checks"]["sicherheitsupdates"]
        steps.append(_step("gelb", f"Security updates pending on {r['system_name']}", check.get("detail") or "",
                           command=check.get("command") or FULL_UPGRADE.get(pm, ""),
                           link={"path": "/systeme", "query": {"open": str(r["system_id"])}}, cta="Open host"))
    for key, cta in (("container", "Open systems"), ("versionen", "Show versions")):
        items = [f"{r['system_name']}: {r['checks'][key].get('detail')}" for r in cov["systems"]
                 if (r["checks"].get(key) or {}).get("status") == "fund"]
        if items:
            link = {"path": "/systeme"} if key == "container" else {"path": "/funde", "query": {"source": "products"}}
            steps.append(_step("gelb", CHECK_NAMES[key], "; ".join(items)[:400], link=link, cta=cta))
    order = {"rot": 0, "gelb": 1}
    return sorted(steps, key=lambda st: order[st["level"]])
