import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .containers import container_check
from .earlywarning import PACKAGE_MANAGERS, UPGRADE
from .models import Finding, ImageSbom, ScanRun, System, SystemScanResult

AGENT_STALE_HOURS = 24.0
SCAN_MAX_AGE_HOURS = 36.0
FINISHED = ("success", "partial", "failed")


CHECK_KEYS = ("paket_cve", "sicherheitsupdates", "reboot", "container", "images", "versionen")
SCANNER_SOURCES = ("grype", "osv", "both")


def security_updates(sys: System) -> tuple[str, str]:
    """(Detail, Befehl) für ausstehende Sicherheitsupdates. Die Pakete nennt der Agent ab 0.15; nennt er alle, gilt
    der Befehl genau für sie, sonst das ganze System."""
    inv = json.loads(sys.inventory_json or "{}")
    n, pkgs = sys.security_updates_count, inv.get("security_updates") or []
    if not n:
        return "0 pending", ""
    shown = ", ".join(f"{p['name']} → {p['to']}" if p.get("to") else p["name"] for p in pkgs[:8])
    detail = f"{n} pending" + (f": {shown}" if shown else "") + (f" and {len(pkgs) - 8} more" if len(pkgs) > 8 else "")
    cmds = UPGRADE.get(PACKAGE_MANAGERS.get(inv.get("os_id", ""), ""))
    if not cmds:
        return detail, ""
    if pkgs and len(pkgs) == n:
        return detail, cmds[0].format(pkgs=" ".join(p["name"] for p in pkgs))
    return detail, cmds[1]


def _hours(now: datetime, dt: datetime | None) -> float | None:
    return None if dt is None else round((now - dt).total_seconds() / 3600, 1)


def image_problems(session, sys, last) -> list[dict]:
    """Images, die nicht geprüft werden konnten, mit Namen und vollständigem Grund (für die Detailansicht)."""
    from .scanrun import system_images

    refs = {i["id"]: i["ref"] for i in system_images(sys)}
    if not refs:
        return []
    found = {r.image_id: f"SBOM: {r.error}" for r in session.scalars(
        select(ImageSbom).where(ImageSbom.system_id == sys.id, ImageSbom.image_id.in_(list(refs)),
                                ImageSbom.error != ""))}
    for iid, err in (json.loads(last.image_errors or "{}") if last else {}).items():
        found.setdefault(iid, f"scan: {err}")
    return [{"image_id": iid, "image": refs.get(iid, iid), "error": err} for iid, err in sorted(found.items())]


def _image_check(session, sys, last, stale, stale_detail, image_has_sbom):
    from .scanrun import system_images

    images = system_images(sys)
    if stale:
        return ("fehler", stale_detail)
    if not images:
        return ("ok", "no containers")
    problems = image_problems(session, sys, last)
    if problems:
        return ("fehler", f"{len(problems)} image(s) could not be checked: {problems[0]['image']}: {problems[0]['error']}")
    missing = [i for i in images if not image_has_sbom(sys.id, i["id"])]
    if missing:
        return ("offen", f"{len(missing)} image(s) without SBOM, the agent sends them on its next run")
    bad = session.scalar(select(func.count(Finding.id)).where(
        Finding.system_id == sys.id, Finding.status == "open", Finding.target != "host",
        Finding.source.in_(SCANNER_SOURCES),
        Finding.severity.in_(("kritisch", "hoch"))))
    return ("fund" if bad else "ok", f"{len(images)} images, {bad} critical/high")


def _collector_checks(session, sys, last, stale, stale_detail, image_has_sbom, cve, container) -> dict:
    """Collector-Geräte (PLAN-extensions C): bewertet wird nur, was der Report hergibt, der Rest ist n/a."""
    from .scanrun import system_images

    inv = json.loads(sys.inventory_json or "{}")
    na = ("na", "not reported by the collector")
    if not stale and cve[0] != "fehler":
        ecosystems = (inv.get("collector") or {}).get("ecosystems") or {}
        unmatched = sorted(e for e, (_total, scannable) in ecosystems.items() if not scannable)
        if not any(scannable for _total, scannable in ecosystems.values()):
            n = sum(total for total, _ in ecosystems.values())
            what = ", ".join(unmatched) or "no"
            cve = ("na", f"no vulnerability database covers {what} packages ({n} recorded)")
        elif unmatched:
            cve = (cve[0], f"{cve[1]}; not checkable: {', '.join(unmatched)} packages")
    images = system_images(sys)
    if not images:
        return {"paket_cve": cve, "sicherheitsupdates": na, "reboot": na,
                "container": ("na", "no containers reported"), "images": ("na", "no containers reported")}
    hint = "install syft on the device to scan images"
    missing = [i for i in images if not image_has_sbom(sys.id, i["id"])]
    if len(missing) == len(images) and not stale:
        image = ("na", f"{len(missing)} image(s) without SBOM: {hint}")
    else:
        image = _image_check(session, sys, last, stale, stale_detail, lambda *_: True)
        if missing and image[0] == "ok":   # nie ok, solange ein Image ungeprüft ist
            image = ("na", f"{image[1]}; {len(missing)} image(s) without SBOM: {hint}")
        elif missing:
            image = (image[0], f"{image[1]}; {len(missing)} image(s) without SBOM: {hint}")
    return {"paket_cve": cve, "sicherheitsupdates": na, "reboot": na, "container": container, "images": image}


def latest_finished_run(session: Session) -> ScanRun | None:
    return session.scalar(
        select(ScanRun).where(ScanRun.status.in_(FINISHED)).order_by(ScanRun.started_at.desc(), ScanRun.id.desc()).limit(1)
    )


def calculate_coverage_matrix(session: Session, now: datetime | None = None, sbom_exists=lambda _id: True,
                              image_has_sbom=lambda _sid, _id: True) -> dict[str, Any]:
    """Abdeckungsmatrix (PLAN Abschnitt 6): System × Prüfung → ok / fund / fehler / Alter der letzten Daten.
    Was nicht lief oder nicht prüfbar war, ist `fehler`, nie `ok`."""
    now = now or datetime.now(timezone.utc)
    latest_run = latest_finished_run(session)
    matrix, total, ok_count = [], 0, 0
    from .appliances import connector_checks
    from .products import load_state, open_product_counts, versions_check
    vstate, vcounts = load_state(session), open_product_counts(session)
    from .snooze import active_exclusions
    exclusions, excluded = active_exclusions(session, now), 0

    for sys in session.scalars(select(System).order_by(System.name)):
        if sys.status == "revoked":
            continue
        age = _hours(now, sys.last_seen)
        ex = exclusions.get(f"system:{sys.id}")
        if ex is not None:   # ausgenommen: zählt weder als geprüft noch als Lücke, steht aber mit Grund da
            excluded += 1
            detail = f"excluded until {ex.until.date().isoformat()}: {ex.reason}"
            matrix.append({
                "system_id": sys.id, "system_name": sys.name, "status": sys.status, "age_hours": age,
                "is_stale": False, "scan_age_hours": None,
                "checks": {k: {"status": "excluded", "detail": detail} for k in CHECK_KEYS},
                "excluded": {"id": ex.id, "reason": ex.reason, "until": ex.until.isoformat(), "by": ex.created_by},
                "last_scan": None, "image_problems": [], "collection_errors": {},
            })
            continue
        if sys.status == "pending":
            matrix.append({
                "system_id": sys.id, "system_name": sys.name, "status": "pending", "age_hours": age,
                "is_stale": False, "scan_age_hours": None,
                "checks": {k: {"status": "offen", "detail": "waiting for approval"}
                           for k in CHECK_KEYS},
            })
            continue

        if sys.status == "connector":   # TrueNAS, Home Assistant: nur was die API hergibt
            checks = connector_checks(sys, now, session.scalar(select(func.count(Finding.id)).where(
                Finding.system_id == sys.id, Finding.status == "open", Finding.cve_id == "VW-UPDATE")))
            for status, _ in checks.values():
                total += status != "na"
                ok_count += status in ("ok", "fund")
            matrix.append({
                "system_id": sys.id, "system_name": sys.name, "status": sys.status, "age_hours": age,
                "is_stale": checks["versionen"][0] == "fehler", "scan_age_hours": None,
                "checks": {k: {"status": st, "detail": d} for k, (st, d) in checks.items()},
                "last_scan": None, "image_problems": [], "collection_errors": json.loads(sys.collection_errors or "{}"),
            })
            continue

        stale = age is None or age > AGENT_STALE_HOURS
        collector = sys.host_type == "collector"
        who = "collector" if collector else "agent"
        stale_detail = f"{who} has not reported for over 24 h" if age is not None else f"{who} has never reported"

        errors = json.loads(sys.collection_errors or "{}")
        sec_command = ""
        if stale:
            sec = reboot = container = ("fehler", stale_detail)
        else:
            sec_detail, sec_command = security_updates(sys)
            sec = ("fund" if sys.security_updates_count > 0 else "ok", sec_detail)
            reboot = ("fund" if sys.reboot_required else "ok", "reboot required" if sys.reboot_required else "no")
            container = container_check(sys)
            if "security_updates" in errors:
                sec = ("fehler", errors["security_updates"])
            if "containers" in errors:
                container = ("fehler", errors["containers"])

        last = session.scalar(
            select(SystemScanResult).where(SystemScanResult.system_id == sys.id)
            .order_by(SystemScanResult.id.desc()).limit(1)
        )
        scan_age = _hours(now, last.created_at) if last else None
        if stale:
            cve = ("fehler", stale_detail)
        elif "packages" in errors:
            cve = ("fehler", errors["packages"])
        elif sys.sbom_updated_at is None and sbom_exists(sys.id):
            cve = ("fehler", "SBOM comes from the old agent: set the system up again")
        elif last is not None and last.status != "ok" and sys.sbom_updated_at is not None \
                and sys.sbom_updated_at > last.created_at:
            cve = ("offen", "new data from the agent, checked on the next run")
        elif last is None and (_hours(now, sys.enrolled_at) or 0) <= SCAN_MAX_AGE_HOURS:
            cve = ("offen", "new host: checked in the next scan run")
        elif last is None:
            cve = ("fehler", "never checked by a scan run")
        elif last.status != "ok":
            cve = ("fehler", f"scan failed: {last.error}")
        elif scan_age is not None and scan_age > SCAN_MAX_AGE_HOURS:
            cve = ("fehler", f"last scan {scan_age} h ago (limit {SCAN_MAX_AGE_HOURS:g} h)")
        else:
            bad = session.scalars(select(Finding).where(
                Finding.system_id == sys.id, Finding.status == "open", Finding.target == "host",
                Finding.source.in_(SCANNER_SOURCES),
                Finding.severity.in_(("kritisch", "hoch")))).all()
            cve = ("fund" if bad else "ok", f"{len(bad)} critical/high")

        images = _image_check(session, sys, last, stale, stale_detail, image_has_sbom)
        versions = ("fehler", stale_detail) if stale else versions_check(vstate, sys, vcounts.get(sys.id, {}),
                                                                         now.timestamp())
        checks = {"paket_cve": cve, "sicherheitsupdates": sec, "reboot": reboot, "container": container,
                  "images": images, "versionen": versions}
        if collector:
            checks.update(_collector_checks(session, sys, last, stale, stale_detail, image_has_sbom, cve, container))
        for status, _ in checks.values():
            total += status != "na"
            ok_count += status in ("ok", "fund")  # Abdeckung = geprüft; ein Fund ist geprüft
        matrix.append({
            "system_id": sys.id, "system_name": sys.name, "status": sys.status, "age_hours": age,
            "is_stale": stale, "scan_age_hours": scan_age,
            "checks": {k: {"status": st, "detail": d} for k, (st, d) in checks.items()},
            # für die Detailansicht: woher die Bewertung kommt
            "last_scan": {"run_id": last.run_id, "at": last.created_at.isoformat(), "status": last.status,
                          "error": last.error, "findings_count": last.findings_count} if last else None,
            "image_problems": image_problems(session, sys, last),
            "collection_errors": errors,
        })
        if sec[0] == "fund" and sec_command:
            matrix[-1]["checks"]["sicherheitsupdates"]["command"] = sec_command

    # Zurückgestellte Funde zählen eigens, nie als ok (PLAN-extensions A2)
    snoozed = dict(session.execute(select(Finding.system_id, func.count(Finding.id))
                                   .where(Finding.status == "accepted").group_by(Finding.system_id)).all())
    for entry in matrix:
        entry["snoozed"] = snoozed.get(entry["system_id"], 0)
    # Proxmox-Gäste (PLAN-extensions D1): ohne Agent eine Lücke, ausgenommen zählt weder als geprüft noch als Lücke
    from .proxmox import guest_rows
    guests = guest_rows(session, exclusions)
    total += sum(g["status"] != "excluded" for g in guests)
    ok_count += sum(g["status"] == "ok" for g in guests)
    excluded += sum(g["status"] == "excluded" for g in guests)
    # Jede Expositionsquelle ist eine Prüfung: fällt sie aus, ist das eine Lücke, kein "nicht erreichbar"
    from .exposure import source_rows
    sources = source_rows(session, now.timestamp())
    total += len(sources)
    ok_count += sum(r["status"] == "ok" for r in sources)
    canary_status = latest_run.canary_status if latest_run else "offen"
    return {
        "canary_status": canary_status,
        "canary_ok": canary_status == "ok",
        "coverage_percent": round(ok_count / total * 100, 1) if total else 100.0,
        "total_checks": total,
        "excluded_count": excluded,
        "ok_checks": ok_count,
        "systems": matrix,
        "exposure_sources": sources,
        "guests": guests,
    }
