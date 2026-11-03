"""Lebenszyklus eines Scan-Laufs. Der Server reiht ein und wertet aus, der Worker (ohne Master key,
ohne Datenbankzugriff) scannt nur und liefert Rohdaten. Bewertet wird ausschließlich hier, nach festen Regeln."""
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field
from sqlalchemy import func, select, update

from .containers import exposed_targets
from .context import Context
from .coverage import SCANNER_SOURCES, calculate_coverage_matrix
from . import watchdog
from .models import Finding, ImageSbom, ScanJob, ScanRun, System, SystemScanResult, put_setting, setting
from .archive import archive_run, config_version
from .earlywarning import warnings_since
from .mailtpl import run_report_html
from .report import MAX_LISTED_FINDINGS, format_run_report, run_level
from .reportpolicy import ALERT_LEVELS, get_report_policy, report_decision, set_report_policy
from .rules import classify_severity
from .snooze import apply_snoozes, ended_since, snoozed_summary

log = logging.getLogger("lablantern.scanrun")

JOB_TIMEOUT = 75 * 60          # Grype und OSV über alle SBOMs; OSV lädt allein ~5 min seine Datenbank
COLLECT_TIMEOUT = 10 * 60      # so lange wird auf frische Agentendaten gewartet
REPORT_INTERVAL = 55 * 60      # ohne Anforderung meldet ein Agent etwa stündlich
REFRESH_KEY = "refresh.requested"
NO_DATA_HOURS = 2              # Agent länger still: der Lauf hat für diesen Host keine frischen Daten
COLLECTOR_HOURS = 24           # Collector-Geräte melden per Cron, oft nur täglich: so alt darf ihr Report sein


class ScanAlreadyActive(Exception):
    pass


class JobStateError(Exception):
    pass


class FindingIn(BaseModel):
    cve_id: str = Field(min_length=1, max_length=64)
    title: str = Field(default="", max_length=5000)
    component: str = Field(default="unknown", max_length=300)
    installed_version: str = Field(default="", max_length=300)
    fixed_version: str = Field(default="", max_length=300)
    has_fix: bool = False
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity_label: str = Field(default="", max_length=32)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    kev: bool = False
    source: Literal["grype", "osv", "both"] = "grype"
    purl: str = Field(default="", max_length=600)
    target: str = Field(default="host", max_length=300)


class SystemResultIn(BaseModel):
    system_id: int
    ok: bool
    error: str = Field(default="", max_length=500)
    findings: list[FindingIn] = Field(default_factory=list, max_length=250_000)
    image_errors: dict[str, str] = Field(default_factory=dict)


class CanaryIn(BaseModel):
    ok: bool
    message: str = Field(default="", max_length=500)


class DbStatusIn(BaseModel):
    ok: bool
    age_hours: float | None = None
    built: str = Field(default="", max_length=64)
    reason: str = Field(default="", max_length=300)
    disabled: bool = False   # leichter Modus: OSV abgeschaltet, kein Fehler


class WorkerResultIn(BaseModel):
    canary: CanaryIn
    grype_db: DbStatusIn
    osv: DbStatusIn | None = None   # zweite Quelle; fehlt bei Workern vor Phase 4
    systems: list[SystemResultIn] = Field(default_factory=list, max_length=1000)


def sbom_path(ctx: Context, system_id: int):
    return ctx.settings.data_dir / "sboms" / f"{system_id}.json"


IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


def image_sbom_path(ctx: Context, system_id: int, image_id: str):
    """Je System eine eigene Datei: Ein Agent kann nur die SBOMs seines eigenen Hosts liefern (nie die anderer)."""
    return ctx.settings.data_dir / "images" / str(int(system_id)) / f"{image_id.removeprefix('sha256:')}.json"


def remove_system_files(ctx: Context, system_id: int) -> None:
    """SBOM-Dateien eines gelöschten Systems entfernen (Host und Images)."""
    sbom_path(ctx, system_id).unlink(missing_ok=True)
    shutil.rmtree(ctx.settings.data_dir / "images" / str(int(system_id)), ignore_errors=True)


def system_images(system: System) -> list[dict]:
    """Eindeutige Images eines Systems laut letztem Agenten-Inventar, mit der ersten Referenz (z. B. nginx:1.27)."""
    try:
        containers = json.loads(system.inventory_json or "{}").get("containers", [])
    except json.JSONDecodeError:
        containers = []
    seen: dict[str, str] = {}
    for c in containers:
        iid = c.get("image_id", "")
        if IMAGE_ID.match(iid) and iid not in seen:
            ref = c.get("image", "")
            if ref.startswith("sha256:") or not ref:   # Tag zeigt inzwischen woanders hin: Container nennen
                ref = f"{c.get('name') or 'container'} ({iid[7:19]})"
            seen[iid] = ref[:200]
    return [{"id": i, "ref": ref} for i, ref in sorted(seen.items())]


# ---------- einreihen und abholen ----------

ACTIVE = ("collecting", "queued", "running")


def enqueue_scan_run(ctx: Context, trigger: str) -> ScanRun:
    """Scan sofort mit den vorhandenen Daten einreihen (ohne vorher frische Agentendaten anzufordern)."""
    with ctx.session_factory() as s:
        if s.scalar(select(ScanRun.id).where(ScanRun.status.in_(ACTIVE)).limit(1)):
            raise ScanAlreadyActive("A scan is already running")
        run = ScanRun(status="queued", trigger=trigger, canary_status="offen")
        s.add(run)
        s.flush()
        _create_job(ctx, s, run)
        s.commit()
    watchdog.run_started(ctx, run.id, trigger)
    return run


def request_scan_run(ctx: Context, trigger: str) -> ScanRun:
    """Erst frische Daten von allen Agenten anfordern, dann scannen. Die Agenten fragen alle 5 min nach
    (`/api/agent/poll`); der Server kann sie zu nichts anderem als ihrem normalen Report veranlassen."""
    with ctx.session_factory() as s:
        if s.scalar(select(ScanRun.id).where(ScanRun.status.in_(ACTIVE)).limit(1)):
            raise ScanAlreadyActive("A scan is already running")
        if s.scalar(select(System.id).where(System.status == "active").limit(1)):
            run = ScanRun(status="collecting", trigger=trigger, canary_status="offen")
            s.add(run)
            s.flush()
            put_setting(s, REFRESH_KEY, {"run_id": run.id, "at": datetime.now(timezone.utc).isoformat(), "clock": ctx.clock()})
            s.commit()
            watchdog.run_started(ctx, run.id, trigger)
            return run
    return enqueue_scan_run(ctx, trigger)


def refresh_request(s) -> dict | None:
    data = setting(s, REFRESH_KEY)
    if data is None:
        return None
    run = s.get(ScanRun, data["run_id"])
    if run is None or run.status != "collecting":
        return None
    data["at"] = datetime.fromisoformat(data["at"])
    return data


def _system_ready(ctx: Context, s, system: System, since: datetime) -> bool:
    seen = system.last_seen
    if system.host_type == "collector":   # lässt sich nicht anstoßen; Image-SBOMs kommen im Report mit
        return seen is not None and (datetime.now(timezone.utc) - seen).total_seconds() <= COLLECTOR_HOURS * 3600
    if seen is None or seen < since:
        return False
    for img in system_images(system):
        if image_sbom_path(ctx, system.id, img["id"]).is_file():
            continue
        row = s.get(ImageSbom, (system.id, img["id"]))
        if row is None or not row.error or row.created_at < since:
            return False  # SBOM noch unterwegs
    return True


def collection_progress(ctx: Context, s) -> dict | None:
    req = refresh_request(s)
    if req is None:
        return None
    systems = s.scalars(select(System).where(System.status == "active")).all()
    ready_ids = [x.id for x in systems if _system_ready(ctx, s, x, req["at"])]
    # ready_ids: welche Hosts schon bereit sind (frischer Report samt Image-SBOMs), für die Pipeline-Anzeige
    return {"run_id": req["run_id"], "systems_total": len(systems), "systems_reported": len(ready_ids),
            "ready_ids": ready_ids, "timeout_in": max(0, int(req["clock"] + COLLECT_TIMEOUT - ctx.clock()))}


def advance_collecting_runs(ctx: Context) -> None:
    """Sobald alle Agenten frisch gemeldet haben (oder die Wartezeit um ist), wird gescannt."""
    with ctx.session_factory() as s:
        prog = collection_progress(ctx, s)
        if prog is None:
            return
        if prog["systems_reported"] < prog["systems_total"] and prog["timeout_in"] > 0:
            return
        # Jeder Agentenbericht ruft das auf: Nach „Scan now“ melden mehrere Agenten im gleichen Augenblick, und jeder
        # sah „alle da“. Der Wechsel ist deshalb eine bedingte Änderung: nur wer ihn schafft, legt den Auftrag an.
        moved = s.execute(update(ScanRun).where(ScanRun.id == prog["run_id"], ScanRun.status == "collecting")
                          .values(status="queued"))
        if moved.rowcount != 1:
            s.rollback()
            return
        _create_job(ctx, s, s.get(ScanRun, prog["run_id"]))
        s.commit()


def agent_should_report(ctx: Context, system: System) -> bool:
    seen = system.last_seen
    if seen is None or (datetime.now(timezone.utc) - seen).total_seconds() > REPORT_INTERVAL:
        return True
    with ctx.session_factory() as s:
        req = refresh_request(s)
    return req is not None and seen < req["at"]


def _create_job(ctx: Context, s, run: ScanRun) -> None:
    systems = s.scalars(select(System).where(System.status == "active").order_by(System.name)).all()
    payload = {"systems": [
        {"id": x.id, "name": x.name, "sbom": sbom_path(ctx, x.id).is_file(),
         "images": [{**img, "sbom": image_sbom_path(ctx, x.id, img["id"]).is_file()} for img in system_images(x)]}
        for x in systems
    ]}
    s.add(ScanJob(target_type="full_scan", run_id=run.id, status="pending",
                  queued_at=ctx.clock(), payload=json.dumps(payload)))


def claim_job(ctx: Context) -> dict | None:
    with ctx.session_factory() as s:
        while True:
            job = s.scalar(select(ScanJob).where(ScanJob.status == "pending").order_by(ScanJob.id).limit(1))
            if job is None:
                return None
            # Ein Lauf hat genau einen Auftrag: ein zweiter (frühere Doppelanlage) wird verworfen, nie doppelt gescannt
            if s.scalar(select(ScanJob.id).where(ScanJob.run_id == job.run_id, ScanJob.id != job.id,
                                                 ScanJob.status.in_(("running", "done", "failed")))):
                job.status, job.error_message = "failed", "duplicate job of this run, dropped"
                job.finished_at = datetime.now(timezone.utc)
                s.commit()
                log.warning("Duplicate job #%d of run #%s dropped", job.id, job.run_id)
                continue
            break
        claimed = s.execute(
            update(ScanJob).where(ScanJob.id == job.id, ScanJob.status == "pending")
            .values(status="running", claimed_at=ctx.clock())
        )
        if claimed.rowcount != 1:  # ein anderer Worker war schneller
            return None
        run = s.get(ScanRun, job.run_id)
        if run:
            run.status = "running"
        s.commit()
        return {"id": job.id, "run_id": job.run_id, **json.loads(job.payload)}


# ---------- auswerten ----------

def _counts(s) -> dict[str, int]:
    out = {"kritisch": 0, "hoch": 0, "mittel": 0, "info": 0}
    for sev, n in s.execute(select(Finding.severity, func.count(Finding.id))
                            .where(Finding.status == "open").group_by(Finding.severity)):
        if sev in out:
            out[sev] = n
    return out


def _send(ctx: Context, run_id: int, info: dict) -> None:
    # Jeder Abschluss (Ergebnis, Fehler, Zeitüberschreitung) läuft hier durch: Offsite-Wächter zuerst, er ist billig
    watchdog.run_finished(ctx, run_id, info["status"], info["canary_ok"], info.get("error") or "",
                          info.get("trigger", "manual"))
    with ctx.session_factory() as s:
        info["coverage"] = calculate_coverage_matrix(s, None, lambda i: sbom_path(ctx, i).is_file(),
                                                     lambda sid, i: image_sbom_path(ctx, sid, i).is_file())
    with ctx.session_factory() as s:
        s.get(ScanRun, run_id).coverage_percent = info["coverage"].get("coverage_percent")
        s.commit()
    notifier = ctx.notifier
    if info.get("trigger") == "short" and not short_run_notable(info):
        # Kurzlauf: nur melden, wenn er etwas Neues findet; sonst kämen vier gleiche Berichte am Tag
        _set_notify_status(ctx, run_id, "skipped: short run, nothing new")
        return
    # Ein Kurzlauf meldet nur Auffälliges, das ist ein Alarm; sonst entscheidet die Stufe
    kind = "alert" if info.get("trigger") == "short" or run_level(info) in ALERT_LEVELS else "report"
    policy = get_report_policy(ctx)
    regular = info.get("trigger") == "scheduled" and kind == "report"
    if regular:
        # Häufigkeit und Pause gelten nur für den Bericht des geplanten Laufs; Handläufe meldet LabLantern immer
        from .schedule import get_timezone
        now_local = datetime.fromtimestamp(ctx.clock(), ZoneInfo(get_timezone(ctx)))
        decision = report_decision(policy, info, now_local)
        if decision != "send":
            _set_notify_status(ctx, run_id, decision)
            return
    if info.get("trigger") == "scheduled" and policy["frequency"] == "weekly":
        info["period"] = "weekly"
    subject, body = format_run_report(info)
    html = run_report_html(subject, info, MAX_LISTED_FINDINGS)
    try:
        ok, err = notifier(subject, body, html, kind=kind) if notifier else (False, "no notification channel")
    except Exception as e:  # ein kaputter Kanal darf die Auswertung nie kippen
        log.exception("Notification failed")
        ok, err = False, type(e).__name__
    _set_notify_status(ctx, run_id, "sent" if ok else f"failed: {err}")
    if ok and regular:
        set_report_policy(ctx, {"last_regular_sent": datetime.fromtimestamp(ctx.clock(), timezone.utc).isoformat()})


def _set_notify_status(ctx: Context, run_id: int, status: str) -> None:
    with ctx.session_factory() as s:
        s.get(ScanRun, run_id).notify_status = status
        s.commit()


def short_run_notable(info: dict) -> bool:
    return (info["status"] != "success" or not info["canary_ok"] or not info.get("db_ok", True)
            or bool(info.get("system_errors")) or bool(info.get("repeat_no_data")) or bool(info.get("sharp_drops"))
            or any(f["severity"] in ("kritisch", "hoch") for f in info.get("new_findings") or []))


def process_scan_result(ctx: Context, job_id: int, result: WorkerResultIn) -> ScanRun:
    now = datetime.now(timezone.utc)
    try:   # Traefik-Labels kommen mit jedem Agenten-Report: vor der Bewertung frisch auswerten
        from .traefik import refresh_traefik
        refresh_traefik(ctx)
    except Exception:  # noqa: BLE001 (bleibt die alte Zuordnung; die Matrix zeigt das Alter)
        log.exception("Traefik labels could not be evaluated")
    new_findings: list[dict] = []
    new_objs: list[Finding] = []
    resolved = reopened = changed = osv_closed = 0
    system_errors: list[tuple[str, str]] = []
    repeat_no_data: list[str] = []
    sharp_drops: list[tuple[str, int, int]] = []   # (Host, Funde vorher, nachher)

    with ctx.session_factory() as s:
        from .integrity import drop_config, is_sharp_drop
        drop_cfg = drop_config(s)
        job = s.get(ScanJob, job_id)
        if job is None or job.status != "running":
            raise JobStateError("Job is not in state 'running'")
        run = s.get(ScanRun, job.run_id)
        previous_finished = s.scalar(select(ScanRun.finished_at).where(ScanRun.id != run.id,
                                     ScanRun.finished_at.is_not(None)).order_by(ScanRun.finished_at.desc()).limit(1))
        expected = {x["id"]: x for x in json.loads(job.payload)["systems"]}
        sent = {r.system_id: r for r in result.systems}
        unknown = set(sent) - set(expected)
        if unknown:
            raise ValueError(f"Result contains unknown systems: {sorted(unknown)}")

        run.canary_status = "ok" if result.canary.ok else "fehler"
        run.canary_details = result.canary.message
        run.db_status = json.dumps({**result.grype_db.model_dump(),
                                    "osv": result.osv.model_dump() if result.osv else None})
        run.finished_at = now
        job.status, job.finished_at = "done", now
        valid = result.canary.ok and result.grype_db.ok
        osv_ok = bool(result.osv and result.osv.ok)
        osv_off = bool(result.osv and result.osv.disabled)

        if not valid:
            run.status = "failed"
            run.error = result.canary.message if not result.canary.ok else result.grype_db.reason
        else:
            from .connectors import connector_exposed
            auto = connector_exposed(s)
            for sid, meta in expected.items():
                r = sent.get(sid)
                system = s.get(System, sid)
                if not meta["sbom"]:
                    status, err, items = "fehler", "no SBOM received from the agent", []
                elif r is None:
                    status, err, items = "fehler", "worker returned no result for this system", []
                elif not r.ok:
                    status, err, items = "fehler", r.error or "scan failed", []
                else:
                    status, err, items = "ok", "", r.findings
                seen_at = system.last_seen if system else None
                limit = COLLECTOR_HOURS if system and system.host_type == "collector" else NO_DATA_HOURS
                no_data = status == "fehler" or seen_at is None or (now - seen_at).total_seconds() > limit * 3600
                prev = s.scalar(select(SystemScanResult).where(SystemScanResult.system_id == sid)
                                .order_by(SystemScanResult.id.desc()).limit(1))
                if no_data and prev is not None and prev.no_data:
                    repeat_no_data.append(meta["name"])
                s.add(SystemScanResult(run_id=run.id, system_id=sid, status=status, error=err,
                                       findings_count=len(items), no_data=no_data,
                                       image_errors=json.dumps({k[:80]: v[:300] for k, v in (r.image_errors if r else {}).items()})))
                if status == "fehler":
                    system_errors.append((meta["name"], err))
                    continue  # bestehende Funde bleiben unverändert, nichts wird still „behoben“

                exposed = exposed_targets(system, set(auto.get(sid, {}))) if system else set()
                existing = {(f.target, f.cve_id, f.component, f.installed_version): f for f in s.scalars(
                    select(Finding).where(Finding.system_id == sid, Finding.status.in_(["open", "accepted"]),
                                          Finding.source.in_(SCANNER_SOURCES)))}
                seen = set()
                for fi in items:
                    key = (fi.target, fi.cve_id, fi.component, fi.installed_version)
                    if key in seen:
                        continue
                    seen.add(key)
                    internet = fi.target in exposed
                    sev = classify_severity(fi.cvss_score, fi.kev, fi.has_fix, internet, fi.severity_label)
                    f = existing.get(key)
                    fields = dict(title=fi.title[:500], severity=sev, fixed_version=fi.fixed_version,
                                  cvss_score=fi.cvss_score, epss_score=fi.epss_score, kev=fi.kev,
                                  source=fi.source, internet_exposed=internet, last_seen_run_id=run.id)
                    if f is None:
                        nf = Finding(scan_run_id=run.id, system_id=sid, cve_id=fi.cve_id, target=fi.target,
                                     component=fi.component, installed_version=fi.installed_version,
                                     status="open", **fields)
                        s.add(nf)
                        new_objs.append(nf)
                        new_findings.append({"cve_id": fi.cve_id, "component": fi.component,
                                             "installed_version": fi.installed_version,
                                             "fixed_version": fi.fixed_version, "severity": sev,
                                             "kev": fi.kev, "system_name": meta["name"], "target": fi.target})
                    else:
                        if f.severity != sev or f.fixed_version != fi.fixed_version:
                            changed += 1
                        for k, v in fields.items():
                            setattr(f, k, v)
                # Was in diesem Lauf nicht geprüft wurde, bleibt offen: Images ohne SBOM oder mit Fehler, und Funde nur
                # aus OSV, wenn OSV ausfiel. Sonst wären sie jetzt „behoben“ und kämen im nächsten Lauf als „neu“.
                errors = r.image_errors if r else {}
                unscanned = {f"image:{img['ref']}"[:300] for img in meta.get("images", [])
                             if not img.get("sbom") or img["id"] in errors or f"ref:{img['ref']}"[:200] in errors}
                kept = 0
                for key, f in existing.items():
                    if key in seen:
                        continue
                    if f.target in unscanned or (f.source == "osv" and not osv_ok):
                        kept += 1
                        continue
                    f.status, f.resolved_at = "resolved", now
                    if f.source == "osv" and osv_off:
                        # Leichter Modus: nicht behoben, nur nicht mehr geprüft; zählt weder als behoben noch als Einbruch
                        osv_closed += 1
                        kept += 1
                        continue
                    resolved += 1
                if is_sharp_drop(drop_cfg, len(existing), len(seen) + kept):
                    sharp_drops.append((meta["name"], len(existing), len(seen)))
            run.status = "partial" if system_errors else "success"
            if system_errors:
                run.error = f"{len(system_errors)} system(s) not checked"
        # Snoozes nach dem Abgleich: neue Funde unter einem Snooze sind nicht "neu", beendete kommen zurück
        apply_snoozes(s, now)
        new_findings = [d for d, nf in zip(new_findings, new_objs) if nf.status == "open"]
        snooze_ended = ended_since(s, previous_finished, now)
        reopened = len(snooze_ended)
        s.flush()
        run.summary_counts = json.dumps(_counts(s))
        run.config_version = config_version(s)
        s.commit()
        info = {
            "run_id": run.id, "status": run.status, "trigger": run.trigger, "error": run.error,
            "canary_ok": result.canary.ok, "canary_message": result.canary.message,
            "db_ok": result.grype_db.ok, "db_reason": result.grype_db.reason,
            "osv_ok": bool(result.osv and result.osv.ok),
            "osv_reason": (result.osv.reason if result.osv else "worker without OSV-Scanner"),
            "summary": json.loads(run.summary_counts), "system_errors": system_errors,
            "new_findings": new_findings, "resolved_count": resolved, "reopened_count": reopened,
            "changed_count": changed, "osv_disabled": bool(result.osv and result.osv.disabled),
            "osv_closed_count": osv_closed,
            "repeat_no_data": repeat_no_data, "sharp_drops": sharp_drops, "config_version": run.config_version,
            "early_warnings": warnings_since(s, previous_finished),
            "snoozed": snoozed_summary(s), "snooze_ended": snooze_ended,
        }
        run_id = run.id
    info["archive_status"] = archive_run(ctx, run_id, result.model_dump_json().encode(),
                                         [x["id"] for x in expected.values()],
                                         [(x["id"], i["id"]) for x in expected.values() for i in x.get("images", [])])
    with ctx.session_factory() as s:
        s.get(ScanRun, run_id).archive_status = info["archive_status"]
        s.commit()
    _send(ctx, run_id, info)
    with ctx.session_factory() as s:
        return s.get(ScanRun, run_id)


def fail_job(ctx: Context, job_id: int, error: str, allowed=("running",)) -> None:
    """Auftrag und Lauf als fehlgeschlagen markieren und Sofort-Alarm auslösen."""
    now = datetime.now(timezone.utc)
    with ctx.session_factory() as s:
        job = s.get(ScanJob, job_id)
        if job is None or job.status not in allowed:
            raise JobStateError("Job cannot be marked as failed")
        job.status, job.error_message, job.finished_at = "failed", error, now
        run = s.get(ScanRun, job.run_id)
        run.status, run.error, run.finished_at, run.canary_status = "failed", error, now, "fehler"
        run.canary_details = error
        run.summary_counts = json.dumps(_counts(s))
        s.commit()
        info = {"run_id": run.id, "status": "failed", "trigger": run.trigger, "error": error,
                "canary_ok": False, "canary_message": error, "db_ok": True, "db_reason": "",
                "summary": json.loads(run.summary_counts), "system_errors": [],
                "new_findings": [], "resolved_count": 0, "reopened_count": 0}
        run_id = run.id
    _send(ctx, run_id, info)


def expire_stale_jobs(ctx: Context) -> None:
    """Liefert der Worker nichts oder holt niemand den Auftrag ab, ist das ein Fehler mit Alarm, kein Schweigen."""
    now = ctx.clock()
    with ctx.session_factory() as s:
        stale = []
        for job in s.scalars(select(ScanJob).where(ScanJob.status.in_(["pending", "running"]))):
            started = job.claimed_at if job.status == "running" else job.queued_at
            if started is not None and now - started > JOB_TIMEOUT:
                stale.append((job.id, job.status))
    for job_id, status in stale:
        msg = (f"Worker returned no result within {JOB_TIMEOUT // 60} min" if status == "running"
               else f"No worker claimed the scan job within {JOB_TIMEOUT // 60} min (worker down?)")
        fail_job(ctx, job_id, msg, allowed=("pending", "running"))
