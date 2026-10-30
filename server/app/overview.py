import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .context import Context
from .coverage import SCAN_MAX_AGE_HOURS, calculate_coverage_matrix, latest_finished_run
from .guards import Guards
from .models import Finding, ScanJob, ScanRun, System
from .notify import load_notification_urls
from .scanrun import collection_progress, image_sbom_path
from .worker_api import worker_last_seen


def compute_ampel(counts: dict, cov: dict, last_run: ScanRun | None, now: datetime) -> str:
    """rot: kritischer Fund, ungültiger/fehlgeschlagener oder veralteter Lauf, nicht prüfbares System.
    gelb: hohe/mittlere Funde oder offene Befunde. grün: nur mit gültigem, frischem Lauf. Sonst unbekannt."""
    if last_run is None:
        return "unbekannt"
    finished = last_run.finished_at
    stale = finished is None or (now - finished).total_seconds() / 3600 > SCAN_MAX_AGE_HOURS
    has_error = any(c["status"] == "fehler" for s in cov["systems"] for c in s["checks"].values())
    if (counts["kritisch"] > 0 or last_run.status == "failed" or last_run.canary_status != "ok"
            or stale or has_error):
        return "rot"
    has_fund = any(c["status"] == "fund" for s in cov["systems"] for c in s["checks"].values())
    if counts["hoch"] > 0 or counts["mittel"] > 0 or has_fund:
        return "gelb"
    return "gruen"


def build_overview_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    @router.get("/overview", dependencies=[Depends(guards.require_session)])
    def overview():
        now = datetime.now(timezone.utc)
        notifications_done = bool(load_notification_urls(ctx))
        with ctx.session_factory() as s:
            counts = {"kritisch": 0, "hoch": 0, "mittel": 0, "info": 0}
            for sev, n in s.execute(select(Finding.severity, func.count(Finding.id))
                                    .where(Finding.status == "open").group_by(Finding.severity)):
                if sev in counts:
                    counts[sev] = n
            from .runs_api import fixable_now
            fixable = dict.fromkeys(counts, 0)   # davon jetzt per Update behebbar, siehe fixable_now
            for sev, n in s.execute(select(Finding.severity, func.count(Finding.id))
                                    .where(Finding.status == "open", fixable_now()).group_by(Finding.severity)):
                if sev in fixable:
                    fixable[sev] = n
            cov = calculate_coverage_matrix(s, now, lambda i: (ctx.settings.data_dir / "sboms" / f"{i}.json").is_file(),
                                          lambda sid, i: image_sbom_path(ctx, sid, i).is_file())
            last = latest_finished_run(s)
            newest = s.scalar(select(ScanRun).order_by(ScanRun.started_at.desc(), ScanRun.id.desc()).limit(1))
            last_run = None
            if last:
                last_run = {
                    "id": last.id, "started_at": last.started_at.isoformat(),
                    "finished_at": last.finished_at.isoformat() if last.finished_at else None,
                    "status": last.status, "trigger": last.trigger, "canary_status": last.canary_status,
                    "notify_status": last.notify_status,
                    "db_status": json.loads(last.db_status or "{}"),
                }
            ampel = compute_ampel(counts, cov, last, now)
            from .actions import affected_warnings, apply_done, next_steps
            steps = apply_done(s, next_steps(s, counts, cov, last, now), last) \
                if ampel in ("rot", "gelb", "unbekannt") else []
            warnings_hit = affected_warnings(s, now)
            active_run = None
            if newest and newest.status in ("collecting", "queued", "running"):
                active_run = {"run_id": newest.id, "phase": "collecting" if newest.status == "collecting" else "scanning",
                              "status": newest.status, "started_at": newest.started_at.isoformat()}
                if newest.status == "collecting":
                    active_run.update(collection_progress(ctx, s) or {})
                else:   # was der Worker gerade tut (Schritt, Host, Image)
                    job = s.scalar(select(ScanJob).where(ScanJob.run_id == newest.id)   # der laufende zählt, nicht ein
                                   .order_by((ScanJob.status == "running").desc(), ScanJob.id.desc()).limit(1))   # wartender Doppelauftrag
                    if job is not None:
                        active_run["progress"] = json.loads(job.progress or "{}")
                        active_run["claimed_at"] = job.claimed_at
        from .earlywarning import overview_summary
        from .schedule import get_short_schedule, next_run_iso, next_short_iso
        with ctx.session_factory() as s:
            early = overview_summary(ctx, s)
        return {
            "short_run": {**get_short_schedule(ctx), "next_run": next_short_iso(ctx)},
            "early_warning": early,
            "ampel": ampel,
            "next_steps": steps,
            "early_warning_hits": warnings_hit,   # eigene Leiste auf der Übersicht
            "updates": pending_updates(ctx),      # ebenso: Agent-Updates und Sicherheitsupdates der Hosts
            "findings": counts,
            "fixable": fixable,
            "coverage": cov["systems"],
            "coverage_percent": cov["coverage_percent"],
            "canary_status": cov["canary_status"],
            "last_run": last_run,
            "active_run": active_run,
            "next_run": next_run_iso(ctx),
            "worker": worker_last_seen(ctx),
            "watchdog": {"configured": False},
            "setup_hints": [{"id": "notifications", "done": notifications_done}],
        }

    class DoneIn(BaseModel):
        id: str = Field(min_length=1, max_length=200)
        done: bool = True

    @router.get("/systems/{system_id}/coverage", dependencies=[Depends(guards.require_session)])
    def system_coverage(system_id: int):
        """Zeile der Abdeckungsmatrix für die Host-Detailansicht: Prüfungen, letzter Scan, was nicht prüfbar war."""
        with ctx.session_factory() as s:
            cov = calculate_coverage_matrix(s, None, lambda i: (ctx.settings.data_dir / "sboms" / f"{i}.json").is_file(),
                                          lambda sid, i: image_sbom_path(ctx, sid, i).is_file())
        row = next((r for r in cov["systems"] if r["system_id"] == system_id), None)
        if row is None:
            raise HTTPException(404, "system not found")
        return row

    @router.post("/overview/steps/done")
    def step_done(body: DoneIn, found=Depends(guards.require_admin)):
        """Schritt abhaken: verborgen bis zum nächsten Lauf, der ihn auflöst oder wieder zeigt."""
        from .actions import mark_done
        with ctx.session_factory() as s:
            mark_done(s, latest_finished_run(s), body.id, body.done)
            ctx.audit(s, found[0].username, "overview.step_done" if body.done else "overview.step_undone", body.id)
            s.commit()
        return {"ok": True}

    return router


def pending_updates(ctx: Context) -> dict:
    """Was auf den Hosts zu aktualisieren ist: der Agent (neue Version freigegeben) und Sicherheitsupdates."""
    from .agent_api import _version
    newest = ctx.settings_agent_version()
    with ctx.session_factory() as s:
        hosts = s.scalars(select(System).where(System.status == "active").order_by(System.name)).all()
        return {
            "agent_version": newest,
            "agent_outdated": [{"id": h.id, "name": h.name, "version": h.agent_version} for h in hosts
                               if _version(h.agent_version) < _version(newest)],
            "security": [{"id": h.id, "name": h.name, "count": h.security_updates_count} for h in hosts
                         if h.security_updates_count > 0],
        }
