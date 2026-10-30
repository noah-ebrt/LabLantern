import json
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select, tuple_
from sqlalchemy.orm import aliased

from .context import Context
from .guards import Guards
from .models import Finding, ScanRun, System, SystemScanResult
from .scanrun import ScanAlreadyActive, enqueue_scan_run, request_scan_run


class TriggerIn(BaseModel):
    # full: Agenten um frische Daten bitten, scannen, dazu Produktstände und KI-Frühwarnung (wie der tägliche Lauf)
    # latest: sofort mit den zuletzt automatisch gemeldeten Agentendaten scannen und bewerten (wie der Kurzlauf)
    mode: Literal["full", "latest"] = "full"


class AcceptFindingIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)
    days: int = Field(default=30, ge=1, le=90)


def _loads(raw: str) -> dict:
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}


def fixable_now():
    """Scannerfund mit Fix-Version, den ein Update jetzt behebt: das Paketupdate auf dem Host, oder für das Image
    gibt es ein neueres (VW-IMAGE-OUTDATED/-NEWER auf demselben Ziel). Steht der Fix nur in der Paketquelle der
    Distribution und das Image ist nicht neu gebaut, zählt er nicht. Ob das neue Image den Fix wirklich enthält,
    zeigt erst der nächste Scan."""
    update = aliased(Finding)
    # nicht korreliert: einmal ausgewertet; ein EXISTS je Fund dauert bei >100 000 offenen Funden Minuten
    image_update = tuple_(Finding.system_id, Finding.target).in_(
        select(update.system_id, update.target).where(update.cve_id.in_(("VW-IMAGE-OUTDATED", "VW-IMAGE-NEWER")),
                                                      update.status != "resolved"))
    return ((Finding.fixed_version != "") & Finding.source.in_(("grype", "osv", "both"))
            & ((Finding.target == "host") | image_update))


def run_to_dict(r: ScanRun) -> dict:
    return {
        "id": r.id,
        "started_at": r.started_at.isoformat(),
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "status": r.status,
        "trigger": r.trigger,
        "canary_status": r.canary_status,
        "canary_details": r.canary_details,
        "db_status": _loads(r.db_status),
        "error": r.error,
        "notify_status": r.notify_status,
        "archive_status": r.archive_status,
        "config_version": r.config_version,
        "summary_counts": _loads(r.summary_counts),
    }


def build_runs_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    # --- Findings ---

    @router.get("/findings")
    def list_findings(
        response: Response,
        severity: str | None = Query(None),
        system_id: int | None = Query(None),
        status: str = Query("open"),
        q: str | None = Query(None, max_length=100),
        source: str | None = Query(None, pattern=r"^(grype|osv|both|registry|eol|ai|npm|scanner|products|appliances|truenas|homeassistant)$"),
        kev: bool | None = Query(None),
        exposed: bool | None = Query(None),
        has_fix: bool | None = Query(None),
        fixable: bool | None = Query(None),
        limit: int = Query(200, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        _found=Depends(guards.require_session),
    ):
        with ctx.session_factory() as s:
            stmt = select(Finding, System.name.label("system_name")).join(System, Finding.system_id == System.id)
            if status != "all":
                stmt = stmt.where(Finding.status == status)
            if severity:
                stmt = stmt.where(Finding.severity == severity)
            if system_id:
                stmt = stmt.where(Finding.system_id == system_id)
            groups = {"scanner": ("grype", "osv", "both"), "products": ("registry", "eol"),
                      "appliances": ("truenas", "homeassistant")}
            if source:
                stmt = stmt.where(Finding.source.in_(groups.get(source, (source,))))
            if kev is not None:
                stmt = stmt.where(Finding.kev == kev)
            if exposed is not None:
                stmt = stmt.where(Finding.internet_exposed == exposed)
            if has_fix is not None:
                stmt = stmt.where((Finding.fixed_version != "") if has_fix else (Finding.fixed_version == ""))
            if fixable is not None:
                stmt = stmt.where(fixable_now() if fixable else ~fixable_now())
            if q and q.strip():
                like = f"%{q.strip()}%"
                stmt = stmt.where(Finding.cve_id.ilike(like) | Finding.component.ilike(like)
                                  | Finding.target.ilike(like) | System.name.ilike(like))
            total = s.scalar(select(func.count()).select_from(stmt.subquery()))
            response.headers["X-Total-Count"] = str(total)
            rank = case({"kritisch": 0, "hoch": 1, "mittel": 2}, value=Finding.severity, else_=3)
            rows = s.execute(stmt.order_by(rank, Finding.kev.desc(), Finding.cvss_score.desc(), Finding.id.desc())
                             .limit(limit).offset(offset)).all()
            from .recommend import recommend
            systems = {x.id: x for x in s.scalars(select(System).where(System.id.in_({f.system_id for f, _ in rows})))}
            return [
                {
                    "id": f.id, "cve_id": f.cve_id, "title": f.title, "target": f.target, "severity": f.severity,
                    "system_id": f.system_id, "system_name": name, "component": f.component,
                    "installed_version": f.installed_version, "fixed_version": f.fixed_version,
                    "cvss_score": f.cvss_score, "epss_score": f.epss_score, "kev": f.kev,
                    "source": f.source, "internet_exposed": f.internet_exposed, "status": f.status,
                    "accepted_reason": f.accepted_reason,
                    "accepted_until": f.accepted_until.isoformat() if f.accepted_until else None,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                    "action": recommend(f, systems.get(f.system_id)),   # Text und Befehl, siehe recommend.py
                }
                for f, name in rows
            ]

    @router.post("/findings/{finding_id}/accept")
    def accept_finding(finding_id: int, body: AcceptFindingIn, found=Depends(guards.require_admin)):
        user, _ = found
        with ctx.session_factory() as s:
            finding = s.get(Finding, finding_id)
            if not finding:
                raise HTTPException(404, "Finding not found")
            finding.status = "accepted"
            finding.accepted_reason = body.reason
            finding.accepted_until = datetime.now(timezone.utc) + timedelta(days=body.days)
            ctx.audit(s, user.username, "finding.accepted",
                      f"{finding.cve_id} accepted for {body.days} days: {body.reason}")
            s.commit()
        return {"ok": True}

    # --- Verlauf (PLAN Abschnitt 7) ---

    @router.get("/history")
    def history(days: int = Query(90, ge=7, le=365), _found=Depends(guards.require_session)):
        """Funde je Stufe, Laufdauer und Abdeckung je Lauf; Zeit bis zur Behebung je Woche (kritisch/hoch)."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        with ctx.session_factory() as s:
            runs = s.scalars(select(ScanRun).where(ScanRun.started_at >= since, ScanRun.finished_at.is_not(None))
                             .order_by(ScanRun.started_at)).all()
            fixed = s.execute(select(Finding.created_at, Finding.resolved_at, Finding.severity).where(
                Finding.resolved_at >= since, Finding.severity.in_(("kritisch", "hoch")))).all()
        weeks: dict[str, list[float]] = {}
        for created, resolved, _sev in fixed:
            week = (resolved - timedelta(days=resolved.weekday())).date().isoformat()
            weeks.setdefault(week, []).append((resolved - created).total_seconds() / 86400)
        return {
            "runs": [{"id": r.id, "started_at": r.started_at.isoformat(), "status": r.status, "trigger": r.trigger,
                      "duration_min": round((r.finished_at - r.started_at).total_seconds() / 60, 1),
                      "counts": _loads(r.summary_counts), "coverage_percent": r.coverage_percent} for r in runs],
            "time_to_fix": [{"week": w, "fixed": len(v), "median_days": round(sorted(v)[len(v) // 2], 1)}
                            for w, v in sorted(weeks.items())],
        }

    # --- Läufe ---

    @router.get("/runs")
    def list_runs(_found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            runs = s.scalars(select(ScanRun).order_by(ScanRun.started_at.desc(), ScanRun.id.desc()).limit(30)).all()
            return [run_to_dict(r) for r in runs]

    @router.get("/runs/{run_id}")
    def get_run(run_id: int, _found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            run = s.get(ScanRun, run_id)
            if run is None:
                raise HTTPException(404, "Run not found")
            rows = s.execute(
                select(SystemScanResult, System.name).join(System, System.id == SystemScanResult.system_id)
                .where(SystemScanResult.run_id == run_id).order_by(System.name)
            ).all()
            return {**run_to_dict(run), "systems": [
                {"system_id": r.system_id, "system_name": name, "status": r.status, "error": r.error,
                 "findings_count": r.findings_count, "image_errors": _loads(r.image_errors)} for r, name in rows
            ]}

    @router.post("/runs/trigger")
    def trigger_run(body: TriggerIn | None = None, found=Depends(guards.require_admin)):
        from .schedule import start_side_passes

        user, _ = found
        mode = body.mode if body else "full"
        try:
            run = request_scan_run(ctx, "manual") if mode == "full" else enqueue_scan_run(ctx, "short")
        except ScanAlreadyActive:
            raise HTTPException(409, "A scan is already running") from None
        if mode == "full":
            start_side_passes(ctx)
        with ctx.session_factory() as s:
            ctx.audit(s, user.username, "run.queued",
                      f"Manual {'full' if mode == 'full' else 'latest-data'} scan run #{run.id} queued")
            s.commit()
        return {"ok": True, "run_id": run.id, "status": run.status, "mode": mode}

    return router
