import json
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select, tuple_
from sqlalchemy.orm import aliased

from .context import Context
from .guards import Guards
from .models import CoverageExclusion, Finding, ScanRun, Snooze, System, SystemScanResult
from .scanrun import ScanAlreadyActive, enqueue_scan_run, request_scan_run
from .snooze import apply_snoozes, create_exclusion, create_snooze


class TriggerIn(BaseModel):
    # full: Agenten um frische Daten bitten, scannen, dazu Produktstände und KI-Frühwarnung (wie der tägliche Lauf)
    # latest: sofort mit den zuletzt automatisch gemeldeten Agentendaten scannen und bewerten (wie der Kurzlauf)
    mode: Literal["full", "latest"] = "full"


class SnoozeIn(BaseModel):
    scope: Literal["occurrence", "everywhere"] = "occurrence"
    until: date   # der Snooze endet am Beginn dieses Tages (UTC)
    reason: str = Field(min_length=3, max_length=500)


class SnoozeKeyIn(SnoozeIn):
    """Snooze ohne Fund-ID (Konfiguration als JSON): CVE, Komponente und bei "occurrence" System und Ziel."""
    cve_id: str = Field(min_length=1, max_length=200)
    component: str = Field(min_length=1, max_length=300)
    system_id: int | None = None
    target: str = Field(default="host", max_length=300)


class ExclusionIn(BaseModel):
    subject: str = Field(min_length=3, max_length=200)
    until: date
    reason: str = Field(min_length=3, max_length=500)


def _until(d: date) -> datetime:
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)


def _loads(raw: str) -> dict:
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}


def fixable_now():
    """Scannerfund mit Fix-Version, den ein Update jetzt behebt: das Paketupdate auf dem Host, oder für das Image
    gibt es ein neueres (LL-IMAGE-OUTDATED/-NEWER auf demselben Ziel). Steht der Fix nur in der Paketquelle der
    Distribution und das Image ist nicht neu gebaut, zählt er nicht. Ob das neue Image den Fix wirklich enthält,
    zeigt erst der nächste Scan."""
    update = aliased(Finding)
    # nicht korreliert: einmal ausgewertet; ein EXISTS je Fund dauert bei >100 000 offenen Funden Minuten
    image_update = tuple_(Finding.system_id, Finding.target).in_(
        select(update.system_id, update.target).where(update.cve_id.in_(("LL-IMAGE-OUTDATED", "LL-IMAGE-NEWER")),
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

    class FindingFilters:
        """Filter der Fundliste; gelten gleich für Liste, „By host“ und die Gruppen eines Hosts."""

        def __init__(
            self,
            severity: str | None = Query(None),
            system_id: int | None = Query(None),
            status: str = Query("open"),
            q: str | None = Query(None, max_length=100),
            source: str | None = Query(None, pattern=r"^(grype|osv|both|registry|eol|ai|npm|scanner|products|appliances|truenas|homeassistant|proxmox|synology|opnsense)$"),
            kev: bool | None = Query(None),
            exposed: bool | None = Query(None),
            has_fix: bool | None = Query(None),
            fixable: bool | None = Query(None),
            target: str | None = Query(None, max_length=300),
        ):
            self.severity, self.system_id, self.status, self.q, self.source = severity, system_id, status, q, source
            self.kev, self.exposed, self.has_fix, self.fixable, self.target = kev, exposed, has_fix, fixable, target

        def apply(self, stmt):
            if self.status != "all":
                stmt = stmt.where(Finding.status == self.status)
            if self.severity:
                stmt = stmt.where(Finding.severity == self.severity)
            if self.system_id:
                stmt = stmt.where(Finding.system_id == self.system_id)
            if self.target:
                stmt = stmt.where(Finding.target == self.target)
            groups = {"scanner": ("grype", "osv", "both"), "products": ("registry", "eol"),
                      "appliances": ("truenas", "homeassistant", "proxmox", "synology", "opnsense")}
            if self.source:
                stmt = stmt.where(Finding.source.in_(groups.get(self.source, (self.source,))))
            if self.kev is not None:
                stmt = stmt.where(Finding.kev == self.kev)
            if self.exposed is not None:
                stmt = stmt.where(Finding.internet_exposed == self.exposed)
            if self.has_fix is not None:
                stmt = stmt.where((Finding.fixed_version != "") if self.has_fix else (Finding.fixed_version == ""))
            if self.fixable is not None:
                stmt = stmt.where(fixable_now() if self.fixable else ~fixable_now())
            if self.q and self.q.strip():
                like = f"%{self.q.strip()}%"
                stmt = stmt.where(Finding.cve_id.ilike(like) | Finding.component.ilike(like)
                                  | Finding.target.ilike(like) | System.name.ilike(like))
            return stmt

    def _base(flt: FindingFilters):
        return flt.apply(select(Finding).join(System, Finding.system_id == System.id))

    @router.get("/findings/by-host")
    def findings_by_host(flt: FindingFilters = Depends(), _found=Depends(guards.require_session)):
        from .findgroups import host_summaries
        with ctx.session_factory() as s:
            return host_summaries(s, _base(flt), fixable_now())

    @router.get("/findings/groups")
    def findings_groups(system_id: int = Query(...), flt: FindingFilters = Depends(),
                        _found=Depends(guards.require_session)):
        from .findgroups import host_groups, image_statuses
        from .products import load_state
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if system is None:
                raise HTTPException(404, "system not found")
            flt.system_id = None   # host_groups grenzt selbst ein
            return {"system_id": system.id, "system_name": system.name,
                    "groups": host_groups(s, system, _base(flt), image_statuses(load_state(s), system.id),
                                          fixable_now())}

    @router.get("/findings")
    def list_findings(
        response: Response,
        flt: FindingFilters = Depends(),
        limit: int = Query(200, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        _found=Depends(guards.require_session),
    ):
        with ctx.session_factory() as s:
            stmt = flt.apply(select(Finding, System.name.label("system_name")).join(System, Finding.system_id == System.id))
            total = s.scalar(select(func.count()).select_from(stmt.subquery()))
            response.headers["X-Total-Count"] = str(total)
            rank = case({"kritisch": 0, "hoch": 1, "mittel": 2}, value=Finding.severity, else_=3)
            rows = s.execute(stmt.order_by(rank, Finding.kev.desc(), Finding.cvss_score.desc(), Finding.id.desc())
                             .limit(limit).offset(offset)).all()
            from .findgroups import image_statuses
            from .products import load_state
            from .recommend import recommend
            systems = {x.id: x for x in s.scalars(select(System).where(System.id.in_({f.system_id for f, _ in rows})))}
            state = load_state(s) if any(f.target.startswith("image:") for f, _ in rows) else None
            statuses = {sid: image_statuses(state, sid) for sid in systems}
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
                    "action": recommend(f, systems.get(f.system_id),
                                        statuses.get(f.system_id, {}).get(f.target.removeprefix("image:"))),   # Text und Befehl, siehe recommend.py
                }
                for f, name in rows
            ]

    # --- Snooze (PLAN-extensions A2): nur Admins, nie die KI ---

    def _create(s, f: Finding, body: SnoozeIn, user) -> int:
        now = datetime.now(timezone.utc)
        try:
            sn = create_snooze(s, f, body.scope, _until(body.until), body.reason, user.username, now)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        apply_snoozes(s, now)
        s.commit()
        return sn.id

    @router.post("/findings/{finding_id}/snooze")
    def snooze_finding(finding_id: int, body: SnoozeIn, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            finding = s.get(Finding, finding_id)
            if not finding or finding.status == "resolved":
                raise HTTPException(404, "Finding not found")
            return {"ok": True, "id": _create(s, finding, body, found[0])}

    @router.post("/snoozes")
    def snooze_by_key(body: SnoozeKeyIn, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            if body.scope == "occurrence" and (body.system_id is None or not s.get(System, body.system_id)):
                raise HTTPException(422, "A snooze for one occurrence needs an existing system")
            template = Finding(cve_id=body.cve_id, component=body.component, system_id=body.system_id,
                               target=body.target, severity="info")   # nicht gespeichert, nur als Schlüssel
            return {"ok": True, "id": _create(s, template, body, found[0])}

    @router.get("/snoozes", dependencies=[Depends(guards.require_session)])
    def list_snoozes():
        with ctx.session_factory() as s:
            names = {sid: name for sid, name in s.execute(select(System.id, System.name))}

            def row(sn: Snooze) -> dict:
                return {"id": sn.id, "scope": sn.scope, "cve_id": sn.cve_id, "component": sn.component,
                        "system_id": sn.system_id, "target_key": sn.target_key,
                        "system_name": "all systems" if sn.system_id is None else names.get(sn.system_id, "?"),
                        "reason": sn.reason, "until": sn.until.isoformat(), "created_by": sn.created_by,
                        "ended_at": sn.ended_at.isoformat() if sn.ended_at else None, "end_reason": sn.end_reason}
            active = s.scalars(select(Snooze).where(Snooze.ended_at.is_(None)).order_by(Snooze.until))
            ended = s.scalars(select(Snooze).where(Snooze.ended_at.is_not(None))
                              .order_by(Snooze.ended_at.desc()).limit(20))
            return {"active": [row(x) for x in active], "ended": [row(x) for x in ended]}

    @router.post("/coverage/exclusions")
    def exclude_from_coverage(body: ExclusionIn, found=Depends(guards.require_admin)):
        now = datetime.now(timezone.utc)
        with ctx.session_factory() as s:
            kind, _, ident = body.subject.partition(":")
            from .proxmox import known_guest
            if kind == "pve-guest":   # Gast einer Proxmox-Verbindung (PLAN-extensions D1)
                if not known_guest(s, body.subject):
                    raise HTTPException(422, "Unknown Proxmox guest")
            elif kind != "system" or not ident.isdigit() or not s.get(System, int(ident)):
                raise HTTPException(422, "Unknown subject: use system:<id> of an existing system")
            try:
                ex = create_exclusion(s, body.subject, _until(body.until), body.reason, found[0].username, now)
            except ValueError as e:
                raise HTTPException(422, str(e)) from None
            except LookupError as e:
                raise HTTPException(409, str(e)) from None
            s.commit()
            return {"ok": True, "id": ex.id}

    @router.delete("/coverage/exclusions/{exclusion_id}")
    def include_in_coverage(exclusion_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            ex = s.get(CoverageExclusion, exclusion_id)
            if not ex or ex.ended_at is not None:
                raise HTTPException(404, "Exclusion not found")
            ex.ended_at, ex.end_reason = datetime.now(timezone.utc), f"removed by {found[0].username}"
            ctx.audit(s, found[0].username, "exclusion.removed", f"{ex.subject}: {ex.reason}")
            s.commit()
        return {"ok": True}

    @router.delete("/snoozes/{snooze_id}")
    def remove_snooze(snooze_id: int, found=Depends(guards.require_admin)):
        now = datetime.now(timezone.utc)
        with ctx.session_factory() as s:
            sn = s.get(Snooze, snooze_id)
            if not sn or sn.ended_at is not None:
                raise HTTPException(404, "Snooze not found")
            sn.ended_at, sn.end_reason = now, f"removed by {found[0].username}"
            ctx.audit(s, found[0].username, "snooze.removed", f"{sn.cve_id} in {sn.component}: {sn.reason}")
            apply_snoozes(s, now)
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
