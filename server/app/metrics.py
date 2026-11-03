"""Prometheus-Endpunkt `/metrics` (PLAN Abschnitt 7): Zustand für Grafana & Co., keine eigenen Zeitreihen.
Nur mit Bearer-Token (in der Datenbank nur sein SHA-256); ohne Token ist der Endpunkt aus. Keine Geheimnisse,
keine Fund-Details: nur Zählungen und Zustände je System und Prüfung."""
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from sqlalchemy import func, select

from .auth import sha256_hex
from .context import Context
from .guards import Guards
from .models import EarlyWarning, Finding, ScanRun, System, put_setting, setting

TOKEN_KEY = "metrics.token"   # {"hash": SHA-256, "created_at": ISO}
CHECK_VALUE = {"ok": 0, "fund": 1, "offen": 2, "fehler": 3}


def _label(v) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class Exposition:
    def __init__(self):
        self.lines: list[str] = []
        self.seen: set[str] = set()

    def add(self, name: str, help_: str, value, **labels) -> None:
        if value is None:
            return
        if name not in self.seen:
            self.seen.add(name)
            self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} gauge"]
        lbl = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
        self.lines.append(f"{name}{{{lbl}}} {float(value):g}" if lbl else f"{name} {float(value):g}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(ctx: Context) -> str:
    from .agent_api import is_connected, _version
    from .coverage import calculate_coverage_matrix
    from .scanrun import image_sbom_path, sbom_path
    from .worker_api import worker_last_seen

    m = Exposition()
    now = datetime.now(timezone.utc)
    m.add("lablantern_up", "1 while the LabLantern master answers.", 1)
    with ctx.session_factory() as s:
        for sev, n in s.execute(select(Finding.severity, func.count(Finding.id)).where(Finding.status == "open")
                                .group_by(Finding.severity)):
            m.add("lablantern_findings_open", "Open findings by severity.", n, severity=sev)
        names = dict(s.execute(select(System.id, System.name)).all())
        for sid, sev, n in s.execute(select(Finding.system_id, Finding.severity, func.count(Finding.id))
                                     .where(Finding.status == "open").group_by(Finding.system_id, Finding.severity)):
            m.add("lablantern_system_findings_open", "Open findings per system and severity.", n,
                  system=names.get(sid, sid), severity=sev)
        cov = calculate_coverage_matrix(s, now, lambda i: sbom_path(ctx, i).is_file(),
                                        lambda sid, i: image_sbom_path(ctx, sid, i).is_file())
        m.add("lablantern_coverage_percent", "Share of checks that ran without error.", cov["coverage_percent"])
        for row in cov["systems"]:
            for check, c in row["checks"].items():
                m.add("lablantern_check_status", "Per system and check: 0 ok, 1 finding, 2 queued, 3 error.",
                      CHECK_VALUE.get(c["status"], 3), system=row["system_name"], check=check)
        newest = ctx.settings_agent_version()
        for sys in s.scalars(select(System).where(System.status == "active")):
            if sys.last_seen:
                m.add("lablantern_agent_report_age_seconds", "Seconds since the agent's last report.",
                      round((now - sys.last_seen).total_seconds()), system=sys.name)
            m.add("lablantern_agent_connected", "1 while the agent holds its command connection.",
                  int(is_connected(ctx, sys)), system=sys.name)
            m.add("lablantern_agent_outdated", "1 if a newer agent release is available.",
                  int(_version(sys.agent_version) < _version(newest)), system=sys.name)
        run = s.scalar(select(ScanRun).where(ScanRun.finished_at.is_not(None))
                       .order_by(ScanRun.finished_at.desc()).limit(1))
        if run:
            m.add("lablantern_last_run_finished_timestamp_seconds", "When the last scan run finished.", run.finished_at.timestamp())
            m.add("lablantern_last_run_success", "1 if the last run checked every system.", int(run.status == "success"))
            m.add("lablantern_last_run_duration_seconds", "Duration of the last run.",
                  round((run.finished_at - run.started_at).total_seconds()))
            m.add("lablantern_canary_ok", "1 if the canary test of the last run passed.", int(run.canary_status == "ok"))
            db = json.loads(run.db_status or "{}")
            m.add("lablantern_scanner_db_age_hours", "Age of the scanner databases in the last run.", db.get("age_hours"), db="grype")
            if db.get("osv"):
                m.add("lablantern_scanner_db_age_hours", "Age of the scanner databases in the last run.",
                      db["osv"].get("age_hours"), db="osv")
        for st, n in s.execute(select(EarlyWarning.status, func.count(EarlyWarning.id)).group_by(EarlyWarning.status)):
            m.add("lablantern_early_warnings", "Early warnings by rating.", n, status=st)
        for c in (setting(s, "npm.state") or {}).get("certificates") or []:
            m.add("lablantern_tls_certificate_days_left", "Days until a certificate used by an active NPM proxy host expires.",
                  c.get("days_left"), domain=", ".join(c.get("domains") or []) or c.get("name", ""))
        for kind, last in (setting(s, "watchdog.last") or {}).items():
            m.add("lablantern_watchdog_ping_ok", "1 if the last ping to the offsite watchdog was delivered.",
                  int(bool(last.get("ok"))), check=kind)
    age = worker_last_seen(ctx)["age_seconds"]
    m.add("lablantern_worker_last_seen_age_seconds", "Seconds since the scan worker last asked for a job.", age)
    from .models import HealthMonitor

    with ctx.session_factory() as s:
        for mon in s.scalars(select(HealthMonitor).order_by(HealthMonitor.slug)):
            value = -1 if mon.paused else {"up": 1, "degraded": 0.5, "down": 0}.get(mon.state, -1)
            m.add("lablantern_health_state", "Health monitor: 1 up, 0.5 degraded, 0 down, -1 unknown or paused.", value,
                  monitor=mon.slug, name=mon.name)
    return m.text()


def build_metrics_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    @router.get("/metrics", include_in_schema=False)
    def metrics(authorization: str | None = Header(None)):
        with ctx.session_factory() as s:
            cfg = setting(s, TOKEN_KEY)
        if not cfg:
            raise HTTPException(404, "Metrics are disabled (enable them under Settings)")
        given = (authorization or "").removeprefix("Bearer ").strip()
        if not given or not hmac.compare_digest(sha256_hex(given), cfg["hash"]):
            raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
        return Response(render(ctx), media_type="text/plain; version=0.0.4; charset=utf-8")

    @router.get("/api/settings/metrics", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            cfg = setting(s, TOKEN_KEY)
        return {"enabled": bool(cfg), "created_at": (cfg or {}).get("created_at")}

    @router.post("/api/settings/metrics/token")
    def new_token(found=Depends(guards.require_admin)):
        """Neues Token; es wird genau einmal angezeigt. Ein altes Token gilt danach nicht mehr."""
        token = secrets.token_urlsafe(32)
        with ctx.session_factory() as s:
            put_setting(s, TOKEN_KEY, {"hash": sha256_hex(token), "created_at": datetime.now(timezone.utc).isoformat()})
            ctx.audit(s, found[0].username, "settings.metrics", "new scrape token")
            s.commit()
        return {"token": token}

    @router.delete("/api/settings/metrics")
    def disable(found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            put_setting(s, TOKEN_KEY, None)
            ctx.audit(s, found[0].username, "settings.metrics", "metrics disabled")
            s.commit()
        return {"ok": True}

    return router
