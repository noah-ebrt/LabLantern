import logging
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .context import Context
from .guards import Guards
from .models import put_setting, setting
from .scanrun import ScanAlreadyActive, advance_collecting_runs, expire_stale_jobs, request_scan_run

log = logging.getLogger("vulnwatch.schedule")

SCHEDULE_KEY = "schedule.daily"
DEFAULT = {"enabled": True, "time": "03:00"}
SHORT_KEY = "schedule.short"
# Kurzlauf (PLAN Abschnitt 7): scannt mit den vorhandenen Agentendaten und frischer Datenbank, meldet nur Neues
SHORT_DEFAULT = {"enabled": True, "hours": 12}   # ein Lauf mit Grype und OSV dauert ~45 min
SHORT_HOURS = (2, 3, 4, 6, 8, 12)
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
TIMEZONE_KEY = "system.timezone"
DEFAULT_TZ = "UTC"


def get_timezone(ctx: Context) -> str:
    """Zeitzone des Systems (IANA-Name): gilt für den täglichen Lauf und für alle Zeitangaben in der Oberfläche."""
    with ctx.session_factory() as s:
        return setting(s, TIMEZONE_KEY, DEFAULT_TZ, raw=True)


def set_timezone(ctx: Context, name: str) -> None:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"Unknown time zone: {name}") from None
    with ctx.session_factory() as s:
        put_setting(s, TIMEZONE_KEY, name, raw=True)
        s.commit()


def get_schedule(ctx: Context) -> dict:
    with ctx.session_factory() as s:
        return {**DEFAULT, **setting(s, SCHEDULE_KEY, {})}


def set_schedule(ctx: Context, enabled: bool, time: str) -> None:
    if not _TIME.match(time):
        raise ValueError("Time must be HH:MM (24 h)")
    with ctx.session_factory() as s:
        put_setting(s, SCHEDULE_KEY, {"enabled": enabled, "time": time})
        s.commit()


def get_short_schedule(ctx: Context) -> dict:
    with ctx.session_factory() as s:
        return {**SHORT_DEFAULT, **setting(s, SHORT_KEY, {})}


def set_short_schedule(ctx: Context, enabled: bool, hours: int) -> None:
    if hours not in SHORT_HOURS:
        raise ValueError(f"Interval must be one of {', '.join(map(str, SHORT_HOURS))} hours")
    with ctx.session_factory() as s:
        put_setting(s, SHORT_KEY, {"enabled": enabled, "hours": hours})
        s.commit()


def short_hours_of_day(ctx: Context) -> list[int]:
    """Stunden der Kurzläufe: ab der Stunde des täglichen Laufs im Abstand `hours`, ohne die tägliche selbst.
    Feste Uhrzeiten statt „alle N h ab Serverstart“: vorhersehbar und als Cron in Healthchecks eintragbar."""
    hours = get_short_schedule(ctx)["hours"]
    daily_h = int(get_schedule(ctx)["time"].split(":")[0])
    return sorted((daily_h + k * hours) % 24 for k in range(1, 24 // hours))


def next_short_iso(ctx: Context) -> str | None:
    short = get_short_schedule(ctx)
    if not short["enabled"]:
        return None
    minute = int(get_schedule(ctx)["time"].split(":")[1])
    tz = ZoneInfo(get_timezone(ctx))
    now = datetime.fromtimestamp(ctx.clock(), tz=tz)
    for day in (0, 1):
        for h in short_hours_of_day(ctx):
            cand = (now + timedelta(days=day)).replace(hour=h, minute=minute, second=0, microsecond=0)
            if cand > now:
                return cand.astimezone(timezone.utc).isoformat()
    return None


def start_side_passes(ctx: Context) -> None:
    """Zum vollständigen Lauf gehören auch Produktstände und KI-Frühwarnung: beide im Hintergrund anstoßen,
    damit ihr Ergebnis im Report des Laufs steht (sie sind nach Minuten fertig, der Scan dauert länger)."""
    import threading

    from .earlywarning import run_pass
    from .products import refresh_versions

    for name, fn in (("versions", refresh_versions), ("earlywarning", run_pass)):
        threading.Thread(target=_safe, args=(fn, ctx, name), daemon=True, name=name).start()


def _safe(fn, ctx: Context, name: str) -> None:
    try:
        fn(ctx)
    except Exception:
        log.exception("%s pass failed", name)


def run_short_job(ctx: Context) -> None:
    """Überspringt, wenn gerade ein Lauf aktiv ist oder der letzte erst vor kurzem begann (z. B. der tägliche)."""
    from sqlalchemy import select

    from .models import ScanRun
    from .scanrun import enqueue_scan_run

    hours = get_short_schedule(ctx)["hours"]
    with ctx.session_factory() as s:
        last = s.scalar(select(ScanRun.started_at).order_by(ScanRun.started_at.desc()).limit(1))
    if last is not None and (datetime.now(timezone.utc) - last).total_seconds() < hours * 3600 / 2:
        log.info("Short run skipped: last run started %s", last.isoformat())
        return
    try:
        run = enqueue_scan_run(ctx, "short")
        log.info("Short run queued (run #%d)", run.id)
    except ScanAlreadyActive:
        log.info("Short run skipped: a scan is already running")


def _versions(ctx: Context) -> None:
    from .products import refresh_versions

    try:
        refresh_versions(ctx)
    except Exception:
        log.exception("Version check failed")


def _early_warnings(ctx: Context) -> None:
    from .earlywarning import run_pass

    try:
        run_pass(ctx)
    except Exception:
        log.exception("Early warning pass failed")


def next_run_iso(ctx: Context) -> str | None:
    sched = get_schedule(ctx)
    if not sched["enabled"]:
        return None
    tz = ZoneInfo(get_timezone(ctx))
    now = datetime.fromtimestamp(ctx.clock(), tz=tz)
    hour, minute = map(int, sched["time"].split(":"))
    nxt = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)   # Wanduhr-Arithmetik: bleibt bei Sommerzeitwechsel auf HH:MM
    return nxt.astimezone(timezone.utc).isoformat()


def run_daily_job(ctx: Context) -> None:
    try:
        run = request_scan_run(ctx, "scheduled")
        log.info("Daily scan queued (run #%d)", run.id)
    except ScanAlreadyActive:
        log.warning("Daily scan skipped: a scan is already running")
        return
    start_side_passes(ctx)


def _maintenance(ctx: Context) -> None:
    try:
        advance_collecting_runs(ctx)
        expire_stale_jobs(ctx)
    except Exception:
        log.exception("Maintenance run failed")


def _release_sync(ctx: Context) -> None:
    from .releases import check_releases

    try:
        status = check_releases(ctx)
        if not status["ok"]:
            log.info("Agent release sync skipped: %s", status["error"])
    except Exception:
        log.exception("Agent release sync failed")


def apply_schedule(scheduler: BackgroundScheduler, ctx: Context) -> None:
    sched = get_schedule(ctx)
    for job_id in ("daily-scan", "short-scan"):
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
    from .watchdog import get_config as watchdog_config
    if scheduler.get_job("watchdog-heartbeat"):
        scheduler.reschedule_job("watchdog-heartbeat", trigger="interval", minutes=watchdog_config(ctx)["heartbeat_minutes"])
    hour, minute = map(int, sched["time"].split(":"))
    short = get_short_schedule(ctx)
    if short["enabled"]:
        scheduler.add_job(run_short_job, CronTrigger(hour=",".join(map(str, short_hours_of_day(ctx))), minute=minute,
                                                     timezone=ZoneInfo(get_timezone(ctx))),
                          args=[ctx], id="short-scan", max_instances=1, coalesce=True, misfire_grace_time=1800)
    if not sched["enabled"]:
        return
    scheduler.add_job(run_daily_job, CronTrigger(hour=hour, minute=minute, timezone=ZoneInfo(get_timezone(ctx))),
                      args=[ctx], id="daily-scan", misfire_grace_time=3600,
                      coalesce=True)


def _heartbeat(ctx: Context) -> None:
    from .watchdog import heartbeat

    try:
        heartbeat(ctx)
    except Exception:
        log.exception("Watchdog heartbeat failed")


def build_scheduler(ctx: Context) -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(_maintenance, "interval", seconds=60, args=[ctx], id="maintenance",
                      max_instances=1, coalesce=True)
    # agent-sign läuft bei jedem `docker compose up`; ein neues Release ist so binnen einer Minute ausgeliefert
    scheduler.add_job(_release_sync, "interval", minutes=1, args=[ctx], id="release-sync",
                      max_instances=1, coalesce=True,
                      next_run_time=datetime.now(timezone.utc) + timedelta(seconds=30))
    # Herzschlag an den Offsite-Wächter (tut nichts, solange keine Ping-URL hinterlegt ist)
    scheduler.add_job(_heartbeat, "interval", minutes=5, args=[ctx], id="watchdog-heartbeat",
                      max_instances=1, coalesce=True, next_run_time=datetime.now(timezone.utc) + timedelta(seconds=20))
    # Produktstände (Registry, EOL, NPM) wie früher image-check alle 6 h; der erste Durchgang kurz nach dem Start
    from .products import INTERVAL_HOURS
    scheduler.add_job(_versions, "interval", hours=INTERVAL_HOURS, args=[ctx], id="versions",
                      max_instances=1, coalesce=True, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2))
    # KI-Frühwarnung: Feeds alle 2 h (ohne Claude-Schlüssel wird alles `unklar`, nie still übergangen)
    from .earlywarning import INTERVAL_HOURS as EW_HOURS
    scheduler.add_job(_early_warnings, "interval", hours=EW_HOURS, args=[ctx], id="early-warnings",
                      max_instances=1, coalesce=True, next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5))
    apply_schedule(scheduler, ctx)
    return scheduler


class ScheduleIn(BaseModel):
    enabled: bool
    time: str


class ShortScheduleIn(BaseModel):
    enabled: bool
    hours: int


class TimezoneIn(BaseModel):
    timezone: str


def build_schedule_router(ctx: Context, guards: Guards) -> APIRouter:
    from fastapi import HTTPException

    router = APIRouter(prefix="/settings")

    @router.get("/schedule", dependencies=[Depends(guards.require_session)])
    def read():
        return {**get_schedule(ctx), "timezone": get_timezone(ctx), "next_run": next_run_iso(ctx)}

    @router.put("/schedule")
    def write(body: ScheduleIn, found=Depends(guards.require_admin)):
        try:
            set_schedule(ctx, body.enabled, body.time)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "settings.schedule",
                      f"daily run {'on' if body.enabled else 'off'}, {body.time} {get_timezone(ctx)}")
            s.commit()
        if ctx.on_schedule_change:
            ctx.on_schedule_change()
        return {"ok": True}

    @router.get("/short-schedule", dependencies=[Depends(guards.require_session)])
    def read_short():
        from .scanrun import REPORT_INTERVAL
        # agent_report_minutes: so oft melden die Agenten von sich aus (der Kurzlauf scannt höchstens so alte Daten)
        return {**get_short_schedule(ctx), "choices": list(SHORT_HOURS), "hours_of_day": short_hours_of_day(ctx),
                "next_run": next_short_iso(ctx), "agent_report_minutes": REPORT_INTERVAL // 60}

    @router.put("/short-schedule")
    def write_short(body: ShortScheduleIn, found=Depends(guards.require_admin)):
        try:
            set_short_schedule(ctx, body.enabled, body.hours)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "settings.short_schedule",
                      f"short run {'on' if body.enabled else 'off'}, every {body.hours} h")
            s.commit()
        if ctx.on_schedule_change:
            ctx.on_schedule_change()
        return {"ok": True}

    @router.get("/timezone", dependencies=[Depends(guards.require_session)])
    def read_timezone():
        return {"timezone": get_timezone(ctx)}

    @router.put("/timezone")
    def write_timezone(body: TimezoneIn, found=Depends(guards.require_admin)):
        try:
            set_timezone(ctx, body.timezone)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "settings.timezone", f"time zone {body.timezone}")
            s.commit()
        if ctx.on_schedule_change:
            ctx.on_schedule_change()
        return {"ok": True}

    return router
