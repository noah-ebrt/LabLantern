"""Offsite-Wächter: LabLantern pingt eine Healthchecks-Instanz außer Haus (PLAN Abschnitt 9).

Bleiben die Pings aus (Master aus, Strom oder Internet weg, Lauf hängt), alarmiert Healthchecks von dort aus.
Zwei Checks, angelegt vom Admin in Healthchecks, ihre Ping-URLs hier hinterlegt:
- Herzschlag alle 5 min, solange Master und Worker leben (sonst /fail mit Grund);
- täglicher Lauf: /start beim Beginn, danach Erfolg oder /fail mit Grund.
Die Management-API von Healthchecks bleibt bewusst zu; LabLantern braucht nur die Ping-URLs. Die URLs liegen im
Geheimnisspeicher, weil man mit ihnen Erfolg vortäuschen und so einen Ausfall verdecken könnte.
"""
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .context import Context
from .guards import Guards
from .models import put_setting, setting

log = logging.getLogger("lablantern")

SECRETS = {"heartbeat": "watchdog.heartbeat_url", "run": "watchdog.run_url", "short": "watchdog.short_url"}
STATUS_KEY = "watchdog.last"
PING_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?/ping/[A-Za-z0-9_-]{6,64}(/[A-Za-z0-9_-]{1,100})?$")
CONFIG_KEY = "watchdog.config"
# Wie gepingt wird. Healthchecks: /start, Erfolg, /fail mit Grund. Uptime Kuma: Push-Monitor mit status=up/down.
# Eigener Dienst: nur Erfolg per POST; bleibt er aus (Fehler, Ausfall), schlägt der Dienst selbst Alarm.
PROVIDERS = {
    "healthchecks": PING_URL,
    "uptimekuma": re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~-]+)*/api/push/[A-Za-z0-9_-]{4,64}$"),
    "custom": re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s]*)?$"),
}
HEARTBEAT_MINUTES = (1, 2, 5, 10, 15, 30, 60)
DEFAULT_CONFIG = {"provider": "healthchecks", "heartbeat_minutes": 5}
WORKER_SILENT = 15 * 60   # länger ohne Lebenszeichen des Workers: Herzschlag meldet Fehler
MAX_BODY = 10_000


def get_config(ctx: Context) -> dict:
    with ctx.session_factory() as s:
        return {**DEFAULT_CONFIG, **(setting(s, CONFIG_KEY) or {})}


def ping(url: str, suffix: str = "", body: str = "", timeout: float = 10, method: str = "POST") -> str | None:
    """Sendet einen Ping. Liefert None oder den Fehler; wirft nie (der Wächter darf nichts aufhalten)."""
    data = body[:MAX_BODY].encode() if method == "POST" else None
    req = urllib.request.Request(url + suffix, data=data, method=method,
                                 headers={"Content-Type": "text/plain; charset=utf-8", "User-Agent": "lablantern"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL geprüft, vom Admin hinterlegt)
            return None if 200 <= r.status < 300 else f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return f"unreachable ({getattr(e, 'reason', e)})"


def _record(ctx: Context, kind: str, kind_status: dict) -> None:
    with ctx.session_factory() as s:
        data = setting(s, STATUS_KEY, {})
        data[kind] = kind_status
        put_setting(s, STATUS_KEY, data)
        s.commit()


def _send(ctx: Context, kind: str, suffix: str, body: str, what: str) -> str | None:
    """`suffix` ist die Healthchecks-Form ("", "/start", "/fail"); andere Anbieter übersetzen sie."""
    url = ctx.secrets.get(SECRETS[kind])
    if not url:
        return None   # nicht eingerichtet
    provider = get_config(ctx)["provider"]
    if provider == "uptimekuma":
        if suffix == "/start":
            return None   # Kuma kennt keinen Start
        from urllib.parse import urlencode
        query = urlencode({"status": "down" if suffix == "/fail" else "up", "msg": body[:200], "ping": ""})
        err = ping(url, f"?{query}", method="GET")
    elif provider == "custom":
        if suffix:
            return None   # nur Erfolge; das Ausbleiben ist der Alarm
        err = ping(url, "", body)
    else:
        err = ping(url, suffix, body)
    _record(ctx, kind, {"at": datetime.now(timezone.utc).isoformat(), "ok": err is None, "error": err, "sent": what})
    if err:
        log.warning("Watchdog %s ping failed: %s", kind, err)
    return err


def heartbeat(ctx: Context) -> None:
    """Alle 5 min aus dem Planer: Master lebt; meldet Fehler, wenn der Worker verstummt ist."""
    from sqlalchemy import select

    from .models import ScanJob
    from .scanrun import JOB_TIMEOUT
    from .worker_api import worker_last_seen

    age = worker_last_seen(ctx)["age_seconds"]
    with ctx.session_factory() as s:
        busy = s.scalar(select(ScanJob.id).where(ScanJob.status == "running").limit(1)) is not None
    # Während eines Laufs fragt der Worker bis zu ~25 min nichts an (Grype/OSV); ein hängender Job scheitert
    # nach JOB_TIMEOUT mit eigenem Alarm, danach gilt wieder WORKER_SILENT.
    if age is None or age > (JOB_TIMEOUT if busy else WORKER_SILENT):
        since = "never" if age is None else f"{age // 60} min ago"
        _send(ctx, "heartbeat", "/fail", f"lablantern master is up, but the scan worker was last seen {since}.", "fail")
    else:
        doing = ", busy with a scan job" if busy else ""
        _send(ctx, "heartbeat", "", f"lablantern master up, worker seen {age} s ago{doing}.", "success")


def _run_kind(trigger: str) -> str:
    """Kurzläufe pingen ihren eigenen Check (eigener Zeitplan in Healthchecks), alle anderen den täglichen."""
    return "short" if trigger == "short" else "run"


def run_started(ctx: Context, run_id: int, trigger: str) -> None:
    _send(ctx, _run_kind(trigger), "/start", f"Run #{run_id} started ({trigger}).", "start")


def run_finished(ctx: Context, run_id: int, status: str, canary_ok: bool, error: str = "",
                 trigger: str = "manual") -> None:
    """Erfolg nur bei vollständigem Lauf mit bestandenem Kanarien-Test; sonst /fail mit Grund."""
    kind = _run_kind(trigger)
    if status == "success" and canary_ok:
        _send(ctx, kind, "", f"Run #{run_id} finished successfully.", "success")
        return
    reasons = [f"status {status}"] + ([] if canary_ok else ["canary test failed"]) + ([error] if error else [])
    _send(ctx, kind, "/fail", f"Run #{run_id}: " + "; ".join(reasons), "fail")


def _masked(url: str | None) -> str | None:
    """Host und Pfad, das letzte Pfadstück (der geheime Teil: UUID, Push-Token) gekürzt."""
    if not url:
        return None
    from urllib.parse import urlsplit

    u = urlsplit(url)
    head, _, secret = u.path.rpartition("/")
    secret = f"{secret[:4]}…{secret[-4:]}" if len(secret) > 8 else "…"
    return f"{u.netloc}{head}/{secret}"


class WatchdogIn(BaseModel):
    heartbeat_url: str | None = Field(default=None, max_length=300)
    run_url: str | None = Field(default=None, max_length=300)
    short_url: str | None = Field(default=None, max_length=300)
    provider: Literal["healthchecks", "uptimekuma", "custom"] | None = None
    heartbeat_minutes: int | None = None
    clear: list[Literal["heartbeat", "run", "short"]] = []


def build_watchdog_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/watchdog", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            last = setting(s, STATUS_KEY, {})
        out = {kind: {**ctx.secrets.meta(name), "target": _masked(ctx.secrets.get(name)), "last": last.get(kind)}
               for kind, name in SECRETS.items()}
        return {**out, "config": get_config(ctx), "heartbeat_choices": list(HEARTBEAT_MINUTES)}

    @router.put("/watchdog")
    def write(body: WatchdogIn, found=Depends(guards.require_admin)):
        changes = []
        cfg = get_config(ctx)
        if body.provider:
            cfg["provider"] = body.provider
        if body.heartbeat_minutes is not None:
            if body.heartbeat_minutes not in HEARTBEAT_MINUTES:
                raise HTTPException(422, f"Heartbeat must be one of {', '.join(map(str, HEARTBEAT_MINUTES))} minutes")
            cfg["heartbeat_minutes"] = body.heartbeat_minutes
        examples = {"healthchecks": "https://watch.example.org/ping/<uuid>",
                    "uptimekuma": "https://kuma.example.org/api/push/<token>", "custom": "https://monitor.example.org/<path>"}
        for kind, url in (("heartbeat", body.heartbeat_url), ("run", body.run_url), ("short", body.short_url)):
            if url:
                url = url.strip()
                if not PROVIDERS[cfg["provider"]].match(url):
                    raise HTTPException(422, f"{kind}: expected a URL like {examples[cfg['provider']]}")
                ctx.secrets.set(SECRETS[kind], url)
                changes.append(f"{kind} set")
        for kind in body.clear:
            ctx.secrets.delete(SECRETS[kind])
            changes.append(f"{kind} removed")
        if body.provider or body.heartbeat_minutes is not None:
            changes.append(f"{cfg['provider']}, heartbeat every {cfg['heartbeat_minutes']} min")
        with ctx.session_factory() as s:
            put_setting(s, CONFIG_KEY, cfg)
            ctx.audit(s, found[0].username, "settings.watchdog", ", ".join(changes) or "no change")
            s.commit()
        if ctx.on_schedule_change:   # Herzschlag-Abstand im Planer übernehmen
            ctx.on_schedule_change()
        return {"ok": True}

    @router.post("/watchdog/test")
    def test(found=Depends(guards.require_admin)):
        """Je ein Erfolgs-Ping an beide Checks; danach zeigt Healthchecks sie als „up“."""
        out = {}
        for kind in SECRETS:
            if ctx.secrets.get(SECRETS[kind]):
                err = _send(ctx, kind, "", f"Test ping from LabLantern ({found[0].username}).", "test")
                out[kind] = {"ok": err is None, "error": err}
        if not out:
            raise HTTPException(409, "No ping URL configured yet")
        return out

    return router
