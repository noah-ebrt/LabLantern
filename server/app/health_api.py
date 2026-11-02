"""HTTP-Schnittstelle der Gesundheitsüberwachung.

Für die Oberfläche (angemeldet): Übersicht mit Verfügbarkeit, Verlauf je Monitor, Verwaltung (nur Admin).
Für andere Geräte (ESP-Statusleiste, Home Assistant, Skripte): /api/health/status und /api/health/states mit einem
Nur-Lese-Token (Bearer), dazu der Heartbeat-Eingang /api/health/beat/<token>. Steht die Engine, melden beide
"unknown" für alles, nie einen veralteten Zustand. /states kommt aus healthfeed.HealthFeed: mit ETag (rev) und als
Long-Poll (?since=<rev>&wait=<s>), so dass ein Gerät ohne offenen Port sofort von Wechseln erfährt."""
import json
import secrets
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from .auth import RateLimiter, sha256_hex
from .context import Context
from .fritzbox import tr064_url
from .guards import Guards, client_ip
from .health import (KIND_LABELS, HealthEngine, beat, check_label, effective_state, params_of, secret_name,
                     state_durations, unique_slug, uptime_of, worst_of)
from .healthfeed import MAX_WAIT, monitor_state
from .healthprobes import FRITZ_KINDS, HOST_RE, KINDS, PASSIVE, ProbeSpec, clean_params, run_probe
from .healthwebhooks import EVENTS, check_url, deliver, key_name, split_list, url_name
from .models import (HealthCheck, HealthEvent, HealthMonitor, HealthRollup, HealthSample, HealthToken, HealthWebhook, System,
                     setting)

MAX_CHECKS = 10
TOKEN_RATE = (60, 60.0)   # Abfragen je Token im Fenster (Sekunden): im Mittel eine je Sekunde, kurze Schübe erlaubt
RANGES = {"24h": (86400, 96), "7d": (7 * 86400, 84), "30d": (30 * 86400, 90), "90d": (90 * 86400, 90)}


class CheckIn(BaseModel):
    id: int | None = None
    kind: str = Field(max_length=20)
    params: dict = Field(default_factory=dict)
    interval_s: int = Field(default=30, ge=10, le=3600)
    retry_s: int = Field(default=10, ge=5, le=3600)
    timeout_s: float = Field(default=5.0, ge=1, le=30)
    fails_degraded: int = Field(default=2, ge=1, le=20)
    fails_down: int = Field(default=4, ge=1, le=50)
    paused: bool = False
    auth: str | None = Field(default=None, max_length=1000)   # HTTP-Authorization; None = unverändert, "" = entfernen


class MonitorIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    slug: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,39}$")
    host: str = Field(default="", max_length=253)
    critical: bool = True
    paused: bool = False
    checks: list[CheckIn] = Field(default_factory=list, max_length=MAX_CHECKS)


class PauseIn(BaseModel):
    paused: bool


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)


class WebhookIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    url: str = Field(default="", max_length=2000)   # beim Ändern leer: bleibt
    events: list[str] = Field(default_factory=list, max_length=len(EVENTS))   # leer: alle
    monitors: list[str] = Field(default_factory=list, max_length=500)          # Host-Schlüssel; leer: alle
    heartbeat_min: int = Field(default=0, ge=0, le=1440)


class TestIn(BaseModel):
    host: str = Field(default="", max_length=253)
    check: CheckIn


def fritz_available(ctx: Context) -> bool:
    with ctx.session_factory() as s:
        cfg = setting(s, "fritz.config")
    return bool(cfg) and bool(ctx.secrets.get("fritz.password"))


def _check_view(c: HealthCheck, now: float, has_auth: bool) -> dict:
    state, stale = effective_state(c, now)
    return {"id": c.id, "kind": c.kind, "label": check_label(c), "params": params_of(c), "interval_s": c.interval_s,
            "retry_s": c.retry_s, "timeout_s": c.timeout_s, "fails_degraded": c.fails_degraded,
            "fails_down": c.fails_down, "paused": c.paused, "state": state, "stale": stale,
            "latency_ms": c.latency_ms, "last_checked": c.last_checked, "last_ok": c.last_ok, "error": c.error,
            "since": c.state_since, "has_auth": has_auth, "heartbeat": c.beat_hash is not None}


def _primary_latency(checks: list[HealthCheck]) -> float | None:
    for c in checks:
        if c.latency_ms is not None and c.kind not in PASSIVE:
            return c.latency_ms
    return None


def public_view(m: HealthMonitor, checks: list[HealthCheck], now: float, engine_ok: bool, source: str = "manual") -> dict:
    """Was Abnehmer der API sehen: Zustand, Alter, Latenz, keine Einstellungen."""
    out_checks = []
    for c in checks:
        state, stale = effective_state(c, now)
        out_checks.append({"kind": c.kind, "label": check_label(c), "state": state if engine_ok else "unknown",
                           "stale": stale or not engine_ok, "latency_ms": c.latency_ms, "error": c.error,
                           "age_s": None if c.last_checked is None else round(now - c.last_checked, 1)})
    return {"slug": m.slug, "name": m.name, "host": m.host, "state": monitor_state(m, engine_ok),
            "critical": m.critical, "since": m.state_since, "warning": m.warning, "source": source,
            "latency_ms": _primary_latency(checks), "checks": out_checks}


def summary_of(states: list[str]) -> dict:
    out = {k: 0 for k in ("up", "degraded", "down", "unknown", "paused")}
    for st in states:
        out[st if st in out else "unknown"] += 1
    out["total"] = len(states)
    return out


def build_health_router(ctx: Context, guards: Guards, engine: HealthEngine) -> APIRouter:
    router = APIRouter(prefix="/health")
    limiter = RateLimiter(ctx.clock, max_failures=20, window=900)
    per_token = RateLimiter(ctx.clock, max_failures=TOKEN_RATE[0], window=TOKEN_RATE[1])   # zählt jede Abfrage
    feed = engine.feed

    def sources(s) -> dict[int, str]:
        """system_id -> "agent" oder "connector" (Gerät ohne Agent, z. B. TrueNAS)."""
        return {sid: "agent" if st == "active" else "connector" for sid, st in s.execute(select(System.id, System.status))}

    def source_of(m: HealthMonitor, src: dict[int, str]) -> str:
        return src.get(m.system_id, "agent") if m.system_id is not None else "manual"

    def load(s):
        monitors = s.scalars(select(HealthMonitor).order_by(HealthMonitor.name)).all()
        checks: dict[int, list[HealthCheck]] = {}
        for c in s.scalars(select(HealthCheck).order_by(HealthCheck.id)).all():
            checks.setdefault(c.monitor_id, []).append(c)
        return monitors, checks

    def consumer(request: Request, authorization: str | None = Header(None)):
        """Lesender Zugriff: Nur-Lese-Token der Gesundheits-API oder eine angemeldete Sitzung."""
        given = (authorization or "").removeprefix("Bearer ").strip()
        if given:
            ip = client_ip(request)
            if limiter.blocked(ip):
                raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": str(limiter.retry_after(ip))})
            with ctx.session_factory() as s:
                row = s.scalars(select(HealthToken).where(HealthToken.token_hash == sha256_hex(given))).first()
                if row is not None:
                    key = f"token:{row.id}"
                    if per_token.blocked(key):
                        raise HTTPException(429, "Too many requests for this token, use ?since=&wait= instead of polling",
                                            headers={"Retry-After": str(per_token.retry_after(key))})
                    per_token.fail(key)
                    if row.last_used is None or ctx.clock() - row.last_used > 60 or row.last_ip != ip:
                        row.last_used, row.last_ip = ctx.clock(), ip
                        s.commit()
                    return row.name
            limiter.fail(ip)
            raise HTTPException(401, "Invalid token", headers={"WWW-Authenticate": "Bearer"})
        if guards.current_session(request) is not None:
            return "session"
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})

    def status_doc(s) -> dict:
        now = ctx.clock()
        engine_ok = engine.ok()
        monitors, checks = load(s)
        src = sources(s)
        views = [public_view(m, checks.get(m.id, []), now, engine_ok, source_of(m, src)) for m in monitors]
        return {"generated_at": now, "rev": feed.current().rev, "engine": {"ok": engine_ok, "last_tick": engine.last_tick or None},
                "summary": summary_of([v["state"] for v in views]),
                "critical_down": [v["slug"] for v in views if v["critical"] and v["state"] == "down"],
                "monitors": views}

    # --- Für Abnehmer (Token oder Sitzung) ---

    async def changed(known: str | None, wait: float):
        """Long-Poll für /states und /status: Stand frisch lesen, bei since == rev bis zu wait Sekunden auf einen
        Wechsel warten. Zurück der Stand und ob er noch `known` ist (dann 304)."""
        snap = await run_in_threadpool(feed.refresh)
        if known is not None and wait > 0 and str(snap.rev) == known:
            await feed.wait(known, min(wait, MAX_WAIT))
            snap = feed.current()
        return snap, known is not None and str(snap.rev) == known

    @router.get("/status")
    async def status(since: str | None = None, wait: float = Query(0, ge=0), _who=Depends(consumer)):
        """Alles mit Prüfungen, Latenz und Alter. since/wait wie bei /states: 304 heißt kein Zustand hat sich
        geändert (Latenzen und Alter ändern sich laufend und wecken nicht). rev steht auch im Header X-Vulnwatch-Rev."""
        snap, same = await changed(since, wait)
        head = {"X-Vulnwatch-Rev": str(snap.rev), "Cache-Control": "no-cache"}
        if same:
            return Response(status_code=304, headers=head)

        def build():
            with ctx.session_factory() as s:
                return status_doc(s)

        return JSONResponse(await run_in_threadpool(build), headers=head)

    @router.get("/status/{slug}")
    def status_one(slug: str, _who=Depends(consumer)):
        now = ctx.clock()
        with ctx.session_factory() as s:
            m = s.scalars(select(HealthMonitor).where(HealthMonitor.slug == slug)).first()
            if m is None:
                raise HTTPException(404, "Unknown monitor")
            checks = s.scalars(select(HealthCheck).where(HealthCheck.monitor_id == m.id).order_by(HealthCheck.id)).all()
            return {"generated_at": now, "engine": {"ok": engine.ok()},
                    **public_view(m, list(checks), now, engine.ok(), source_of(m, sources(s)))}

    @router.get("/states")
    async def states(request: Request, since: str | None = None, wait: float = Query(0, ge=0), hosts: bool = False,
                     _who=Depends(consumer)):
        """Kompakt für Mikrocontroller: {slug: Zustand}. Ohne Parameter wie immer eine Antwort mit dem aktuellen Stand.
        since=<rev>: 304, solange sich nichts geändert hat; dazu wait=<s>: bis zu MAX_WAIT Sekunden auf einen Wechsel
        warten (Long-Poll). If-None-Match mit dem ETag wirkt wie since. hosts=1: Name, kritisch und Art je Host."""
        known = since if since is not None else (request.headers.get("if-none-match") or "").strip('W/"') or None
        snap, same = await changed(known, wait)
        head = {"ETag": f'"{snap.rev}"', "X-Vulnwatch-Rev": str(snap.rev), "Cache-Control": "no-cache"}
        if same:
            return Response(status_code=304, headers=head)
        return JSONResponse(feed.document(snap, hosts=hosts), headers=head)

    def _beat(token: str, state: str | None, request: Request):
        ip = client_ip(request)
        if limiter.blocked(ip):
            raise HTTPException(429, "Too many failed attempts")
        with ctx.session_factory() as s:
            c = s.scalars(select(HealthCheck).where(HealthCheck.beat_hash == sha256_hex(token))).first()
            if c is None:
                limiter.fail(ip)
                raise HTTPException(404, "Unknown heartbeat")
            down = state == "down"
            beat(s, c, ctx.clock(), down)
            s.commit()
        if down:
            engine.poke(c.id)
        return Response("bye\n" if down else "ok\n", media_type="text/plain")

    @router.get("/beat/{token}")
    def beat_get(token: str, request: Request, state: str | None = None):
        return _beat(token, state, request)

    @router.post("/beat/{token}")
    def beat_post(token: str, request: Request, state: str | None = None):
        return _beat(token, state, request)

    # --- Oberfläche ---

    @router.get("/overview", dependencies=[Depends(guards.require_session)])
    def overview():
        now = ctx.clock()
        engine_ok = engine.ok()
        with ctx.session_factory() as s:
            monitors, checks = load(s)
            src = sources(s)
            auth_ids = {c.id for cs in checks.values() for c in cs if c.kind == "http" and ctx.secrets.meta(secret_name(c.id))}
            out = []
            for m in monitors:
                segs = state_durations(s, m.id, now - 86400, now, 48)
                day = {k: sum(d[k] for d in segs) for k in segs[0]}
                week = state_durations(s, m.id, now - 7 * 86400, now)[0]
                month = state_durations(s, m.id, now - 30 * 86400, now)[0]
                cs = checks.get(m.id, [])
                out.append({
                    "id": m.id, "name": m.name, "slug": m.slug, "host": m.host, "critical": m.critical,
                    "paused": m.paused, "auto": m.system_id is not None, "system_id": m.system_id,
                    "source": source_of(m, src),
                    "state": monitor_state(m, engine_ok), "since": m.state_since, "warning": m.warning,
                    "latency_ms": _primary_latency(cs),
                    "uptime": {"24h": uptime_of(day), "7d": uptime_of(week), "30d": uptime_of(month)},
                    "segments": [{"state": worst_of(d), "uptime": uptime_of(d)} for d in segs],
                    "checks": [_check_view(c, now, c.id in auth_ids) for c in cs],
                })
            incidents = s.scalars(select(HealthEvent).where(HealthEvent.state == "down")
                                  .order_by(HealthEvent.ts.desc()).limit(20)).all()
            names = {m.id: m.name for m in monitors}
            return {"engine": {"ok": engine_ok, "last_tick": engine.last_tick or None, "started": engine.started},
                    "summary": summary_of([o["state"] for o in out]), "monitors": out,
                    "incidents": [{"monitor_id": e.monitor_id, "name": names.get(e.monitor_id, "?"), "ts": e.ts,
                                   "detail": e.detail} for e in incidents],
                    "fritz": fritz_available(ctx)}

    @router.get("/monitors/{monitor_id}/history", dependencies=[Depends(guards.require_session)])
    def history(monitor_id: int, period: str = Query("24h", alias="range")):
        if period not in RANGES:
            raise HTTPException(422, "range must be 24h, 7d, 30d or 90d")
        span, n = RANGES[period]
        now = ctx.clock()
        start = now - span
        width = span / n
        with ctx.session_factory() as s:
            m = s.get(HealthMonitor, monitor_id)
            if m is None:
                raise HTTPException(404, "Unknown monitor")
            segs = state_durations(s, m.id, start, now, n)
            total = {k: sum(d[k] for d in segs) for k in segs[0]}
            checks = s.scalars(select(HealthCheck).where(HealthCheck.monitor_id == m.id).order_by(HealthCheck.id)).all()
            series = []
            for c in checks:
                buckets = [{"n": 0, "ok": 0, "lat_sum": 0.0, "lat_n": 0, "lat_max": None} for _ in range(n)]
                if period == "24h":
                    rows = s.execute(select(HealthSample.ts, HealthSample.ok, HealthSample.latency_ms)
                                     .where(HealthSample.check_id == c.id, HealthSample.ts >= start)).all()
                    for ts, ok, lat in rows:
                        b = buckets[min(n - 1, int((ts - start) // width))]
                        b["n"] += 1
                        b["ok"] += 1 if ok else 0
                        if lat is not None:
                            b["lat_sum"] += lat
                            b["lat_n"] += 1
                            b["lat_max"] = lat if b["lat_max"] is None else max(b["lat_max"], lat)
                else:
                    rows = s.scalars(select(HealthRollup).where(HealthRollup.check_id == c.id,
                                                                HealthRollup.hour >= start - 3600)).all()
                    for r in rows:
                        if r.hour + 3600 <= start:
                            continue
                        i = min(n - 1, int((max(r.hour, start) - start) // width))   # laufende Stunde zählt mit
                        b = buckets[i]
                        b["n"] += r.total
                        b["ok"] += r.ok
                        b["lat_sum"] += r.lat_sum
                        b["lat_n"] += r.lat_n
                        if r.lat_n:
                            b["lat_max"] = r.lat_max if b["lat_max"] is None else max(b["lat_max"], r.lat_max)
                series.append({
                    "id": c.id, "kind": c.kind, "label": check_label(c),
                    "latency": [round(b["lat_sum"] / b["lat_n"], 1) if b["lat_n"] else None for b in buckets],
                    "latency_max": [b["lat_max"] for b in buckets],
                    "uptime": [round(b["ok"] / b["n"] * 100, 2) if b["n"] else None for b in buckets],
                    "samples": sum(b["n"] for b in buckets),
                    "ok": sum(b["ok"] for b in buckets),
                })
            events = s.scalars(select(HealthEvent).where(HealthEvent.monitor_id == m.id, HealthEvent.ts >= start)
                               .order_by(HealthEvent.ts.desc()).limit(100)).all()
            return {
                "range": period, "start": start, "end": now, "bucket_s": width,
                "uptime": uptime_of(total), "durations": total,
                "segments": [{"state": worst_of(d), "uptime": uptime_of(d)} for d in segs],
                "checks": series,
                "events": [{"ts": e.ts, "state": e.state, "prev": e.prev, "detail": e.detail} for e in events],
            }

    @router.get("/options", dependencies=[Depends(guards.require_session)])
    def options():
        fritz = fritz_available(ctx)
        return {"kinds": [{"kind": k, "label": KIND_LABELS[k],
                           "available": fritz if k in FRITZ_KINDS else k != "agent",
                           "reason": "Set up the FRITZ!Box connector under Settings → Integrations"
                           if k in FRITZ_KINDS and not fritz else ("Added automatically on agent hosts" if k == "agent" else "")}
                          for k in KINDS],
                "fritz": fritz}

    # --- Verwaltung (Admin) ---

    def _validated(body: MonitorIn, auto: bool) -> list[tuple[CheckIn, dict]]:
        host = body.host.strip()
        if host and not HOST_RE.match(host):
            raise HTTPException(422, "Host must be an IP address or host name")
        out = []
        for c in body.checks:
            if c.kind not in KINDS:
                raise HTTPException(422, f"Unknown check type: {c.kind}")
            if c.kind == "agent" and not auto:
                raise HTTPException(422, "Agent checks exist only on agent hosts")
            if c.kind in FRITZ_KINDS and not fritz_available(ctx):
                raise HTTPException(422, "FRITZ!Box checks need the FRITZ!Box connector (Settings → Integrations)")
            if c.fails_down < c.fails_degraded:
                raise HTTPException(422, "Failures to down must be at least the failures to degraded")
            try:
                params = clean_params(c.kind, c.params)
            except (ValueError, TypeError) as e:
                raise HTTPException(422, str(e)) from None
            needs_host = c.kind not in PASSIVE and c.kind != "fritz_wan"
            if needs_host and not (params.get("target") or host):
                raise HTTPException(422, f"{KIND_LABELS[c.kind]} needs a host or its own target")
            out.append((c, params))
        return out

    def _store_checks(s, m: HealthMonitor, items: list[tuple[CheckIn, dict]], tokens: dict) -> list:
        """Prüfungen anlegen/ändern/entfernen. Liefert Änderungen am Geheimnisspeicher für nach dem Commit
        (der Speicher schreibt mit eigener Sitzung; vorher hielte diese Transaktion die Datenbank gesperrt)."""
        secret_ops: list[tuple[str, str | None]] = []
        existing = {c.id: c for c in s.scalars(select(HealthCheck).where(HealthCheck.monitor_id == m.id))}
        keep = set()
        for c_in, params in items:
            c = existing.get(c_in.id) if c_in.id else None
            if c is None or c.kind != c_in.kind:
                c = HealthCheck(monitor_id=m.id, kind=c_in.kind)
                s.add(c)
            c.params = json.dumps(params)
            for f in ("interval_s", "retry_s", "timeout_s", "fails_degraded", "fails_down", "paused"):
                setattr(c, f, getattr(c_in, f))
            s.flush()
            keep.add(c.id)
            if c.kind == "heartbeat" and c.beat_hash is None:
                token = secrets.token_urlsafe(24)
                c.beat_hash = sha256_hex(token)
                tokens[str(c.id)] = token
            if c.kind == "http" and c_in.auth is not None:
                secret_ops.append((secret_name(c.id), c_in.auth or None))
            engine.poke(c.id)
        for cid, c in existing.items():
            if cid in keep:
                continue
            if c.kind == "agent" and m.system_id is not None:
                continue   # die Agentenprüfung eines Agenten-Hosts bleibt immer
            secret_ops.append((secret_name(cid), None))
            s.delete(c)
        return secret_ops

    def _apply_secrets(ops: list) -> None:
        for name, value in ops:
            if value:
                ctx.secrets.set(name, value)
            else:
                ctx.secrets.delete(name)

    @router.post("/monitors")
    def create(body: MonitorIn, found=Depends(guards.require_admin)):
        items = _validated(body, auto=False)
        tokens: dict[str, str] = {}
        with ctx.session_factory() as s:
            if body.slug and s.scalars(select(HealthMonitor).where(HealthMonitor.slug == body.slug)).first():
                raise HTTPException(409, "This API key is already used by another monitor")
            now = ctx.clock()
            m = HealthMonitor(name=body.name.strip(), slug=body.slug or unique_slug(s, body.name), host=body.host.strip(),
                              critical=body.critical, paused=body.paused, created_at=now, state="unknown", state_since=now)
            s.add(m)
            s.flush()
            ops = _store_checks(s, m, items, tokens)
            ctx.audit(s, found[0].username, "health.monitor.created", m.name)
            s.commit()
        _apply_secrets(ops)
        feed.refresh()
        return {"id": m.id, "slug": m.slug, "heartbeat_tokens": tokens}

    @router.put("/monitors/{monitor_id}")
    def update(monitor_id: int, body: MonitorIn, found=Depends(guards.require_admin)):
        tokens: dict[str, str] = {}
        with ctx.session_factory() as s:
            m = s.get(HealthMonitor, monitor_id)
            if m is None:
                raise HTTPException(404, "Unknown monitor")
            items = _validated(body, auto=m.system_id is not None)
            if body.slug and body.slug != m.slug:
                if s.scalars(select(HealthMonitor).where(HealthMonitor.slug == body.slug)).first():
                    raise HTTPException(409, "This API key is already used by another monitor")
                m.slug = body.slug
            if m.system_id is None:   # Hosts aus „Systems“ tragen den Namen ihres Systems
                m.name = body.name.strip()
            m.host, m.critical, m.paused = body.host.strip(), body.critical, body.paused
            ops = _store_checks(s, m, items, tokens)
            ctx.audit(s, found[0].username, "health.monitor.updated", m.name)
            s.commit()
        _apply_secrets(ops)
        feed.refresh()
        return {"id": m.id, "slug": m.slug, "heartbeat_tokens": tokens}

    @router.post("/monitors/{monitor_id}/pause")
    def pause(monitor_id: int, body: PauseIn, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            m = s.get(HealthMonitor, monitor_id)
            if m is None:
                raise HTTPException(404, "Unknown monitor")
            m.paused = body.paused
            if not body.paused:
                m.state, m.state_since = "unknown", ctx.clock()
            s.add(HealthEvent(monitor_id=m.id, ts=ctx.clock(), state="paused" if body.paused else "unknown",
                              prev=m.state, detail="paused" if body.paused else "resumed"))
            ctx.audit(s, found[0].username, "health.monitor.paused" if body.paused else "health.monitor.resumed", m.name)
            s.commit()
        feed.refresh()   # Pausieren ist ein Zustandswechsel: Webhooks und Long-Poll erfahren es sofort
        engine.poke()
        return {"ok": True}

    @router.delete("/monitors/{monitor_id}")
    def remove(monitor_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            m = s.get(HealthMonitor, monitor_id)
            if m is None:
                raise HTTPException(404, "Unknown monitor")
            if m.system_id is not None:
                raise HTTPException(409, "Hosts from Systems are monitored automatically; pause it instead")
            ops = [(secret_name(c.id), None) for c in s.scalars(select(HealthCheck).where(HealthCheck.monitor_id == m.id))]
            s.delete(m)
            ctx.audit(s, found[0].username, "health.monitor.deleted", m.name)
            s.commit()
        _apply_secrets(ops)
        feed.refresh()
        return {"ok": True}

    @router.post("/checks/{check_id}/heartbeat-token")
    def new_beat_token(check_id: int, found=Depends(guards.require_admin)):
        """Neue Heartbeat-Adresse; die alte gilt danach nicht mehr. Das Token gibt es nur jetzt zu sehen."""
        with ctx.session_factory() as s:
            c = s.get(HealthCheck, check_id)
            if c is None or c.kind != "heartbeat":
                raise HTTPException(404, "Unknown heartbeat check")
            token = secrets.token_urlsafe(24)
            c.beat_hash = sha256_hex(token)
            ctx.audit(s, found[0].username, "health.heartbeat.token", str(check_id))
            s.commit()
        return {"token": token}

    @router.post("/test")
    def test(body: TestIn, _found=Depends(guards.require_admin)):
        """Prüfung einmal ausführen, ohne zu speichern (Knopf „Test“ im Formular)."""
        c = body.check
        if c.kind not in KINDS or c.kind in PASSIVE:
            raise HTTPException(422, "Only active checks can be tested")
        try:
            params = clean_params(c.kind, c.params)
        except (ValueError, TypeError) as e:
            raise HTTPException(422, str(e)) from None
        host = params.get("target") or body.host.strip()
        if c.kind != "fritz_wan" and (not host or not HOST_RE.match(host)):
            raise HTTPException(422, "Host must be an IP address or host name")
        fritz = None
        if c.kind in FRITZ_KINDS:
            with ctx.session_factory() as s:
                cfg = setting(s, "fritz.config")
            if not cfg or not ctx.secrets.get("fritz.password"):
                raise HTTPException(422, "FRITZ!Box connector not set up")
            fritz = {"url": tr064_url(cfg["url"]), "user": cfg["user"], "password": ctx.secrets.get("fritz.password")}
        spec = ProbeSpec(kind=c.kind, host=host or "fritz.box", params=params, timeout=c.timeout_s,
                         auth=c.auth or None, fritz=fritz)
        t0 = time.monotonic()
        r = run_probe(spec)
        return {"ok": r.ok and not r.inconclusive, "warn": r.warn, "error": r.error, "latency_ms": r.latency_ms,
                "inconclusive": r.inconclusive, "took_ms": round((time.monotonic() - t0) * 1000)}

    # --- Nur-Lese-Token für andere Geräte ---

    @router.get("/tokens", dependencies=[Depends(guards.require_session)])
    def tokens():
        with ctx.session_factory() as s:
            rows = s.scalars(select(HealthToken).order_by(HealthToken.id)).all()
            return [{"id": t.id, "name": t.name, "created_at": t.created_at, "last_used": t.last_used, "last_ip": t.last_ip}
                    for t in rows]

    @router.post("/tokens")
    def new_token(body: TokenIn, found=Depends(guards.require_admin)):
        token = "vwh_" + secrets.token_urlsafe(32)
        with ctx.session_factory() as s:
            row = HealthToken(name=body.name.strip(), token_hash=sha256_hex(token), created_at=ctx.clock())
            s.add(row)
            ctx.audit(s, found[0].username, "health.token.created", row.name)
            s.commit()
            return {"id": row.id, "token": token}

    @router.delete("/tokens/{token_id}")
    def delete_token(token_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            row = s.get(HealthToken, token_id)
            if row is None:
                raise HTTPException(404, "Unknown token")
            s.delete(row)
            ctx.audit(s, found[0].username, "health.token.deleted", row.name)
            s.commit()
        return {"ok": True}

    # --- Webhooks: Push bei Zustandswechseln ---

    @router.get("/webhooks", dependencies=[Depends(guards.require_session)])
    def webhooks():
        with ctx.session_factory() as s:
            rows = s.scalars(select(HealthWebhook).order_by(HealthWebhook.id)).all()
            return [{"id": w.id, "name": w.name, "target": w.target, "created_at": w.created_at,
                     "events": split_list(w.events), "monitors": split_list(w.monitors), "heartbeat_min": w.heartbeat_min,
                     "last_sent": w.last_sent, "last_event": w.last_event, "last_error": w.last_error} for w in rows]

    def _filters(row: HealthWebhook, body: WebhookIn) -> None:
        unknown = set(body.events) - set(EVENTS)
        if unknown:
            raise HTTPException(422, f"Unknown event {sorted(unknown)[0]}; choose from {', '.join(EVENTS)}")
        row.name = body.name.strip()
        row.events = ",".join(e for e in EVENTS if e in body.events and len(body.events) < len(EVENTS))
        row.monitors = ",".join(sorted({m.strip() for m in body.monitors if m.strip()}))
        row.heartbeat_min = body.heartbeat_min

    @router.post("/webhooks")
    def new_webhook(body: WebhookIn, found=Depends(guards.require_admin)):
        try:
            target = check_url(body.url)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        key = "vwhs_" + secrets.token_urlsafe(32)
        with ctx.session_factory() as s:
            row = HealthWebhook(target=target, created_at=ctx.clock())
            _filters(row, body)
            s.add(row)
            ctx.audit(s, found[0].username, "health.webhook.created", f"{row.name} → {target}")
            s.commit()
            webhook_id = row.id
        ctx.secrets.set(url_name(webhook_id), body.url.strip())
        ctx.secrets.set(key_name(webhook_id), key)
        return {"id": webhook_id, "secret": key}

    @router.put("/webhooks/{webhook_id}")
    def update_webhook(webhook_id: int, body: WebhookIn, found=Depends(guards.require_admin)):
        target = None
        if body.url.strip():
            try:
                target = check_url(body.url)
            except ValueError as e:
                raise HTTPException(422, str(e)) from None
        with ctx.session_factory() as s:
            row = s.get(HealthWebhook, webhook_id)
            if row is None:
                raise HTTPException(404, "Unknown webhook")
            _filters(row, body)
            if target:
                row.target = target
            ctx.audit(s, found[0].username, "health.webhook.updated", row.name)
            s.commit()
        if target:
            ctx.secrets.set(url_name(webhook_id), body.url.strip())
        return {"ok": True}

    @router.post("/webhooks/{webhook_id}/test")
    def test_webhook(webhook_id: int, _found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            row = s.get(HealthWebhook, webhook_id)
            if row is None:
                raise HTTPException(404, "Unknown webhook")
            only = frozenset(split_list(row.monitors))
        body = json.dumps(feed.document(feed.current(), True, only, "test", []), separators=(",", ":")).encode()
        error = deliver(ctx, webhook_id, "test", body)
        return {"ok": not error, "error": error}

    @router.delete("/webhooks/{webhook_id}")
    def delete_webhook(webhook_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            row = s.get(HealthWebhook, webhook_id)
            if row is None:
                raise HTTPException(404, "Unknown webhook")
            s.delete(row)
            ctx.audit(s, found[0].username, "health.webhook.deleted", row.name)
            s.commit()
        ctx.secrets.delete(url_name(webhook_id))
        ctx.secrets.delete(key_name(webhook_id))
        return {"ok": True}

    return router

