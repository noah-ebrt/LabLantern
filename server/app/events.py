"""Live-Updates für die Oberfläche per Server-Sent Events (GET /api/events).

Der Strom trägt nur Themennamen ("systems", "runs" …), nie Daten: Die Oberfläche lädt daraufhin über die
normale, angemeldete REST-API nach. Damit gelten dieselben Rechte wie überall, und im Strom steht nichts,
was ein Mitleser verwerten könnte. Die Sitzung wird beim Verbinden und danach laufend erneut geprüft;
Abmelden oder Ablauf beendet den Strom.

Welche Themen sich ändern, sammelt ein Hook an der Datenbanksitzung: Jeder Commit, der Systeme, Funde,
Läufe usw. anfasst, meldet das passende Thema. So muss kein Endpunkt selbst daran denken. Zeitabhängige
Zustände (verbunden/getrennt, „Initialisierung“ läuft ab) ändern sich ohne Schreibzugriff; dafür vergleicht
ein Wächter alle paar Sekunden einen Schnappschuss, solange jemand zuhört.
"""
import asyncio
import json
import logging
import threading
from typing import Callable, Iterable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import event, inspect
from sqlalchemy.orm import Session, sessionmaker

from .context import Context
from .guards import Guards
from .models import SessionRow

log = logging.getLogger("vulnwatch")

_PENDING = "vw_live_topics"
RESYNC = "*"   # Client lädt alles neu (z. B. wenn seine Warteschlange übergelaufen ist)

TOPICS_BY_TABLE = {
    "systems": "systems",
    "system_image_sboms": "systems",
    "pairings": "pairings",
    "agent_commands": "commands",
    "scan_runs": "runs",
    "scan_jobs": "runs",
    "system_scan_results": "runs",
    "findings": "findings",
    "early_warnings": "findings",
    "passkeys": "settings",
    "health_monitors": "health",
    "health_checks": "health",
    "health_events": "health",
    "health_tokens": "health",
    "health_webhooks": "health",
}
# Spalten, die sich ständig ändern, ohne dass die Anzeige es braucht (der Long-Poll schreibt jede Sekunde).
# Ob ein Agent dadurch verbunden/getrennt wirkt, meldet der Wächter.
IGNORED_COLUMNS = {"systems": {"last_contact"},
                   # jede Prüfung schreibt alle paar Sekunden Messwerte; gemeldet wird nur ein Zustandswechsel
                   "health_checks": {"fails", "last_checked", "last_ok", "latency_ms", "error"},
                   "health_tokens": {"last_used", "last_ip"}}
IGNORED_SETTINGS = {"worker.last_seen"}


def _topics_for(obj, changed: set[str] | None) -> set[str]:
    table = getattr(getattr(obj, "__table__", None), "name", None)
    if table == "settings":
        key = getattr(obj, "key", "")
        if key in IGNORED_SETTINGS:
            return set()
        return {"runs"} if key == "refresh.requested" else {"settings"}
    if changed is not None and changed <= IGNORED_COLUMNS.get(table, set()):
        return set()
    topic = TOPICS_BY_TABLE.get(table)
    if topic is None:
        return set()
    if table == "systems" and changed is None:
        return {"systems", "findings", "runs"}   # neu oder gelöscht: Funde/Ergebnisse hängen daran (CASCADE)
    return {topic}


class EventHub:
    """Verteilt Themen an alle offenen Ströme. `publish` ist aus jedem Thread aufrufbar."""

    def __init__(self, max_subscribers: int = 50, heartbeat: float = 20.0, watch_interval: float = 10.0):
        self.max_subscribers = max_subscribers
        self.heartbeat = heartbeat
        self.watch_interval = watch_interval
        # für den Wächter (in main.py gesetzt): {Thema: Wert}; ändert sich ein Wert, geht dieses Thema raus
        self.snapshot: Callable[[], dict[str, object]] | None = None
        self._lock = threading.Lock()
        self._subs: dict[asyncio.Queue, asyncio.AbstractEventLoop] = {}
        self._watcher: asyncio.Task | None = None

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def check_capacity(self) -> None:
        if self.subscriber_count >= self.max_subscribers:
            raise HTTPException(503, "Too many live connections")

    def subscribe(self) -> asyncio.Queue:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=64)
        with self._lock:
            if len(self._subs) >= self.max_subscribers:
                raise HTTPException(503, "Too many live connections")
            self._subs[q] = loop
            start = self.snapshot is not None and (self._watcher is None or self._watcher.done())
            if start:
                self._watcher = loop.create_task(self._watch())
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subs.pop(q, None)

    def publish(self, topics: Iterable[str]) -> None:
        topics = sorted(set(topics))
        if not topics:
            return
        with self._lock:
            subs = list(self._subs.items())
        for q, loop in subs:
            try:
                loop.call_soon_threadsafe(_offer, q, topics)
            except RuntimeError:   # Schleife schon beendet
                self.unsubscribe(q)

    async def _watch(self) -> None:
        last = None
        while self.subscriber_count:
            try:
                snap = await asyncio.to_thread(self.snapshot)
                if last is not None:
                    self.publish([topic for topic, value in snap.items() if last.get(topic) != value])
                last = snap
            except Exception:   # der Wächter darf nie den Strom mitreißen
                log.exception("live-update watcher failed")
            await asyncio.sleep(self.watch_interval)


def _offer(q: asyncio.Queue, topics: list[str]) -> None:
    try:
        q.put_nowait(topics)
    except asyncio.QueueFull:
        while not q.empty():
            q.get_nowait()
        q.put_nowait([RESYNC])


def install_db_hooks(session_factory: sessionmaker, hub: EventHub) -> None:
    """Sammelt bei jedem Flush die betroffenen Themen und veröffentlicht sie erst nach erfolgreichem Commit."""

    def pending(session: Session) -> set[str]:
        return session.info.setdefault(_PENDING, set())

    @event.listens_for(session_factory, "before_flush")
    def _collect(session, _flush_ctx, _instances):
        topics = pending(session)
        for obj in list(session.new) + list(session.deleted):
            topics |= _topics_for(obj, None)
        for obj in session.dirty:
            if not session.is_modified(obj):
                continue
            changed = {a.key for a in inspect(obj).attrs if a.history.has_changes()}
            topics |= _topics_for(obj, changed)

    @event.listens_for(session_factory, "do_orm_execute")
    def _bulk(state):
        # Massen-UPDATE/DELETE (z. B. Befehle verfallen lassen) laufen am Flush vorbei
        if not (state.is_update or state.is_delete):
            return None
        mapper = state.bind_mapper
        table = mapper.local_table.name if mapper is not None else None
        topic = TOPICS_BY_TABLE.get(table)
        if topic is None:
            return None
        result = state.invoke_statement()
        if getattr(result, "rowcount", 1):
            pending(state.session).add(topic)
        return result

    @event.listens_for(session_factory, "after_commit")
    def _publish(session):
        topics = session.info.pop(_PENDING, None)
        if topics:
            hub.publish(topics)

    @event.listens_for(session_factory, "after_rollback")
    def _discard(session):
        session.info.pop(_PENDING, None)


def _sse(name: str, data: dict) -> str:
    return f"event: {name}\ndata: {json.dumps(data)}\n\n"


def build_events_router(ctx: Context, guards: Guards, hub: EventHub) -> APIRouter:
    router = APIRouter()

    def session_valid(token_hash: str) -> bool:
        with ctx.session_factory() as s:
            row = s.get(SessionRow, token_hash)
            return row is not None and row.expires_at > ctx.clock()

    @router.get("/events")
    async def events(request: Request, found=Depends(guards.require_session)):
        token_hash = found[1].token_hash
        hub.check_capacity()

        async def stream():
            try:
                q = hub.subscribe()
            except HTTPException:   # zwischen Prüfung und Start voll geworden
                return
            try:
                yield "retry: 3000\n\n" + _sse("hello", {})
                while True:
                    try:
                        topics = await asyncio.wait_for(q.get(), timeout=hub.heartbeat)
                    except asyncio.TimeoutError:
                        topics = None
                    if await request.is_disconnected():
                        return
                    if not await asyncio.to_thread(session_valid, token_hash):
                        yield _sse("logout", {})
                        return
                    yield _sse("change", {"topics": topics}) if topics else ": ping\n\n"
            finally:
                hub.unsubscribe(q)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    return router
