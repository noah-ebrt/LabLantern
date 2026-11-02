"""Ein Stand für alle Abnehmer der Gesundheits-API: ein Änderungszähler (rev) und die Zustände, die dazu gehören.

Jeder Weg nach außen liest von hier: GET /api/health/states (mit ETag und wahlweise als Long-Poll mit ?since=&wait=)
und die Webhooks. rev steigt, sobald sich ein Zustand, ein Host (Name, kritisch, angelegt, entfernt) oder der Lauf der
Engine ändert. Er beginnt beim Start bei der Uhrzeit in Millisekunden und springt so auch über Neustarts nicht zurück;
Abnehmer vergleichen trotzdem nur auf Gleichheit.

Die Engine kann ihren eigenen Stillstand nicht melden (ok() kippt mit der Zeit, nicht durch ein Ereignis). Darum
prüft ein eigener Wächter-Thread alle WATCH Sekunden neu und schickt dabei auch fällige Heartbeats."""
import asyncio
import json
import logging
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from . import healthwebhooks as webhooks
from .models import HealthCheck, HealthMonitor

log = logging.getLogger("vulnwatch.health")
VERSION = 1
WATCH = 5.0
MAX_WAIT = 55.0
PRESENCE_KINDS = {"fritz_host"}   # nur Anwesenheit (Handy im WLAN), kein Dienst


def monitor_state(m: HealthMonitor, engine_ok: bool) -> str:
    if m.paused:
        return "paused"
    return m.state if engine_ok else "unknown"


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


@dataclass(frozen=True)
class Snapshot:
    rev: int
    ok: bool
    states: dict[str, str]
    hosts: dict[str, dict]


class HealthFeed:
    def __init__(self, engine, interval: float):
        self.engine = engine   # ok(), last_tick, hooks (Zustell-Pool) werden bei Bedarf gelesen; Tests tauschen sie
        self.ctx = engine.ctx
        self.interval = interval
        self.snap: Snapshot | None = None
        self._lock = threading.Lock()         # Schnappschuss und Wartende
        self._refreshing = threading.Lock()   # eine Auffrischung nach der anderen: kein älterer Stand überschreibt einen neueren
        self._waiters: set[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = set()
        self._beats: dict[int, float] = {}
        self._thread: threading.Thread | None = None

    # Wächter
    def start(self, stop: threading.Event) -> None:
        self._thread = threading.Thread(target=self._watch, args=(stop,), name="health-feed", daemon=True)
        self._thread.start()

    def _watch(self, stop: threading.Event) -> None:
        while not stop.wait(WATCH):
            try:
                self.watch_once()
            except Exception:
                log.exception("Health feed check failed")

    def watch_once(self) -> None:
        self.refresh()
        self._heartbeats()

    # Stand
    def _read(self) -> tuple[bool, dict, dict]:
        ok = self.engine.ok()
        with self.ctx.session_factory() as s:
            monitors = s.scalars(select(HealthMonitor).order_by(HealthMonitor.name)).all()
            kinds: dict[int, set[str]] = defaultdict(set)
            for monitor_id, kind in s.execute(select(HealthCheck.monitor_id, HealthCheck.kind)):
                kinds[monitor_id].add(kind)
            states = {m.slug: monitor_state(m, ok) for m in monitors}
            hosts = {m.slug: {"label": m.name, "critical": bool(m.critical),
                              "kind": "presence" if kinds[m.id] and kinds[m.id] <= PRESENCE_KINDS else "service"}
                     for m in monitors}
        return ok, states, hosts

    def current(self) -> Snapshot:
        return self.snap or self.refresh()

    def refresh(self) -> Snapshot:
        """Liest den Stand neu; hat er sich geändert, steigt rev, Wartende werden geweckt und Webhooks gehen raus."""
        with self._refreshing:
            ok, states, hosts = self._read()
            prev = self.snap
            if prev is not None and (prev.ok, prev.states, prev.hosts) == (ok, states, hosts):
                return prev
            snap = Snapshot(prev.rev + 1 if prev else int(self.ctx.clock() * 1000), ok, states, hosts)
            with self._lock:
                self.snap = snap
                waiters, self._waiters = self._waiters, set()
            for loop, event in waiters:
                loop.call_soon_threadsafe(event.set)
            if prev is not None:
                self._announce(prev, snap)
            return snap

    async def wait(self, since: str, timeout: float) -> None:
        """Kehrt zurück, sobald rev nicht mehr `since` ist, spätestens nach timeout Sekunden."""
        entry = (asyncio.get_running_loop(), asyncio.Event())
        with self._lock:
            if self.snap is None or str(self.snap.rev) != since:
                return
            self._waiters.add(entry)
        try:
            await asyncio.wait_for(entry[1].wait(), timeout)
        except TimeoutError:
            pass
        finally:
            with self._lock:
                self._waiters.discard(entry)

    def document(self, snap: Snapshot, hosts: bool = False, only: frozenset[str] = frozenset(),
                 event: str | None = None, changes: list[dict] | None = None) -> dict:
        """Gemeinsames Format für Abfrage, Long-Poll und Webhook. engine_ok und generated_at bleiben für ältere Geräte."""
        now = self.ctx.clock()

        def keep(slug: str) -> bool:
            return not only or slug in only

        doc = {"v": VERSION, "rev": snap.rev, "server_time": iso(now), "generated_at": int(now), "engine_ok": snap.ok,
               "engine": {"ok": snap.ok, "last_cycle_at": iso(self.engine.last_tick), "interval_s": self.interval},
               "states": {k: v for k, v in snap.states.items() if keep(k)},
               "critical": [k for k, h in snap.hosts.items() if h["critical"] and keep(k)]}
        if hosts:
            doc["hosts"] = {k: h for k, h in snap.hosts.items() if keep(k)}
        if event:
            doc = {"event": event, **doc, "changes": changes or []}
        return doc

    # Webhooks
    def _send(self, target: webhooks.Target, event: str, snap: Snapshot, changes: list[dict]) -> None:
        body = json.dumps(self.document(snap, True, target.only, event, changes), separators=(",", ":")).encode()
        submit = self.engine.hooks.submit
        submit(webhooks.deliver, self.ctx, target.id, event, body, str(uuid.uuid4()), 0, submit)

    def _announce(self, prev: Snapshot, snap: Snapshot) -> None:
        event = ("engine_up" if snap.ok else "engine_down") if prev.ok != snap.ok else "state_changed"
        at = iso(self.ctx.clock())
        changes = []
        for slug in sorted(prev.states.keys() | snap.states.keys()):
            before, after = prev.states.get(slug), snap.states.get(slug)
            if before != after:
                host = snap.hosts.get(slug) or prev.hosts[slug]
                changes.append({"slug": slug, "name": host["label"], "critical": host["critical"],
                                "from": before, "to": after, "at": at})
        if event == "state_changed" and not changes:
            return   # nur Name oder Einstufung geändert: rev steigt für Abfragen, Webhooks bleiben still
        for target in webhooks.targets(self.ctx):
            mine = [c for c in changes if not target.only or c["slug"] in target.only]
            if target.wants(event) and (mine or event != "state_changed"):
                self._send(target, event, snap, mine)

    def _heartbeats(self) -> None:
        now = self.ctx.clock()
        for target in webhooks.targets(self.ctx):
            if target.heartbeat_min <= 0:
                continue
            last = self._beats.setdefault(target.id, now)
            if now - last >= target.heartbeat_min * 60:
                self._beats[target.id] = now
                self._send(target, "heartbeat", self.current(), [])
