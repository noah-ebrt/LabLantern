"""Gesundheitsüberwachung: Monitore (Hosts/Dienste) mit Prüfungen, Zustandsmaschine, Verlauf und Alarm.

Ablauf: Die HealthEngine läuft als eigener Thread im Server. Alle TICK Sekunden schickt sie fällige aktive Prüfungen
an einen Thread-Pool, übernimmt fertige Ergebnisse in einer Transaktion, wertet die passiven Prüfungen (Agent,
Heartbeat) aus und fasst je Monitor einen Zustand zusammen. Zustandswechsel landen als HealthEvent im Verlauf und
lösen für kritische Monitore einen Alarm aus.

Zustände je Prüfung (wie die Status-LED): ein Erfolg -> up; `fails_degraded` Fehlschläge in Folge -> degraded;
`fails_down` -> down. Nach einem Fehlschlag wird im kürzeren `retry_s`-Takt nachgeprüft. Nicht entscheidbare
Ergebnisse (FRITZ!Box selbst weg) zählen nicht als Ausfall, sondern machen die Prüfung "unknown".

Verlässlichkeit für Abnehmer der API: Jede Prüfung trägt ihr Alter. Ist ein Ergebnis zu alt oder steht die Engine,
meldet die API "unknown" statt eines veralteten "up" (siehe effective_state, engine_ok)."""
import json
import logging
import re
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from urllib.parse import urlsplit

from sqlalchemy import delete, select

from .context import Context
from .fritzbox import tr064_url
from .healthprobes import ACTIVE, FRITZ_KINDS, ProbeResult, ProbeSpec, clean_params, run_probe
from .models import HealthCheck, HealthEvent, HealthMonitor, HealthRollup, HealthSample, System, setting

log = logging.getLogger("vulnwatch.health")

TICK = 2.0
WORKERS = 16
AGENT_FRESH = 75.0         # letzter Long-Poll jünger als das: Agent meldet sich
AGENT_GRACE = 150.0        # nach dem Start: Agenten erst wieder verbinden lassen, bevor sie als stumm gelten
ENGINE_STALE = 60.0        # so lange ohne Tick: Engine gilt als stehend, die API meldet alles "unknown"
SAMPLE_DAYS = 7
ROLLUP_DAYS = 400
OUTAGE_SHARE = 0.75        # so viele Monitore gleichzeitig down: ein Alarm "Netzausfall" statt vieler
OUTAGE_MIN = 3
ANNOUNCED = "host announced shutdown"
STATES = ("up", "degraded", "down", "unknown")

KIND_LABELS = {
    "ping": "Ping", "tcp": "TCP port", "http": "HTTP(S)", "tls": "TLS certificate", "dns": "DNS",
    "fritz_host": "FRITZ!Box device", "fritz_wan": "Internet (FRITZ!Box)", "heartbeat": "Heartbeat", "agent": "Agent",
}


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return (s or "host")[:40].strip("-") or "host"


def unique_slug(s, base: str, exclude_id: int | None = None) -> str:
    base = slugify(base)
    taken = {r for r in s.scalars(select(HealthMonitor.slug).where(HealthMonitor.id != (exclude_id or 0)))}
    slug, n = base, 2
    while slug in taken:
        slug = f"{base[:36]}-{n}"
        n += 1
    return slug


def params_of(c: HealthCheck) -> dict:
    try:
        return json.loads(c.params or "{}")
    except ValueError:
        return {}


def check_label(c: HealthCheck) -> str:
    p = params_of(c)
    label = KIND_LABELS.get(c.kind, c.kind)
    if c.kind in ("tcp", "dns", "tls"):
        label += f" {p.get('port')}"
    elif c.kind == "http":
        label = f"{p.get('scheme', 'http').upper()} {p.get('path', '/')}"
    if p.get("target"):
        label += f" · {p['target']}"
    return label


def secret_name(check_id: int) -> str:
    return f"health.check.{check_id}.auth"


# --- Zustände ---

def apply_result(c: HealthCheck, r: ProbeResult, now: float) -> bool:
    """Ergebnis in den Zustand der Prüfung übernehmen. True, wenn sich der Zustand geändert hat."""
    before = c.state
    c.last_checked = now
    c.latency_ms = r.latency_ms
    if r.inconclusive:
        c.state, c.error = "unknown", r.error
    elif r.ok:
        c.fails, c.last_ok = 0, now
        c.state, c.error = ("degraded", r.warn) if r.warn else ("up", "")
    else:
        c.fails += 1
        c.error = r.error or "failed"
        if c.fails >= c.fails_down:
            c.state = "down"
        elif c.fails >= c.fails_degraded:
            c.state = "degraded"
        # vorher: einzelne Aussetzer lassen den Zustand stehen (wird im retry-Takt nachgeprüft)
    if c.state != before:
        c.state_since = now
        return True
    return False


def stale_after(c: HealthCheck) -> float:
    """Ab diesem Alter gilt das letzte Ergebnis als veraltet."""
    return max(3 * c.interval_s, c.interval_s + c.timeout_s + 60)


def effective_state(c: HealthCheck, now: float) -> tuple[str, bool]:
    """(Zustand, veraltet) für Anzeige und API."""
    if c.paused:
        return "paused", False
    if c.last_checked is None:
        return "unknown", False
    if now - c.last_checked > stale_after(c):
        return "unknown", True
    return c.state, False


def aggregate(checks: list[tuple[str, str]]) -> tuple[str, str]:
    """Monitor-Zustand aus [(Art, Zustand)] der aktiven Prüfungen -> (Zustand, Warnung).

    Der Agent ist eine Stimme unter mehreren: schweigt er, während die Prüfungen von außen klappen, bleibt der Host
    "up" mit Warnung (Agent abgestürzt, im Update). Fallen alle Prüfungen von außen aus, der Agent meldet sich aber,
    ist der Host "degraded" (Netz- oder Firewall-Problem), nicht "down"."""
    agent = next((st for k, st in checks if k == "agent"), None)
    outside = [st for k, st in checks if k != "agent" and st != "paused"]
    known = [st for st in outside if st != "unknown"]
    if not known:
        if agent is None or agent == "unknown":
            return "unknown", ""
        return agent, "" if agent == "up" else "Agent not reporting"
    warning = ""
    if all(st == "down" for st in known):
        if agent == "up":
            return "degraded", "Agent still reports: likely a network or firewall problem"
        state = "down"
    elif any(st in ("down", "degraded") for st in known):
        state = "degraded"
    else:
        state = "up"
    if agent in ("down", "degraded") and state != "down":
        warning = "Agent not reporting"
    return state, warning


# --- Systeme automatisch überwachen ---

AUTO_STATUSES = ("active", "connector")   # Agenten und Geräte ohne Agent (TrueNAS, Home Assistant …)


def default_checks(sys: System, connector: dict | None) -> list[tuple[str, dict]]:
    """Grundprüfungen je System: Agent + Ping für Agenten; Ping + die Adresse, über die vulnwatch das Gerät
    ausliest, für Connector-Systeme. Gilt für jede Connector-Art, auch künftige, solange sie eine URL hat."""
    out: list[tuple[str, dict]] = []
    if sys.status == "active":
        out.append(("agent", {}))
    if sys.ip:
        out.append(("ping", {"target": ""}))
    url = (connector or {}).get("url") or ""
    if sys.status == "connector" and url:
        u = urlsplit(url)
        if u.scheme in ("http", "https") and u.hostname:
            target = "" if u.hostname == sys.ip else u.hostname
            out.append(("http", clean_params("http", {
                "target": target, "scheme": u.scheme, "port": u.port or (443 if u.scheme == "https" else 80),
                "path": u.path or "/", "expect": "2xx", "follow_redirects": True,
                # vulnwatch prüft das Zertifikat solcher Geräte per Fingerabdruck (meist selbst signiert)
                "verify_tls": not connector.get("fingerprint")})))
    return out


def _has(checks: list[HealthCheck], kind: str, params: dict) -> bool:
    for c in checks:
        p = params_of(c)
        if c.kind == kind and p.get("port") == params.get("port") and (p.get("target") or "") == (params.get("target") or ""):
            return True
    return False


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _adoptable(s, sys: System) -> HealthMonitor | None:
    """Eigener Monitor, der offensichtlich dieses System meint: gleiche Adresse und gleicher Name (System- oder
    Gerätename wie „TrueNAS“). Nur die Adresse genügt nicht: AdGuard auf dem Pi ist nicht der Pi."""
    from .appliances import KINDS

    if not sys.ip:
        return None
    names = {_norm(sys.name), _norm(sys.host_type), _norm(KINDS.get(sys.host_type, ""))} - {""}
    for m in s.scalars(select(HealthMonitor).where(HealthMonitor.system_id.is_(None), HealthMonitor.host == sys.ip)
                       .order_by(HealthMonitor.id)):
        if _norm(m.name) in names:
            return m
    return None


def sync_system_monitors(s, now: float) -> None:
    """Jedes System aus „Systems“ (freigegebener Agent oder Connector-Gerät) bekommt einen Monitor mit
    Grundprüfungen. Gibt es schon einen eigenen Monitor auf derselben Adresse, wird er übernommen statt verdoppelt.
    Widerruf oder Entfernen des Systems entfernt den Monitor."""
    from .appliances import CONFIG_KEY

    connectors = setting(s, CONFIG_KEY) or {}
    systems = s.scalars(select(System).where(System.status.in_(AUTO_STATUSES))).all()
    existing = {m.system_id: m for m in s.scalars(select(HealthMonitor).where(HealthMonitor.system_id.is_not(None)))}
    for sys in systems:
        m = existing.pop(sys.id, None)
        if m is None:
            m = _adoptable(s, sys)
            if m is not None:   # eigener Monitor auf dieser Adresse: übernehmen, Verlauf und Schlüssel bleiben
                m.system_id, m.name = sys.id, sys.name
            else:
                m = HealthMonitor(name=sys.name, slug=unique_slug(s, sys.name), host=sys.ip or "", system_id=sys.id,
                                  critical=True, created_at=now, state="unknown", state_since=now)
                s.add(m)
            s.flush()
            checks = s.scalars(select(HealthCheck).where(HealthCheck.monitor_id == m.id)).all()
            for kind, params in default_checks(sys, connectors.get(str(sys.id))):
                if not _has(checks, kind, params):
                    s.add(HealthCheck(monitor_id=m.id, kind=kind, params=json.dumps(params),
                                      **({"interval_s": 30, "retry_s": 15} if kind == "agent" else {})))
            continue
        if m.name != sys.name:
            m.name = sys.name
        if not m.host and sys.ip:
            m.host = sys.ip
    for m in existing.values():   # widerrufen, wieder ausstehend oder Connector entfernt
        s.delete(m)


# --- Verlauf ---

def record_sample(s, c: HealthCheck, r: ProbeResult, now: float) -> None:
    ok = r.ok
    s.add(HealthSample(check_id=c.id, ts=now, ok=ok, latency_ms=r.latency_ms))
    hour = int(now // 3600 * 3600)
    row = s.get(HealthRollup, (c.id, hour))
    if row is None:
        row = HealthRollup(check_id=c.id, hour=hour, total=0, ok=0, lat_sum=0.0, lat_n=0, lat_max=0.0)
        s.add(row)
    row.total += 1
    row.ok += 1 if ok else 0
    if r.latency_ms is not None:
        row.lat_sum += r.latency_ms
        row.lat_n += 1
        row.lat_max = max(row.lat_max, r.latency_ms)


def prune(s, now: float) -> None:
    s.execute(delete(HealthSample).where(HealthSample.ts < now - SAMPLE_DAYS * 86400))
    s.execute(delete(HealthRollup).where(HealthRollup.hour < now - ROLLUP_DAYS * 86400))
    s.execute(delete(HealthEvent).where(HealthEvent.ts < now - ROLLUP_DAYS * 86400))


def state_durations(s, monitor_id: int, start: float, end: float, n: int = 1) -> list[dict]:
    """Zeit je Zustand in n gleich langen Abschnitten von start bis end, aus den Zustandswechseln."""
    before = s.scalars(select(HealthEvent).where(HealthEvent.monitor_id == monitor_id, HealthEvent.ts <= start)
                       .order_by(HealthEvent.ts.desc()).limit(1)).first()
    events = s.scalars(select(HealthEvent).where(HealthEvent.monitor_id == monitor_id, HealthEvent.ts > start,
                                                 HealthEvent.ts < end).order_by(HealthEvent.ts)).all()
    spans, cur, t = [], before.state if before else "unknown", start
    for e in events:
        spans.append((t, e.ts, cur))
        cur, t = e.state, e.ts
    spans.append((t, end, cur))
    width = (end - start) / n
    out = []
    for i in range(n):
        a, b = start + i * width, start + (i + 1) * width
        d = {st: 0.0 for st in STATES}
        d["paused"] = 0.0
        for x, y, st in spans:
            overlap = min(b, y) - max(a, x)
            if overlap > 0:
                d[st if st in d else "unknown"] += overlap
        out.append(d)
    return out


def uptime_of(d: dict) -> float | None:
    """Verfügbarkeit: up und degraded zählen als erreichbar; unknown und Pause bleiben außen vor."""
    known = d["up"] + d["degraded"] + d["down"]
    return None if known <= 0 else round((d["up"] + d["degraded"]) / known * 100, 3)


def worst_of(d: dict) -> str:
    for st in ("down", "degraded", "up"):
        if d[st] > 0:
            return st
    return "paused" if d["paused"] > 0 else "unknown"


# --- Engine ---

class InlineExecutor:
    """Für Tests: führt Prüfungen sofort aus."""

    def submit(self, fn, *args):
        f = Future()
        f.set_result(fn(*args))
        return f

    def shutdown(self, wait=False):
        pass


class HealthEngine:
    def __init__(self, ctx: Context, executor=None, probe=run_probe):
        self.ctx = ctx
        self.executor = executor or ThreadPoolExecutor(WORKERS, thread_name_prefix="health")
        self.probe = probe
        self.inflight: dict[int, tuple[Future, float]] = {}
        self.next_due: dict[int, float] = {}
        self.started: float | None = None
        self.last_tick: float = 0.0
        self.last_sync = 0.0
        self.last_prune = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # Lebenszyklus
    def start(self) -> None:
        self.started = self.ctx.clock()
        self._thread = threading.Thread(target=self._run, name="health-engine", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.executor.shutdown(wait=False)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:   # eine kaputte Runde darf die Überwachung nie beenden
                log.exception("Health engine tick failed")
            self._stop.wait(TICK)

    def ok(self) -> bool:
        return self.last_tick > 0 and self.ctx.clock() - self.last_tick < ENGINE_STALE

    def poke(self, check_id: int | None = None) -> None:
        """Nach einer Änderung: Prüfung(en) sofort neu ansetzen."""
        with self._lock:
            if check_id is None:
                self.next_due.clear()
            else:
                self.next_due.pop(check_id, None)

    # Eine Runde
    def tick(self) -> None:
        now = self.ctx.clock()
        if self.started is None:
            self.started = now
        with self.ctx.session_factory() as s:
            if now - self.last_sync >= 60:
                sync_system_monitors(s, now)
                s.commit()
                self.last_sync = now
            self._schedule(s, now)
        transitions = self._collect(now)
        self.last_tick = now
        if transitions:
            self._alert(transitions)

    def _fritz(self) -> dict | None:
        with self.ctx.session_factory() as s:
            cfg = setting(s, "fritz.config")
        password = self.ctx.secrets.get("fritz.password")
        if not cfg or not password:
            return None
        return {"url": tr064_url(cfg["url"]), "user": cfg["user"], "password": password}

    def spec_for(self, c: HealthCheck, m: HealthMonitor, fritz: dict | None) -> ProbeSpec:
        p = params_of(c)
        auth = self.ctx.secrets.get(secret_name(c.id)) if c.kind == "http" else None
        return ProbeSpec(kind=c.kind, host=p.get("target") or m.host, params=p, timeout=c.timeout_s, auth=auth,
                         fritz=fritz if c.kind in FRITZ_KINDS else None)

    def _schedule(self, s, now: float) -> None:
        rows = s.execute(select(HealthCheck, HealthMonitor).join(HealthMonitor, HealthMonitor.id == HealthCheck.monitor_id)
                         .where(HealthCheck.paused.is_(False), HealthMonitor.paused.is_(False),
                                HealthCheck.kind.in_(ACTIVE))).all()
        fritz = None
        fritz_loaded = False
        for c, m in rows:
            with self._lock:
                if c.id in self.inflight or self.next_due.get(c.id, 0) > now:
                    continue
            if c.kind in FRITZ_KINDS and not fritz_loaded:
                fritz, fritz_loaded = self._fritz(), True
            spec = self.spec_for(c, m, fritz)
            if not spec.host and c.kind != "fritz_wan":   # Internet-Status fragt die FRITZ!Box, kein Ziel nötig
                continue
            future = self.executor.submit(self.probe, spec)
            with self._lock:
                self.inflight[c.id] = (future, now)

    def _collect(self, now: float) -> list[tuple[HealthMonitor, str, str]]:
        with self._lock:
            done = {cid: f for cid, (f, _t) in self.inflight.items() if f.done()}
            for cid in done:
                del self.inflight[cid]
        with self.ctx.session_factory() as s:
            for cid, f in done.items():
                c = s.get(HealthCheck, cid)
                if c is None:
                    continue
                try:
                    r = f.result()
                except Exception as e:  # noqa: BLE001 – die Prüfung selbst ist abgestürzt
                    r = ProbeResult(False, error=str(e)[:200])
                self._apply(s, c, r, now)
            self._passive(s, now)
            transitions = self._aggregate(s, now)
            if now - self.last_prune >= 3600:
                prune(s, now)
                self.last_prune = now
            s.commit()
            return transitions

    def _apply(self, s, c: HealthCheck, r: ProbeResult, now: float) -> None:
        apply_result(c, r, now)
        if not r.inconclusive:
            record_sample(s, c, r, now)
        with self._lock:
            self.next_due[c.id] = now + (c.retry_s if c.fails else c.interval_s)

    def _passive(self, s, now: float) -> None:
        """Agent und Heartbeat: Meldungen statt Messung, im selben Takt bewertet."""
        rows = s.execute(select(HealthCheck, HealthMonitor).join(HealthMonitor, HealthMonitor.id == HealthCheck.monitor_id)
                         .where(HealthCheck.paused.is_(False), HealthMonitor.paused.is_(False),
                                HealthCheck.kind.in_(("agent", "heartbeat")))).all()
        for c, m in rows:
            if self.next_due.get(c.id, 0) > now:
                continue
            if c.kind == "agent":
                sys = s.get(System, m.system_id) if m.system_id else None
                if sys is None or sys.status != "active":
                    r = ProbeResult(False, error="no active agent", inconclusive=True)
                elif sys.last_contact is not None and now - sys.last_contact < AGENT_FRESH:
                    r = ProbeResult(True)
                elif self.started is not None and now - self.started < AGENT_GRACE:
                    continue   # gerade gestartet: Agenten verbinden sich erst wieder
                else:
                    age = "never" if sys.last_contact is None else f"{int(now - sys.last_contact)} s ago"
                    r = ProbeResult(False, error=f"agent silent (last contact {age})")
            else:
                grace = params_of(c).get("grace_s", 30)
                if c.error == ANNOUNCED:
                    r = ProbeResult(False, error=ANNOUNCED)
                elif c.last_ok is not None and now - c.last_ok <= c.interval_s + grace:
                    r = ProbeResult(True)
                elif c.last_ok is None and now - (m.created_at or now) <= c.interval_s + grace:
                    continue   # noch keine Meldung erwartet
                else:
                    r = ProbeResult(False, error="no heartbeat received")
                last_ok = c.last_ok
                self._apply(s, c, r, now)
                c.last_ok = last_ok   # last_ok setzt beim Heartbeat nur der Eingang (beat)
                continue
            self._apply(s, c, r, now)

    def _aggregate(self, s, now: float) -> list[tuple[HealthMonitor, str, str]]:
        monitors = s.scalars(select(HealthMonitor)).all()
        checks = s.scalars(select(HealthCheck)).all()
        by_monitor: dict[int, list[tuple[str, str]]] = {}
        for c in checks:
            by_monitor.setdefault(c.monitor_id, []).append((c.kind, effective_state(c, now)[0]))
        transitions = []
        for m in monitors:
            if m.paused:
                continue
            state, warning = aggregate(by_monitor.get(m.id, []))
            if warning != m.warning:
                m.warning = warning
            if state != m.state:
                prev = m.state
                m.state, m.state_since = state, now
                s.add(HealthEvent(monitor_id=m.id, ts=now, state=state, prev=prev, detail=warning))
                transitions.append((m, prev, state))
        return transitions

    # Alarm
    def _alert(self, transitions: list[tuple[HealthMonitor, str, str]]) -> None:
        if self.ctx.notifier is None:
            return
        with self.ctx.session_factory() as s:
            monitors = s.scalars(select(HealthMonitor).where(HealthMonitor.paused.is_(False))).all()
            down_now = [m for m in monitors if m.state == "down"]
            known = [m for m in monitors if m.state != "unknown"]
            details = {m.id: [f"{check_label(c)}: {c.error}" for c in
                              s.scalars(select(HealthCheck).where(HealthCheck.monitor_id == m.id)).all() if c.error]
                       for m, _p, _st in transitions}
        went_down = [(m, p) for m, p, st in transitions if st == "down" and p in ("up", "degraded") and m.critical]
        recovered = [m for m, p, st in transitions if p == "down" and st in ("up", "degraded") and m.critical]
        if not went_down and not recovered:
            return
        lines, title = [], ""
        if went_down and len(known) >= OUTAGE_MIN and len(down_now) >= OUTAGE_SHARE * len(known):
            title = f"vulnwatch: network outage – {len(down_now)} of {len(known)} hosts down"
            lines.append("Most monitored hosts failed at the same time. Check the network, switch or router first.")
            lines += [f"- {m.name}" for m in down_now]
        else:
            if went_down:
                names = ", ".join(m.name for m, _p in went_down)
                title = f"vulnwatch: {names} {'is' if len(went_down) == 1 else 'are'} DOWN"
                for m, _p in went_down:
                    lines.append(f"{m.name} ({m.host or 'no host'}) is down")
                    lines += [f"  {d}" for d in details.get(m.id, [])[:5]]
            if recovered:
                names = ", ".join(m.name for m in recovered)
                title = title or f"vulnwatch: {names} recovered"
                lines += [f"{m.name} is back up" for m in recovered]
        body = "\n".join(lines)
        self.executor.submit(self._send, title, body)

    def _send(self, title: str, body: str) -> None:
        try:
            ok, err = self.ctx.notifier(title, body, None, kind="alert")
            if not ok:
                log.warning("Health alert not delivered: %s", err)
        except Exception:
            log.exception("Health alert failed")


def beat(s, check: HealthCheck, now: float, down: bool) -> None:
    """Eingang eines Heartbeats. `down` = der Host meldet sein Herunterfahren: sofort down."""
    if down:
        check.error, check.fails = ANNOUNCED, check.fails_down
        if check.state != "down":
            check.state, check.state_since = "down", now
        check.last_checked = now
        return
    check.last_ok = now
    if check.error == ANNOUNCED:
        check.error = ""
