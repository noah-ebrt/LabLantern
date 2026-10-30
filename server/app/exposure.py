"""Internet-Erreichbarkeit aus mehreren Quellen (PLAN-extensions A4): NPM, FRITZ!Box, später Cloudflare Tunnel u. a.

Jede Quelle liest selbst und speichert ihren Zustand unter ihrem Schlüssel: {configured, ok, error, at, checked_at,
exposed: {System-ID: [Name]}, via: {System-ID: {Name: [Einzelheit]}}, unmatched}. Schlägt ein Lesen fehl, bleibt
die letzte Zuordnung stehen (ein Ausfall stuft nichts herab), die Quelle steht aber als Fehler in der Matrix."""
import logging
import time
from dataclasses import dataclass
from typing import Callable

from .context import Context
from .models import put_setting, setting

log = logging.getLogger("vulnwatch.exposure")

STALE_HOURS = 26   # täglicher Abgleich plus Spielraum


@dataclass(frozen=True)
class ExposureSource:
    key: str                          # "npm", "fritzbox", …
    label: str                        # in "via …"-Texten und der Abdeckungsmatrix
    short: str                        # Quelle in exposed_auto ("NPM", "router")
    state_key: str
    refresh: Callable[[Context], dict]   # liest und speichert; {"configured": False} ohne Einrichtung


def sources() -> list[ExposureSource]:
    from .connectors import NPM_STATE, refresh_npm
    from .fritzbox import FRITZ_STATE, refresh_fritz

    return [ExposureSource("npm", "NPM", "NPM", NPM_STATE, refresh_npm),
            ExposureSource("fritzbox", "FRITZ!Box", "router", FRITZ_STATE, refresh_fritz)]


def refresh_all(ctx: Context) -> None:
    """Alle Quellen nacheinander; ein unerwarteter Fehler einer Quelle hält die anderen nicht auf."""
    for src in sources():
        try:
            src.refresh(ctx)
        except Exception as e:  # noqa: BLE001
            log.exception("%s refresh failed", src.label)
            mark_failed(ctx, src.state_key, f"{type(e).__name__}: {e}")


def mark_failed(ctx: Context, state_key: str, error: str) -> None:
    with ctx.session_factory() as s:
        old = setting(s, state_key) or {}
        put_setting(s, state_key, {**old, "configured": True, "ok": False, "error": error[:300], "at": time.time()})
        s.commit()


def last_success(state: dict) -> float | None:
    return state.get("checked_at") or (state.get("at") if state.get("ok") else None)


def _states(s):
    for src in sources():
        state = setting(s, src.state_key) or {}
        if state.get("configured") or state.get("exposed"):
            yield src, state


def connector_exposed(s) -> dict[int, dict[str, list[str]]]:
    """{System-ID: {Containername oder HOST: [Quellen]}}: automatisch erkannte Erreichbarkeit."""
    out: dict[int, dict[str, list[str]]] = {}
    for src, state in _states(s):
        for sid, names in (state.get("exposed") or {}).items():
            for name in names:
                out.setdefault(int(sid), {}).setdefault(name, []).append(src.short)
    return out


def exposure_via(s) -> dict[int, dict[str, list[str]]]:
    """Wie connector_exposed, aber mit Begründung: "via NPM: app.example.com", "via FRITZ!Box: port 25565"."""
    out: dict[int, dict[str, list[str]]] = {}
    for src, state in _states(s):
        via = state.get("via") or {}
        for sid, names in (state.get("exposed") or {}).items():
            for name in names:
                details = (via.get(sid) or {}).get(name) or []
                texts = [f"via {src.label}: {d}" for d in details] or [f"via {src.label}"]
                out.setdefault(int(sid), {}).setdefault(name, []).extend(texts)
    return out


def source_rows(s, now: float) -> list[dict]:
    """Eine Zeile je eingerichteter Quelle für die Abdeckungsmatrix: ok oder fehler, nie stillschweigend leer."""
    rows = []
    for src, state in _states(s):
        last = last_success(state)
        age = (now - last) / 3600 if last else None
        if not state.get("ok", True):
            known = f"; showing the last known mapping from {time.strftime('%Y-%m-%d', time.gmtime(last))}" \
                if last else "; showing the last known mapping"
            status, detail = "fehler", f"{state.get('error') or 'read failed'}{known}"
        elif age is None or age > STALE_HOURS:
            status, detail = "fehler", f"last successful read {round(age) if age else '?'} h ago"
        elif state.get("dns_failed"):   # sicher im Zweifel: als erreichbar gezählt, aber nicht still
            names = ", ".join(state["dns_failed"][:5])
            status, detail = "fehler", f"public DNS check failed for {names}; counted as exposed"
        else:
            status, detail = "ok", f"read {round(age)} h ago" if age >= 1 else "read just now"
        rows.append({"key": src.key, "label": src.label, "status": status, "detail": detail,
                     "exposed": sum(len(v) for v in (state.get("exposed") or {}).values()),
                     "unmatched": len(state.get("unmatched") or [])})
    return rows
