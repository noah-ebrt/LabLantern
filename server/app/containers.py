"""Soll/Ist der Container (PLAN Abschnitt 6): Jedes System hat eine Liste der Container, die laufen sollen.
Fehlt einer davon oder läuft ein unbekannter, ist das ein Fund. Gestoppte, nie erwartete Container zählen nicht
(Einmal-Jobs, Init-Container). Der erste Report eines Systems legt den Soll-Zustand fest; danach nur der Admin."""
import json

from .models import System

MAX_LISTED = 5
HOST = "(host)"   # Eintrag in exposed_containers: Dienste des Hosts selbst sind internet-erreichbar


def containers_of(system: System) -> list[dict]:
    try:
        return json.loads(system.inventory_json or "{}").get("containers", [])
    except json.JSONDecodeError:
        return []


def host_ports_of(system: System) -> set[int]:
    """TCP-Ports, auf denen Dienste des Hosts selbst lauschen (Agent ab 0.14)."""
    try:
        return set(json.loads(system.inventory_json or "{}").get("host_ports", []))
    except json.JSONDecodeError:
        return set()


def running_names(system: System) -> set[str]:
    return {c["name"] for c in containers_of(system) if c.get("name") and c.get("state") == "running"}


def expected_names(system: System) -> set[str] | None:
    """None: noch kein Soll-Zustand festgelegt."""
    if not system.expected_containers:
        return None
    try:
        return set(json.loads(system.expected_containers))
    except json.JSONDecodeError:
        return None


def set_expected(system: System, names: set[str]) -> None:
    system.expected_containers = json.dumps(sorted(names))


def learn_baseline(system: System) -> None:
    """Beim ersten Report: was jetzt läuft, ist der Soll-Zustand."""
    if expected_names(system) is None:
        set_expected(system, running_names(system))


def container_diff(system: System) -> dict:
    expected = expected_names(system)
    running = running_names(system)
    if expected is None:
        return {"baseline": False, "missing": [], "unknown": [], "expected": sorted(running)}
    return {"baseline": True, "missing": sorted(expected - running), "unknown": sorted(running - expected),
            "expected": sorted(expected)}


def _names(items: list[str]) -> str:
    shown = ", ".join(items[:MAX_LISTED])
    return shown + (f" +{len(items) - MAX_LISTED}" if len(items) > MAX_LISTED else "")


def container_check(system: System) -> tuple[str, str]:
    """(Status, Text) für die Abdeckungsmatrix."""
    d = container_diff(system)
    total = len(containers_of(system))
    parts = []
    if d["missing"]:
        parts.append(f"{len(d['missing'])} missing: {_names(d['missing'])}")
    if d["unknown"]:
        parts.append(f"{len(d['unknown'])} unexpected: {_names(d['unknown'])}")
    if parts:
        return "fund", " · ".join(parts)
    return "ok", f"{total} containers"


def exposed_names(system: System) -> set[str]:
    try:
        return set(json.loads(system.exposed_containers or "[]"))
    except json.JSONDecodeError:
        return set()


def exposed_targets(system: System, extra: set[str] = frozenset()) -> set[str]:
    """Fund-Ziele (`image:<Referenz>`) der internet-erreichbaren Container; `extra` = Namen aus dem NPM-Connector."""
    names = exposed_names(system) | set(extra)
    out = {"host"} if HOST in names else set()
    for c in containers_of(system):
        if c.get("name") in names:
            ref = c.get("image", "")
            if ref.startswith("sha256:") or not ref:
                ref = f"{c.get('name') or 'container'} ({c.get('image_id', '')[7:19]})"
            out.add(f"image:{ref[:200]}"[:300])
    return out
