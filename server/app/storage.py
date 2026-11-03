"""Speicher von NAS-Geräten in einer gemeinsamen Form, egal ob TrueNAS, Synology oder Proxmox VE: Pools (ZFS-Pool,
Speicherpool, Volume) mit Aufbau, Zustand, Füllstand und ihren Laufwerken, dazu jedes Laufwerk mit Modell, Größe,
Art, Temperatur und Zustand. Jede Quelle füllt, was ihre API hergibt; Unbekanntes bleibt leer, nie „ok“.

{"pools": [{"name", "kind", "layout", "status", "state", "percent", "size", "disks": [Laufwerksnamen]}],
 "disks": [{"name", "model", "serial", "size", "type", "status", "state", "temp", "pool", "detail"}], "error": ""}
"""
MAX_ITEMS = 500   # wie appliances.MAX_ITEMS (dort importiert dieses Modul, nicht umgekehrt)

OK = {"normal", "online", "passed", "ok", "healthy", "initialized", "safe"}
WARN = {"warning", "attention", "repairing", "resilvering"}
BAD = {"degraded", "crashed", "failing", "failed", "faulted", "unavail", "unavailable", "removed", "abnormal",
       "offline", "broken"}
RANK = {"bad": 3, "warn": 2, "ok": 1, "unknown": 0}


def state_of(*statuses) -> str:
    """Schlechtester bekannter Zustand: bad > warn > ok; nur Unbekanntes ergibt „unknown“, nie „ok“."""
    found = "unknown"
    for raw in statuses:
        s = str(raw or "").strip().lower()
        st = "bad" if s in BAD else "warn" if s in WARN else "ok" if s in OK else "unknown"
        found = max(found, st, key=RANK.get)
    return found


def _int(v) -> int | None:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def layout_of(vdevs: list[str]) -> str:
    """Aufbau aus den Datenvdevs: [„RAIDZ1“] -> „RAIDZ1“, zweimal „MIRROR“ -> „2× MIRROR“, gemischt mit „+“."""
    kinds = sorted(set(vdevs))
    if len(kinds) != 1:
        return " + ".join(kinds)
    return f"{len(vdevs)}× {kinds[0]}" if len(vdevs) > 1 else kinds[0]


def pool(name, kind: str, status="", percent=None, size=None, layout="", disks=()) -> dict:
    return {"name": str(name or "?")[:100], "kind": kind, "layout": str(layout or "")[:40],
            "status": str(status or "").lower()[:40], "state": state_of(status),
            "percent": None if percent is None else round(float(percent), 1), "size": _int(size),
            "disks": [str(d)[:100] for d in disks][:MAX_ITEMS]}


def disk(name, model="", serial="", size=None, kind="", status="", smart="", temp=None, pool_name="", detail="") -> dict:
    kind = str(kind or "").lower()
    return {"name": str(name or "?")[:100], "model": str(model or "").strip()[:100], "serial": str(serial or "")[:60],
            "size": _int(size), "type": "nvme" if "nvme" in kind else "ssd" if "ssd" in kind else "hdd" if kind else "",
            "status": str(status or smart or "").lower()[:40], "state": state_of(status, smart),
            "temp": _int(temp), "pool": str(pool_name or "")[:100], "detail": str(detail or "")[:200]}


def storage(pools: list[dict] | None, disks: list[dict] | None, error: str = "") -> dict:
    return {"pools": pools or [], "disks": disks or [], "error": error[:300]}


def from_agent(raw: dict) -> dict:
    """Bericht des Agenten (ab 0.18) in die gemeinsame Form: Zustände und Aufbau rechnet der Master, nicht der Agent."""
    pools = [pool(p["name"], p["kind"] or "Pool", p["status"], p["alloc"] * 100 / p["size"] if p["size"] and p["alloc"] else None,
                  p["size"] or None, layout_of(p["vdevs"]), p["disks"]) for p in raw.get("pools") or []]
    disks = [disk(d["name"], d["model"], d["serial"], d["size"] or None, d["type"], d["status"], d["smart"], d["temp"],
                  d["pool"], d["detail"]) for d in raw.get("disks") or []]
    return storage(pools, disks, raw.get("error") or "")


def drive_findings(st: dict, hint: str) -> list[dict]:
    """Ein Fund je gestörtem Laufwerk (Pools melden die Geräte-Module selbst). `hint`: wo man es auf dem Gerät prüft."""
    out = []
    for d in st.get("disks") or []:
        if d["state"] in ("bad", "warn"):
            out.append({"target": f"drive:{d['name']}", "cve_id": "LL-DRIVE", "component": f"{d['name']} {d['model']}".strip(),
                        "severity": "hoch" if d["state"] == "bad" else "mittel", "installed_version": d["status"] or "?",
                        "fixed_version": hint, "title": f"{d['name']} ({d['model'] or 'drive'}) reports {d['status']}"[:500]})
    return out
