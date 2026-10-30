"""Produktstände (PLAN Abschnitt 5 und 13, Phase 4): Image-Aktualität (Registry), Release-Linien und EOL.
Läuft alle 6 h im Planer (wie früher image-check) und auf Knopfdruck. Erzeugt eigene Funde (Quelle `registry` bzw.
`eol`), die nur dieser Durchgang anlegt, aktualisiert und als behoben markiert; Stufen aus rules.classify_product."""
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from . import eol as eol_mod
from .containers import containers_of
from .context import Context
from .freshness import DOCKERHUB, Registry, check, parse_ref
from .guards import Guards
from .models import Finding, System, put_setting, setting
from .rules import classify_product, is_patch_step

log = logging.getLogger("vulnwatch.products")

STATE_KEY = "registry.state"
SOURCES = ("registry", "eol")
MAX_AGE_HOURS = 36          # älter: Prüfung gilt als nicht gelaufen
INTERVAL_HOURS = 6
_lock = threading.Lock()


def _image_rows(system: System) -> list[dict]:
    """Laufende Container, je Image-Referenz einmal."""
    seen: dict[str, dict] = {}
    for c in containers_of(system):
        if c.get("state") != "running":
            continue
        ref = c.get("image", "")
        row = seen.setdefault(ref or c.get("image_id", ""), {
            "ref": ref, "image_id": c.get("image_id", ""), "containers": [],
            "digests": {d.split("@", 1)[1] for d in c.get("repo_digests") or [] if "@" in d},
            "label": (c.get("labels") or {}).get("org.opencontainers.image.version", ""),
        })
        row["containers"].append(c.get("name", ""))
    return list(seen.values())


def _target(row: dict) -> str:
    ref = row["ref"]
    if ref.startswith("sha256:") or not ref:
        ref = f"{row['containers'][0] or 'container'} ({row['image_id'][7:19]})"
    return f"image:{ref[:200]}"[:300]


def _eol_finding(db, product: str, version: str, target: str, component: str) -> dict | None:
    rel = db.release(product, version)
    if not rel or not rel.get("isEol"):
        return None
    since = rel.get("eolFrom") or "?"
    return {"target": target, "cve_id": "VW-EOL", "severity": classify_product("eol"), "component": component,
            "installed_version": version, "fixed_version": db.newest_maintained(product),
            "title": f"{db.label(product)} {rel['name']} is end of life since {since}: no more security updates"}


def _untagged(system: System, names: list[str]) -> tuple[str, str]:
    """(Container, Hinweis) für Container auf einem Image ohne Tag: Das Image wurde neu gebaut oder gezogen, der
    Tag zeigt jetzt woanders hin, und der Container läuft noch auf dem alten. Ein Neustart reicht nicht."""
    by_name = {c.get("name"): c.get("labels") or {} for c in containers_of(system)}
    projects: dict[str, list[str]] = {}
    for name in names:
        labels = by_name.get(name, {})
        workdir, service = labels.get("com.docker.compose.project.working_dir"), labels.get("com.docker.compose.service")
        if workdir and service:
            projects.setdefault(workdir, []).append(service)
    detail = "runs an image whose tag now points to a newer build; recreate the container (a restart is not enough)"
    if projects:
        detail += ": " + "; ".join(f"cd {wd} && docker compose up -d --force-recreate {' '.join(sorted(set(svcs)))}"
                                   for wd, svcs in projects.items())
    return ", ".join(names) or "container", detail


def check_system(system: System, registry: Registry, cache: dict, db) -> dict:
    try:
        inv = json.loads(system.inventory_json or "{}")
    except ValueError:
        inv = {}
    arch = inv.get("arch") or "amd64"
    rows, findings, errors, pending = [], [], {}, []
    for row in _image_rows(system):
        status, running, newer, detail = check(row["ref"], row["digests"], row["image_id"], arch, row["label"],
                                               registry, cache)
        target = _target(row)
        rows.append({"containers": row["containers"], "image": row["ref"], "status": status,
                     "running": running, "newer": newer, "detail": detail})
        if status == "unknown" and (row["ref"] or "").startswith("sha256:"):
            names, detail = _untagged(system, row["containers"])
            errors[names] = detail
        elif status == "unknown":
            errors[row["ref"] or target] = detail
        elif status == "pending":
            pending.append(row["ref"])
        elif status == "outdated":
            findings.append({"target": target, "cve_id": "VW-IMAGE-OUTDATED", "severity": classify_product("outdated"),
                             "component": row["ref"], "installed_version": running or row["image_id"][7:19],
                             "fixed_version": newer or "newer image",
                             "title": f"Newer image for {row['ref']} in the registry: pull and recreate "
                                      f"{', '.join(row['containers'])}"})
        elif status == "newer-version":
            patch = is_patch_step(running, newer)
            findings.append({"target": target, "cve_id": "VW-IMAGE-NEWER",
                             "severity": classify_product("newer", patch_only=patch),
                             "component": row["ref"], "installed_version": running, "fixed_version": newer,
                             "title": f"{'Newer patch' if patch else 'Newer version'} {newer} available "
                                      f"for {row['ref']}"})
        parsed = parse_ref(row["ref"]) if row["ref"] and not row["ref"].startswith("sha256:") else None
        if db and parsed and parsed[0] == DOCKERHUB and status not in ("local",):
            product = db.docker.get(parsed[1])
            version = parsed[2] if re.match(r"^v?\d", parsed[2]) else running   # der Tag ist verbindlich
            if product and version:
                f = _eol_finding(db, product, version, target, row["ref"])
                if f:
                    findings.append(f)
    os_product = eol_mod.OS_PRODUCTS.get(inv.get("os_id", ""))
    if db and os_product and inv.get("os_version_id"):
        f = _eol_finding(db, os_product, inv["os_version_id"], "host", inv.get("os_name") or os_product)
        if f:
            findings.append(f)
    return {"rows": rows, "findings": findings, "errors": errors, "pending": pending}


def sync_findings(s, system_id: int, desired: list[dict], now: datetime) -> tuple[int, int]:
    """Funde der Quellen registry/eol eines Systems auf den Soll-Stand bringen. (neu, behoben)."""
    existing = {(f.target, f.cve_id): f for f in s.scalars(select(Finding).where(
        Finding.system_id == system_id, Finding.source.in_(SOURCES), Finding.status.in_(["open", "accepted"])))}
    new = resolved = 0
    seen = set()
    for d in desired:
        key = (d["target"], d["cve_id"])
        if key in seen:
            continue
        seen.add(key)
        source = "eol" if d["cve_id"] == "VW-EOL" else "registry"
        f = existing.get(key)
        if f is None:
            s.add(Finding(system_id=system_id, status="open", source=source, **d))
            new += 1
        else:
            for k, v in d.items():
                setattr(f, k, v)
    for key, f in existing.items():
        if key not in seen:
            f.status, f.resolved_at = "resolved", now
            resolved += 1
    from .snooze import apply_snoozes
    apply_snoozes(s, now, system_id)
    return new, resolved


def refresh_versions(ctx: Context) -> dict:
    """Ein Durchgang: NPM- und Router-Expositionen, TrueNAS/Home Assistant, Registry, EOL. Liefert den gespeicherten Zustand."""
    from .connectors import refresh_npm

    if not _lock.acquire(blocking=False):
        return {"busy": True}
    try:
        try:
            refresh_npm(ctx)
        except Exception:  # NPM darf die Produktprüfung nie aufhalten
            log.exception("NPM refresh failed")
        try:
            from .fritzbox import refresh_fritz
            refresh_fritz(ctx)
        except Exception:  # der Router ebenso wenig
            log.exception("FRITZ!Box refresh failed")
        try:
            from .appliances import refresh_appliances
            refresh_appliances(ctx)   # nach NPM: braucht dessen Zuordnung für die Internet-Erreichbarkeit
        except Exception:
            log.exception("TrueNAS/Home Assistant refresh failed")
        cache_dir = ctx.settings.data_dir / "registry"
        registry = Registry(cache_dir)
        db, eol_error = eol_mod.load(ctx.settings.data_dir / "eol")
        with ctx.session_factory() as s:
            systems = s.scalars(select(System).where(System.status == "active")).all()
        cache: dict = {}
        results = {}
        for system in systems:
            try:
                results[system.id] = check_system(system, registry, cache, db)
            except Exception as e:  # noqa: BLE001
                log.exception("Version check of %s failed", system.name)
                results[system.id] = {"rows": [], "findings": None, "errors": {"*": f"check failed: {type(e).__name__}"},
                                      "pending": []}
        try:
            registry.save_cache()
        except OSError:
            log.warning("Registry cache could not be saved")
        now = datetime.now(timezone.utc)
        state = {"at": time.time(), "eol_error": eol_error, "systems": {}}
        with ctx.session_factory() as s:
            for sid, r in results.items():
                if r["findings"] is not None:
                    new, resolved = sync_findings(s, sid, r["findings"], now)
                else:
                    new = resolved = 0
                state["systems"][str(sid)] = {"rows": r["rows"], "errors": r["errors"], "pending": r["pending"],
                                              "new": new, "resolved": resolved}
            put_setting(s, STATE_KEY, state)
            s.commit()
        return state
    finally:
        _lock.release()


def versions_check(state: dict | None, system: System, open_by_kind: dict[str, int], now: float) -> tuple[str, str]:
    """Spalte „Versions“ der Abdeckungsmatrix: Image-Aktualität und EOL eines Systems."""
    entry = (state or {}).get("systems", {}).get(str(system.id))
    has_images = any(c.get("state") == "running" for c in containers_of(system))
    if entry is None:
        if state is None:
            return "offen", "first version check after the next pass (every 6 h)"
        return "offen", "new host: checked in the next version pass"
    age_h = (now - state["at"]) / 3600
    if age_h > MAX_AGE_HOURS:
        return "fehler", f"version check last ran {age_h:.0f} h ago (limit {MAX_AGE_HOURS} h)"
    if entry["errors"]:
        first = next(iter(entry["errors"].items()))
        return "fehler", f"{len(entry['errors'])} image(s) not checkable: {first[0]}: {first[1]}"
    if state.get("eol_error"):
        return "fehler", state["eol_error"]
    parts = []
    if open_by_kind.get("VW-IMAGE-OUTDATED"):
        parts.append(f"{open_by_kind['VW-IMAGE-OUTDATED']} outdated")
    if open_by_kind.get("VW-IMAGE-NEWER"):
        parts.append(f"{open_by_kind['VW-IMAGE-NEWER']} newer version")
    if open_by_kind.get("VW-EOL"):
        parts.append(f"{open_by_kind['VW-EOL']} end of life")
    if parts:
        return "fund", ", ".join(parts)
    if entry["pending"]:
        return "offen", f"{len(entry['pending'])} image(s) waiting for the next pass (Docker Hub limit)"
    return "ok", f"{len(entry['rows'])} images current" if has_images else "OS supported, no containers"


def open_product_counts(s) -> dict[int, dict[str, int]]:
    out: dict[int, dict[str, int]] = {}
    for sid, cve, n in s.execute(select(Finding.system_id, Finding.cve_id, func.count(Finding.id))
                                 .where(Finding.source.in_(SOURCES), Finding.status == "open")
                                 .group_by(Finding.system_id, Finding.cve_id)):
        out.setdefault(sid, {})[cve] = n
    return out


def load_state(s) -> dict | None:
    return setting(s, STATE_KEY)


def build_versions_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    @router.get("/versions", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            return load_state(s) or {}

    @router.post("/versions/refresh")
    def refresh(found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "versions.refresh", "version check started")
            s.commit()
        threading.Thread(target=refresh_versions, args=(ctx,), daemon=True, name="versions").start()
        return {"ok": True, "started": True}

    return router
