"""Archiv der Rohdaten je Lauf (PLAN Abschnitt 1.4 und 6): SBOMs der Hosts und Images und das rohe Worker-Ergebnis,
90 Tage. Ablage nach Inhalt (SHA-256, gzip), damit unveränderte SBOMs nicht jeden Tag neu Platz brauchen;
je Lauf ein Manifest, das auf die Inhalte zeigt. Ein Fehler beim Archivieren kippt nie die Auswertung,
steht aber im Lauf und im Report."""
import gzip
import hashlib
import json
import logging
import os
import time
from pathlib import Path

from sqlalchemy import select

from .context import Context
from .models import Setting, System

log = logging.getLogger("lablantern.archive")

KEEP_DAYS = 90
# Einstellungen, die nichts an der Bewertung ändern (Zustand, Zeitstempel), zählen nicht zur Konfigurationsversion
VOLATILE = ("worker.", "watchdog.", "refresh.", "releases.", "setup.", "passkeys.", "registry.", "eol.", "ai.")


def _root(ctx: Context) -> Path:
    return ctx.settings.data_dir / "archive"


def _put_blob(root: Path, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    path = root / "blobs" / digest[:2] / f"{digest}.gz"
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with gzip.open(tmp, "wb", compresslevel=6) as f:
            f.write(data)
        os.replace(tmp, path)
    return digest


def archive_run(ctx: Context, run_id: int, result: bytes, system_ids: list[int],
                images: list[tuple[int, str]]) -> str:
    from .scanrun import image_sbom_path, sbom_path

    try:
        root = _root(ctx)
        manifest = {"run_id": run_id, "at": time.time(), "result": _put_blob(root, result), "sboms": {}, "images": {}}
        for sid in system_ids:
            p = sbom_path(ctx, sid)
            if p.is_file():
                manifest["sboms"][str(sid)] = _put_blob(root, p.read_bytes())
        for sid, iid in images:
            p = image_sbom_path(ctx, sid, iid)
            if p.is_file():
                manifest["images"][f"{sid}/{iid}"] = _put_blob(root, p.read_bytes())
        (root / "runs").mkdir(parents=True, exist_ok=True)
        (root / "runs" / f"{int(run_id)}.json").write_text(json.dumps(manifest), encoding="utf-8")
        prune(ctx)
        return "ok"
    except OSError as e:
        log.exception("Archiving run #%d failed", run_id)
        return f"failed: {e.strerror or type(e).__name__}"[:200]


def prune(ctx: Context, now: float | None = None) -> int:
    """Manifeste älter als 90 Tage löschen, danach alle Inhalte, auf die kein Manifest mehr zeigt."""
    root = _root(ctx)
    cutoff = (now or time.time()) - KEEP_DAYS * 86400
    keep: set[str] = set()
    for m in (root / "runs").glob("*.json"):
        try:
            data = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("at", 0) < cutoff:
            m.unlink(missing_ok=True)
            continue
        keep.add(data["result"])
        keep.update(data["sboms"].values())
        keep.update(data["images"].values())
    removed = 0
    for blob in (root / "blobs").glob("*/*.gz"):
        if blob.name.removesuffix(".gz") not in keep:
            blob.unlink(missing_ok=True)
            removed += 1
    return removed


def config_version(s) -> str:
    """Kurzer Hash über alles, was die Bewertung bestimmt: Regel-Code, bewertungsrelevante Einstellungen,
    Soll-Container und Expositionen. Gleiche Version + gleiche Eingaben = gleicher Report (PLAN Abschnitt 1.1)."""
    here = Path(__file__).parent
    h = hashlib.sha256()
    for name in ("rules.py", "coverage.py", "scanrun.py", "containers.py", "freshness.py", "eol.py"):
        p = here / name
        if p.is_file():
            h.update(p.read_bytes())
    for row in s.scalars(select(Setting).order_by(Setting.key)):
        if not row.key.startswith(VOLATILE):
            h.update(f"{row.key}={row.value}\n".encode())
    for sid, exp, expo in s.execute(select(System.id, System.expected_containers, System.exposed_containers)
                                    .order_by(System.id)):
        h.update(f"{sid}:{exp}:{expo}\n".encode())
    return h.hexdigest()[:12]
