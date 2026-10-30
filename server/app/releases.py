"""Signierte Agent-Releases dieser Installation. agent-build baut die Pakete aus agent/, agent-sign signiert sie mit
dem Schlüssel der Installation und legt sie in agent_releases_dir ab (deploy/compose.yaml). Der Server sieht den
privaten Schlüssel nie: Er prüft Signatur und Prüfsummen und übernimmt ein Release erst dann. Die Agenten prüfen
dieselbe Signatur gegen den Schlüssel, mit dem sie gebaut wurden; ein übernommener Server kann deshalb kein
Agent-Binary unterschieben."""
import base64
import hashlib
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends

from .context import Context
from .guards import Guards
from .models import put_setting, setting

log = logging.getLogger("vulnwatch.releases")

CURRENT_KEY = "releases.current"
MAX_FILE = 200 * 1024 * 1024


class ReleaseError(Exception):
    pass


def _version(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in (v or "0").split("."))


def _get_setting(ctx: Context, key: str) -> dict | None:
    with ctx.session_factory() as s:
        return setting(s, key)


def _set_setting(ctx: Context, key: str, value: dict) -> None:
    with ctx.session_factory() as s:
        put_setting(s, key, value)
        s.commit()


def current_release(ctx: Context) -> dict | None:
    return _get_setting(ctx, CURRENT_KEY)


def _read(path: Path) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(MAX_FILE)
    except FileNotFoundError:
        raise ReleaseError(f"release file missing: {path.name}") from None
    except OSError:
        raise ReleaseError(f"release file unreadable: {path.name}") from None


def sync_latest_release(ctx: Context) -> str | None:
    """Übernimmt das neueste Release aus agent-sign, wenn es neuer ist oder einen anderen Schlüssel hat, und prüft es
    vorher vollständig. Liefert die ausgelieferte Version."""
    src = ctx.settings.agent_releases_dir
    if not src or not (src / "latest.json").is_file():
        raise ReleaseError("no agent built yet")
    try:
        latest = json.loads(_read(src / "latest.json"))
        pub = _read(src / "release.pub").decode().strip()
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub))
    except (ValueError, AttributeError):
        raise ReleaseError("latest release: description or public key invalid") from None
    newest = str(latest.get("version", ""))
    if not re.fullmatch(r"\d+\.\d+\.\d+", newest):
        raise ReleaseError("latest release: version invalid")
    current = current_release(ctx)
    if current and current.get("public_key") == pub and _version(newest) <= _version(current["version"]):
        return current["version"]
    rel = src / newest
    manifest_raw = _read(rel / "manifest.json")
    sig = _read(rel / "manifest.json.sig")
    try:
        key.verify(base64.b64decode(sig.strip()), manifest_raw)
    except (InvalidSignature, ValueError):
        raise ReleaseError(f"release {newest}: signature invalid") from None
    manifest = json.loads(manifest_raw)
    if manifest.get("version") != newest or not manifest.get("files"):
        raise ReleaseError(f"release {newest}: manifest invalid")

    target = ctx.settings.data_dir / "agent-releases" / newest
    tmp = target.with_name(newest + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    for name, sha in manifest["files"].items():
        if "/" in name or not name.startswith("vulnwatch-agent"):
            shutil.rmtree(tmp, ignore_errors=True)
            raise ReleaseError(f"release {newest}: unexpected file {name}")
        data = _read(rel / name)
        if hashlib.sha256(data).hexdigest() != sha:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ReleaseError(f"release {newest}: checksum mismatch for {name}")
        (tmp / name).write_bytes(data)
    (tmp / "manifest.json").write_bytes(manifest_raw)
    (tmp / "manifest.json.sig").write_bytes(sig)
    shutil.rmtree(target, ignore_errors=True)
    tmp.rename(target)
    _set_setting(ctx, CURRENT_KEY, {"version": newest, "dir": str(target), "public_key": pub,
                                    "built": latest.get("built")})
    log.info("Agent release %s verified and active", newest)
    return newest


STATUS_KEY = "releases.last_check"


def _hint(error: str | None) -> str | None:
    """Was der Admin tun muss, in einem Satz."""
    if not error:
        return None
    if "no agent built" in error:
        return ("The agent is built when the stack starts. Run docker compose up -d --build in deploy/, then check "
                "docker compose logs agent-build agent-sign.")
    if "signature" in error or "checksum" in error:
        return "The release failed verification and was NOT installed. Rebuild it with docker compose up -d --build."
    return None


def check_releases(ctx: Context) -> dict:
    """Sieht nach einem neuen Release und merkt sich das Ergebnis für die Oberfläche."""
    try:
        status = {"ok": True, "version": sync_latest_release(ctx), "error": None}
    except ReleaseError as e:
        status = {"ok": False, "version": None, "error": str(e)}
    status.update(at=datetime.now(timezone.utc).isoformat(), hint=_hint(status["error"]))
    _set_setting(ctx, STATUS_KEY, status)
    return status


def build_releases_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/releases", dependencies=[Depends(guards.require_session)])
    def read():
        cur = current_release(ctx) or {}
        return {"current_version": cur.get("version"), "built": cur.get("built"), "public_key": cur.get("public_key"),
                "last_check": _get_setting(ctx, STATUS_KEY)}

    @router.post("/releases/sync")
    def sync(found=Depends(guards.require_admin)):
        return check_releases(ctx)

    return router
