"""Webhooks der Gesundheitsüberwachung: bei jedem Zustandswechsel ein POST an die eingetragenen URLs.

Der Body ist JSON mit den Änderungen und dem vollständigen Stand im Format von /api/health/states, damit ein Gerät
nicht nachfragen muss. Signiert mit HMAC-SHA256 über den rohen Body (Header X-Vulnwatch-Signature: sha256=<hex>),
der Schlüssel wird beim Anlegen einmal angezeigt. Keine Weiterleitungen: ein Ziel, das umleitet, gilt als Fehler."""
import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from sqlalchemy import select

from .context import Context
from .models import HealthMonitor, HealthWebhook

log = logging.getLogger("vulnwatch.health")
TIMEOUT = 5
RETRY_AFTER = 5


def url_name(webhook_id: int) -> str:
    return f"health.webhook.{webhook_id}.url"


def key_name(webhook_id: int) -> str:
    return f"health.webhook.{webhook_id}.secret"


def check_url(url: str) -> str:
    """Nur http(s) mit Host; zurück kommt die Anzeige ohne Pfad und Zugangsdaten."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("URL must start with http:// or https:// and name a host")
    if parts.username or parts.password:
        raise ValueError("Put credentials in the path or query, not before the host")
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def post(url: str, secret: str, event: str, body: bytes) -> str:
    """Ein Zustellversuch; zurück kommt "" bei 2xx, sonst der Fehler."""
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "vulnwatch-webhook",
        "X-Vulnwatch-Event": event, "X-Vulnwatch-Signature": sign(secret, body)})
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            return "" if 200 <= r.status < 300 else f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        e.close()
        return f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return str(e.reason)[:200]
    except OSError as e:
        return str(e)[:200]


def document(ctx: Context, event: str, changes: list[dict], engine_ok: bool) -> bytes:
    with ctx.session_factory() as s:
        monitors = s.scalars(select(HealthMonitor).order_by(HealthMonitor.name)).all()
        doc = {"event": event, "ts": int(ctx.clock()), "changes": changes, "engine_ok": engine_ok,
               "states": {m.slug: "paused" if m.paused else m.state if engine_ok else "unknown" for m in monitors},
               "critical": [m.slug for m in monitors if m.critical]}
    return json.dumps(doc, separators=(",", ":")).encode()


def change(m: HealthMonitor, prev: str, state: str) -> dict:
    return {"slug": m.slug, "name": m.name, "state": state, "prev": prev, "critical": bool(m.critical)}


def deliver(ctx: Context, webhook_id: int, event: str, body: bytes, retry: bool = True) -> str:
    url, secret = ctx.secrets.get(url_name(webhook_id)), ctx.secrets.get(key_name(webhook_id))
    if not url or not secret:
        return "URL or key missing, add the webhook again"
    error = post(url, secret, event, body)
    if error and retry:
        time.sleep(RETRY_AFTER)
        error = post(url, secret, event, body)
    with ctx.session_factory() as s:
        row = s.get(HealthWebhook, webhook_id)
        if row is not None:
            row.last_sent, row.last_error = ctx.clock(), error
            s.commit()
    if error:
        log.warning("Health webhook %s not delivered: %s", webhook_id, error)
    return error


def send_all(ctx: Context, executor, changes: list[dict], engine_ok: bool) -> None:
    """Jeder Webhook im eigenen Auftrag, damit ein hängendes Ziel die anderen nicht aufhält."""
    with ctx.session_factory() as s:
        ids = s.scalars(select(HealthWebhook.id)).all()
    if not ids:
        return
    body = document(ctx, "health.changed", changes, engine_ok)
    for webhook_id in ids:
        executor.submit(deliver, ctx, webhook_id, "health.changed", body)
