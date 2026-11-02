"""Webhooks der Gesundheitsüberwachung: POST an die eingetragenen URLs, Inhalt baut healthfeed.HealthFeed.

Ereignisse (Header X-Vulnwatch-Event): state_changed, engine_down, engine_up, heartbeat, test. Der Body ist JSON im
Format von /api/health/states plus "event" und "changes". Signiert mit HMAC-SHA256 über "<Zeitstempel>.<Body>"
(X-Vulnwatch-Timestamp, X-Vulnwatch-Signature: sha256=<hex>), so dass ein Empfänger alte Aufrufe verwerfen kann;
X-Vulnwatch-Delivery bleibt bei Wiederholungen gleich. Der Schlüssel wird beim Anlegen einmal angezeigt.
Keine Weiterleitungen: ein Ziel, das umleitet, gilt als Fehler. Fehlschläge werden nach BACKOFF wiederholt."""
import hashlib
import hmac
import logging
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select

from .context import Context
from .models import HealthWebhook

log = logging.getLogger("vulnwatch.health")
TIMEOUT = 5
BACKOFF = (5, 30, 120)   # Sekunden bis zum 2., 3. und 4. Versuch
EVENTS = ("state_changed", "engine_down", "engine_up")   # wählbar je Webhook; heartbeat über heartbeat_min


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


def split_list(value: str) -> list[str]:
    return [x for x in (v.strip() for v in (value or "").split(",")) if x]


@dataclass(frozen=True)
class Target:
    id: int
    events: frozenset[str]    # leer: alle
    only: frozenset[str]      # Host-Schlüssel; leer: alle
    heartbeat_min: int

    def wants(self, event: str) -> bool:
        return not self.events or event in self.events


def targets(ctx: Context) -> list[Target]:
    with ctx.session_factory() as s:
        return [Target(w.id, frozenset(split_list(w.events)), frozenset(split_list(w.monitors)), w.heartbeat_min or 0)
                for w in s.scalars(select(HealthWebhook).order_by(HealthWebhook.id))]


def sign(secret: str, ts: int, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def post(url: str, secret: str, event: str, delivery: str, ts: int, body: bytes) -> str:
    """Ein Zustellversuch; zurück kommt "" bei 2xx, sonst der Fehler."""
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "vulnwatch-webhook",
        "X-Vulnwatch-Event": event, "X-Vulnwatch-Delivery": delivery, "X-Vulnwatch-Timestamp": str(ts),
        "X-Vulnwatch-Signature": sign(secret, ts, body)})
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


def later(delay: float, fn, *args) -> None:
    """Wiederholung ohne einen Thread des Zustell-Pools schlafen zu lassen (Tests ersetzen das)."""
    t = threading.Timer(delay, fn, args)
    t.daemon = True
    t.start()


def deliver(ctx: Context, webhook_id: int, event: str, body: bytes, delivery: str = "", attempt: int = 0,
            submit=None) -> str:
    """Ein Versuch. Schlägt er fehl und ist `submit` (Executor.submit) gegeben, folgt der nächste nach BACKOFF."""
    delivery = delivery or str(uuid.uuid4())
    url, secret = ctx.secrets.get(url_name(webhook_id)), ctx.secrets.get(key_name(webhook_id))
    if not url or not secret:
        return "URL or key missing, add the webhook again"
    error = post(url, secret, event, delivery, int(ctx.clock()), body)
    again = bool(error) and submit is not None and attempt < len(BACKOFF)
    with ctx.session_factory() as s:
        row = s.get(HealthWebhook, webhook_id)
        if row is None:
            return error   # inzwischen entfernt: nicht weiter versuchen
        row.last_sent, row.last_event = ctx.clock(), event
        row.last_error = f"{error} · retry {attempt + 1} of {len(BACKOFF)} follows" if again else error
        s.commit()
    if again:
        later(BACKOFF[attempt], submit, deliver, ctx, webhook_id, event, body, delivery, attempt + 1, submit)
    elif error:
        log.warning("Health webhook %s not delivered (%s): %s", webhook_id, event, error)
    return error
