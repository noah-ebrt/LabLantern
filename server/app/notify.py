import json
import logging
import apprise
from apprise import NotifyFormat

from .context import Context

log = logging.getLogger("lablantern.notify")
NOTIFY_SECRET_KEY = "notifications.urls"
MAIL_SCHEMES = ("mailto", "mailtos")
# Was ein Kanal bekommt: den regelmäßigen Bericht, Alarme (Sofort-Alarm, Alarm, Fehler, Frühwarnung) oder beides
GETS = ("both", "report", "alerts")


def scheme_of(url: str) -> str:
    return url.split("://", 1)[0].lower() if "://" in url else ""


def is_valid_url(url: str) -> bool:
    """Prüft nur das Format (kein Netzwerkzugriff)."""
    return bool(scheme_of(url)) and apprise.Apprise().add(url)


def _channels_from(raw: str | None) -> list[dict]:
    """Gespeichert wird eine JSON-Liste aus {name, url}. Ältere Stände (Liste aus Strings oder Zeilen) lesen wir mit."""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = [line.strip() for line in raw.splitlines() if line.strip()]
    if not isinstance(data, list):
        data = [raw]
    out = []
    for i, item in enumerate(data, 1):
        if isinstance(item, str):
            out.append({"name": f"Channel {i}", "url": item, "gets": "both"})
        elif isinstance(item, dict) and item.get("url"):
            gets = item.get("gets") if item.get("gets") in GETS else "both"
            out.append({"name": str(item.get("name") or f"Channel {i}"), "url": item["url"], "gets": gets})
    return out


def load_channels(ctx: Context) -> list[dict]:
    return _channels_from(ctx.secrets.get(NOTIFY_SECRET_KEY))


def save_channels(ctx: Context, channels: list[dict]) -> None:
    if channels:
        ctx.secrets.set(NOTIFY_SECRET_KEY, json.dumps(channels))
    else:
        ctx.secrets.delete(NOTIFY_SECRET_KEY)


def load_notification_urls(ctx: Context, kind: str | None = None) -> list[str]:
    """Alle Kanal-URLs, mit `kind` ("report" oder "alert") nur die Kanäle, die diese Art bekommen."""
    wanted = {"report": ("both", "report"), "alert": ("both", "alerts")}.get(kind, GETS)
    return [c["url"] for c in load_channels(ctx) if c["gets"] in wanted]


def send_notification(urls: list[str], title: str, body: str, html: str | None = None) -> tuple[bool, str | None]:
    """Versendet eine Benachrichtigung über alle konfigurierten Apprise-URLs.

    Mail bekommt die HTML-Vorlage, alle anderen Kanäle den Klartext. Das Format wird immer genannt: Ohne Angabe
    behandelt der Mail-Plugin Klartext als HTML und verschluckt jeden Zeilenumbruch."""
    if not urls:
        return False, "No notification channels configured"

    mail, other = apprise.Apprise(), apprise.Apprise()
    valid_count = 0
    for u in urls:
        target = mail if html and scheme_of(u) in MAIL_SCHEMES else other
        if target.add(u):
            valid_count += 1
        else:
            log.warning("Invalid Apprise URL (%s://…) skipped", scheme_of(u) or "?")

    if valid_count == 0:
        return False, "No valid notification channels found"

    success = True
    if len(mail):
        success &= bool(mail.notify(title=title, body=html, body_format=NotifyFormat.HTML))
    if len(other):
        success &= bool(other.notify(title=title, body=body, body_format=NotifyFormat.TEXT))
    if success:
        return True, None
    return False, "Delivery to at least one channel failed"


def notify_via_apprise(ctx: Context, title: str, body: str, html: str | None = None,
                       kind: str = "report") -> tuple[bool, str | None]:
    """Standard-Kanal des Servers: die in der Oberfläche hinterlegten Apprise-URLs, die diese Art bekommen."""
    return send_notification(load_notification_urls(ctx, kind), title, body, html)
