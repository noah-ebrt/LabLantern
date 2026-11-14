import json
import logging
from urllib.parse import parse_qsl, urlsplit

import apprise
from apprise import NotifyFormat

from .context import Context
from .models import put_setting, setting

log = logging.getLogger("lablantern.notify")
NOTIFY_SECRET_KEY = "notifications.urls"
MAIL_SCHEMES = ("mailto", "mailtos")
DEFAULTS_KEY = "notifications.defaults"
NTFY_SCHEMES = ("ntfy", "ntfys")

# Arten von Benachrichtigungen. Die Vorgabe sagt, was überhaupt rausgeht; jeder Kanal kann einzelne Arten
# ein- oder ausschalten (überschreiben), alles andere folgt der Vorgabe. ntfy-Priorität je Art: Ausfälle klingeln.
EVENTS = {
    "report": {"label": "Scan reports", "hint": "Result of the scheduled and manual runs", "priority": "low"},
    "alert": {"label": "Scan alerts", "hint": "Critical findings, failed runs, red canary", "priority": "high"},
    "outage": {"label": "Outages", "hint": "Monitored hosts going down and coming back", "priority": "urgent"},
    "early_warning": {"label": "Early warnings", "hint": "New advisories that match your systems", "priority": "high"},
    "service": {"label": "LabLantern problems", "hint": "Feeds or the early warning service failing", "priority": "default"},
    "coverage": {"label": "Coverage checks", "hint": "Exploited issues the early warning missed", "priority": "low"},
}
# Ältere Kanäle kannten nur report/alerts/both
_GETS_OFF = {"report": [e for e in EVENTS if e not in ("report", "coverage")], "alerts": ["report", "coverage"]}


def events_from_gets(gets: str | None) -> dict[str, bool]:
    return {e: False for e in _GETS_OFF.get(gets or "", [])}


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
            out.append({"name": f"Channel {i}", "url": item, "enabled": True, "events": {}})
        elif isinstance(item, dict) and item.get("url"):
            events = item.get("events") if isinstance(item.get("events"), dict) else events_from_gets(item.get("gets"))
            out.append({"name": str(item.get("name") or f"Channel {i}"), "url": item["url"],
                        "enabled": item.get("enabled") is not False,
                        "events": {k: bool(v) for k, v in events.items() if k in EVENTS and v is not None}})
    return out


def load_channels(ctx: Context) -> list[dict]:
    return _channels_from(ctx.secrets.get(NOTIFY_SECRET_KEY))


def save_channels(ctx: Context, channels: list[dict]) -> None:
    if channels:
        ctx.secrets.set(NOTIFY_SECRET_KEY, json.dumps(channels))
    else:
        ctx.secrets.delete(NOTIFY_SECRET_KEY)


def load_defaults(ctx: Context) -> dict[str, bool]:
    with ctx.session_factory() as s:
        stored = setting(s, DEFAULTS_KEY) or {}
    return {e: stored.get(e, True) is not False for e in EVENTS}


def save_defaults(ctx: Context, values: dict[str, bool]) -> dict[str, bool]:
    merged = {**load_defaults(ctx), **{k: bool(v) for k, v in values.items() if k in EVENTS}}
    with ctx.session_factory() as s:
        put_setting(s, DEFAULTS_KEY, merged)
        s.commit()
    return merged


def channel_gets(channel: dict, event: str, defaults: dict[str, bool]) -> bool:
    return channel["enabled"] and channel["events"].get(event, defaults.get(event, True))


def load_notification_urls(ctx: Context, kind: str | None = None) -> list[str]:
    """Alle Kanal-URLs, mit `kind` (eine Art aus EVENTS) nur die eingeschalteten Kanäle, die diese Art bekommen."""
    channels = load_channels(ctx)
    if kind is None:
        return [c["url"] for c in channels]
    defaults = load_defaults(ctx)
    return [_with_priority(c["url"], kind) for c in channels if channel_gets(c, kind, defaults)]


def _with_priority(url: str, kind: str) -> str:
    """ntfy bekommt die Priorität der Art, es sei denn, die URL nennt selbst eine."""
    if scheme_of(url) not in NTFY_SCHEMES or kind not in EVENTS:
        return url
    if any(k == "priority" for k, _ in parse_qsl(urlsplit(url).query)):
        return url
    return f"{url}{'&' if '?' in url else '?'}priority={EVENTS[kind]['priority']}"


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
    """Standard-Kanal des Servers: die in der Oberfläche hinterlegten Apprise-URLs, die diese Art bekommen.

    Ohne eigene HTML-Vorlage bekommt Mail den Klartext im gemeinsamen Rahmen, damit jede Mail gleich aussieht."""
    urls = load_notification_urls(ctx, kind)
    if not urls:
        if load_channels(ctx):
            return False, f"No channel gets {EVENTS.get(kind, {}).get('label', kind).lower()}"
        return False, "No notification channels configured"
    if html is None and any(scheme_of(u) in MAIL_SCHEMES for u in urls):
        from .mailtpl import notice_html
        html = notice_html(title, body, kind)
    return send_notification(urls, title, body, html)
