from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .context import Context
from .guards import Guards
from .mail import MailError, SmtpConfig, send_mail
from .models import put_setting, setting
from . import notify as notify_mod
from .notify import (EVENTS, events_from_gets, is_valid_url, load_channels, load_defaults, save_channels,
                     save_defaults, scheme_of)

SMTP_CONFIG_KEY = "smtp.config"
SMTP_PASSWORD_SECRET = "smtp.password"
_ADDR = r"^[^\s@<>\r\n]+@[^\s@<>\r\n]+\.[^\s@<>\r\n]+$"


class SmtpIn(BaseModel):
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9._:-]+$")
    port: int = Field(ge=1, le=65535)
    security: Literal["none", "starttls", "ssl"]
    username: str = Field(default="", max_length=256)
    from_addr: str = Field(max_length=254, pattern=_ADDR)
    to_addr: str = Field(max_length=254, pattern=_ADDR)
    # None = Passwort unverändert lassen. Der Wert kommt nie wieder aus der API heraus.
    password: str | None = Field(default=None, min_length=1, max_length=512)


class NotificationIn(BaseModel):
    name: str = Field(min_length=1, max_length=60, pattern=r"^[^\r\n\t]+$")
    url: str = Field(max_length=2000)  # bewusst ohne Muster: Fehlermeldungen von Pydantic würden die URL wiederholen
    enabled: bool = True
    events: dict[str, bool] = {}
    gets: Literal["both", "report", "alerts"] | None = None  # ältere Konfig-Dokumente


EventId = Literal[tuple(EVENTS)]  # type: ignore[valid-type]


class ChannelIn(BaseModel):
    """Ein Kanal: an/aus und je Art an/aus; eine Art, die fehlt (oder null ist), folgt der Vorgabe."""
    enabled: bool | None = None
    events: dict[EventId, bool | None] | None = None
    gets: Literal["both", "report", "alerts"] | None = None  # ältere Konfig-Dokumente


class DefaultsIn(BaseModel):
    defaults: dict[EventId, bool]


class NtfyChannelIn(BaseModel):
    name: str = Field(default="Push (ntfy)", min_length=1, max_length=60, pattern=r"^[^\r\n\t]+$")
    server: str = Field(default="ntfy.sh", max_length=253, pattern=r"^(https?://)?[A-Za-z0-9.-]+(:\d{1,5})?/?$")
    topic: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    token: str = Field(default="", max_length=256, pattern=r"^[A-Za-z0-9_.-]*$")
    username: str = Field(default="", max_length=128)
    password: str = Field(default="", max_length=256)


def ntfy_apprise_url(c: NtfyChannelIn) -> str:
    """ntfy über Apprise: Zugangs-Token (tk_…) oder Benutzer/Passwort, sonst offen. http:// nur, wenn so eingegeben."""
    server = c.server.strip().rstrip("/")
    scheme = "ntfy" if server.startswith("http://") else "ntfys"
    host = server.split("://", 1)[-1]
    q = lambda v: quote(v, safe="")  # noqa: E731
    auth = f"{q(c.token)}@" if c.token else f"{q(c.username)}:{q(c.password)}@" if c.username else ""
    return f"{scheme}://{auth}{host}/{c.topic}"


class SmtpChannelIn(BaseModel):
    name: str = Field(default="Mail", min_length=1, max_length=60, pattern=r"^[^\r\n\t]+$")
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    port: int = Field(ge=1, le=65535)
    security: Literal["starttls", "ssl", "none"]
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=512)
    from_addr: str = Field(max_length=254, pattern=_ADDR)
    to_addr: str = Field(max_length=254, pattern=_ADDR)


def smtp_apprise_url(c: SmtpChannelIn) -> str:
    """Baut die Apprise-Mail-URL. Alles wird kodiert, damit Sonderzeichen im Passwort die URL nicht zerlegen."""
    q = lambda v: quote(v, safe="")  # noqa: E731
    scheme = "mailto" if c.security == "none" else "mailtos"
    auth = f"{q(c.username)}:{q(c.password)}@" if c.username else ""
    params = f"smtp={q(c.host)}&from={q(c.from_addr)}&to={q(c.to_addr)}"
    if c.security != "none":
        params += f"&mode={c.security}"
    return f"{scheme}://{auth}{c.host}:{c.port}?{params}"


def load_smtp_config(s: Session) -> SmtpConfig | None:
    value = setting(s, SMTP_CONFIG_KEY)
    return SmtpConfig(**value) if value else None


def build_integrations_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/integrations")

    @router.get("/smtp", dependencies=[Depends(guards.require_session)])
    def get_smtp():
        with ctx.session_factory() as s:
            cfg = load_smtp_config(s)
        body = {"configured": cfg is not None, "password": ctx.secrets.meta(SMTP_PASSWORD_SECRET)}
        if cfg:
            body.update(host=cfg.host, port=cfg.port, security=cfg.security, username=cfg.username,
                        from_addr=cfg.from_addr, to_addr=cfg.to_addr)
        return body

    @router.put("/smtp")
    def put_smtp(body: SmtpIn, found=Depends(guards.require_admin)):
        user = found[0]
        new = SmtpConfig(**body.model_dump(exclude={"password"}))
        with ctx.session_factory() as s:
            old = load_smtp_config(s)
            # gespeichertes Passwort nie an einen anderen Server (oder ohne die bisherige Verschlüsselung) schicken
            if (body.password is None and old is not None and ctx.secrets.meta(SMTP_PASSWORD_SECRET)["set"]
                    and (old.host.lower(), old.port, old.security) != (new.host.lower(), new.port, new.security)):
                raise HTTPException(422, "The server changed: enter the password again "
                                         "(a stored password is never sent to a new server)")
            changed = [k for k, v in new.__dict__.items() if old is None or getattr(old, k) != v]
            if body.password is not None:
                changed.append("password changed")
            put_setting(s, SMTP_CONFIG_KEY, new.__dict__)
            ctx.audit(s, user.username, "integration.smtp.saved", ", ".join(changed) or "no change")
            s.commit()
        if body.password is not None:
            ctx.secrets.set(SMTP_PASSWORD_SECRET, body.password)
        return {"ok": True}

    @router.post("/smtp/test")
    def test_smtp(found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            cfg = load_smtp_config(s)
        if cfg is None:
            raise HTTPException(409, "SMTP is not set up yet")
        result = {"ok": True}
        try:
            send_mail(cfg, ctx.secrets.get(SMTP_PASSWORD_SECRET), "LabLantern: test mail",
                      "If you can read this, mail delivery from LabLantern works.")
        except MailError as e:
            result = {"ok": False, "error": str(e)}
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.smtp.tested", "ok" if result["ok"] else "error")
            s.commit()
        return result

    # --- Benachrichtigungen (Apprise: Mail und Push) ---
    # Kanäle werden mit Namen angelegt. Die URL enthält oft das Geheimnis (Bot-Token, Webhook-Token) und
    # wird deshalb nie ausgegeben, auch nicht maskiert: Die Oberfläche kennt nur Name und Typ.

    @router.get("/notifications", dependencies=[Depends(guards.require_session)])
    def get_notifications():
        channels = [{"index": i, "name": c["name"], "scheme": scheme_of(c["url"]), "enabled": c["enabled"],
                     "events": c["events"]} for i, c in enumerate(load_channels(ctx))]
        events = [{"id": k, "label": v["label"], "hint": v["hint"]} for k, v in EVENTS.items()]
        return {"configured": bool(channels), "channels": channels, "events": events, "defaults": load_defaults(ctx)}

    @router.put("/notifications/defaults")
    def set_notification_defaults(body: DefaultsIn, found=Depends(guards.require_admin)):
        merged = save_defaults(ctx, body.defaults)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.defaults",
                      "off: " + (", ".join(k for k, v in merged.items() if not v) or "none"))
            s.commit()
        return {"ok": True, "defaults": merged}

    @router.post("/notifications")
    def add_notification(body: NotificationIn, found=Depends(guards.require_admin)):
        url = body.url.strip()
        if not url or "\n" in url or "\r" in url or not is_valid_url(url):
            raise HTTPException(422, "This is not a valid Apprise URL (see the help text for the format)")
        channels = load_channels(ctx)
        if any(c["url"] == url for c in channels):
            raise HTTPException(409, "This channel already exists")
        events = body.events if body.gets is None else events_from_gets(body.gets)
        channels.append({"name": body.name, "url": url, "enabled": body.enabled,
                         "events": {k: bool(v) for k, v in events.items() if k in EVENTS}})
        save_channels(ctx, channels)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.added", f"{body.name} ({scheme_of(url)})")
            s.commit()
        return {"ok": True}

    @router.post("/notifications/smtp")
    def add_smtp_channel(body: SmtpChannelIn, found=Depends(guards.require_admin)):
        url = smtp_apprise_url(body)
        if not is_valid_url(url):
            raise HTTPException(422, "These details do not form a valid mail configuration")
        channels = [c for c in load_channels(ctx) if c["url"] != url]
        channels.insert(0, {"name": body.name, "url": url, "enabled": True, "events": {}})  # Mail ist der primäre Kanal
        save_channels(ctx, channels)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.added",
                      f"{body.name} (mail {body.host}:{body.port}, password {'set' if body.password else 'empty'})")
            s.commit()
        return {"ok": True}

    @router.post("/notifications/ntfy")
    def add_ntfy_channel(body: NtfyChannelIn, found=Depends(guards.require_admin)):
        url = ntfy_apprise_url(body)
        if not is_valid_url(url):
            raise HTTPException(422, "These details do not form a valid ntfy configuration")
        channels = load_channels(ctx)
        if any(c["url"] == url for c in channels):
            raise HTTPException(409, "This channel already exists")
        channels.append({"name": body.name, "url": url, "enabled": True, "events": {}})
        save_channels(ctx, channels)
        auth = "token" if body.token else "login" if body.username else "open topic"
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.added", f"{body.name} (ntfy, {auth})")
            s.commit()
        return {"ok": True}

    @router.put("/notifications/{index}")
    def set_notification_channel(index: int, body: ChannelIn, found=Depends(guards.require_admin)):
        channels = load_channels(ctx)
        if not 0 <= index < len(channels):
            raise HTTPException(404, "Channel not found")
        ch = channels[index]
        if body.enabled is not None:
            ch["enabled"] = body.enabled
        if body.gets is not None:
            ch["events"] = events_from_gets(body.gets)
        for k, v in (body.events or {}).items():
            if v is None:
                ch["events"].pop(k, None)
            else:
                ch["events"][k] = v
        save_channels(ctx, channels)
        own = ", ".join(f"{k} {'on' if v else 'off'}" for k, v in ch["events"].items()) or "defaults"
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.changed",
                      f"{ch['name']}: {'on' if ch['enabled'] else 'off'}, {own}")
            s.commit()
        return {"ok": True}

    @router.post("/notifications/{index}/test")
    def test_notification_channel(index: int, found=Depends(guards.require_admin)):
        channels = load_channels(ctx)
        if not 0 <= index < len(channels):
            raise HTTPException(404, "Channel not found")
        ok, err = notify_mod.send_notification([channels[index]["url"]], "LabLantern: test notification",
                                               "If you can read this, this LabLantern channel works.")
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.tested",
                      f"{channels[index]['name']}: {'ok' if ok else err}")
            s.commit()
        return {"ok": ok, "error": None if ok else f"Delivery to {channels[index]['name']} failed"}

    @router.delete("/notifications/{index}")
    def remove_notification(index: int, found=Depends(guards.require_admin)):
        channels = load_channels(ctx)
        if not 0 <= index < len(channels):
            raise HTTPException(404, "Channel not found")
        gone = channels.pop(index)
        save_channels(ctx, channels)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.removed", f"{gone['name']} ({scheme_of(gone['url'])})")
            s.commit()
        return {"ok": True}

    @router.post("/notifications/test")
    def test_notifications(found=Depends(guards.require_admin)):
        channels = load_channels(ctx)
        if not channels:
            raise HTTPException(409, "No notification channels configured")
        failed = []
        for c in channels:
            ok, _err = notify_mod.send_notification(
                [c["url"]], "LabLantern: test notification",
                "If you can read this, LabLantern notifications work.")
            if not ok:
                failed.append(c["name"])
        error = f"Delivery failed for: {', '.join(failed)}" if failed else None
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.tested", "ok" if not failed else error)
            s.commit()
        return {"ok": not failed, "error": error}

    return router
