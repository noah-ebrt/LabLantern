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
from .notify import is_valid_url, load_channels, save_channels, scheme_of

MODEL_KEY = "claude.model"           # alte Modellwahl; nur noch für den Konfigurationsexport (configdoc), gewählt wird unter /api/ai


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
    gets: Literal["both", "report", "alerts"] = "both"


class ChannelGetsIn(BaseModel):
    gets: Literal["both", "report", "alerts"]


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
            send_mail(cfg, ctx.secrets.get(SMTP_PASSWORD_SECRET), "vulnwatch: test mail",
                      "If you can read this, mail delivery from vulnwatch works.")
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
        channels = [{"index": i, "name": c["name"], "scheme": scheme_of(c["url"]), "gets": c["gets"]}
                    for i, c in enumerate(load_channels(ctx))]
        return {"configured": bool(channels), "channels": channels}

    @router.post("/notifications")
    def add_notification(body: NotificationIn, found=Depends(guards.require_admin)):
        url = body.url.strip()
        if not url or "\n" in url or "\r" in url or not is_valid_url(url):
            raise HTTPException(422, "This is not a valid Apprise URL (see the help text for the format)")
        channels = load_channels(ctx)
        if any(c["url"] == url for c in channels):
            raise HTTPException(409, "This channel already exists")
        channels.append({"name": body.name, "url": url, "gets": body.gets})
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
        channels.insert(0, {"name": body.name, "url": url})  # Mail ist der primäre Kanal
        save_channels(ctx, channels)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.added",
                      f"{body.name} (mail {body.host}:{body.port}, password {'set' if body.password else 'empty'})")
            s.commit()
        return {"ok": True}

    @router.put("/notifications/{index}")
    def set_notification_gets(index: int, body: ChannelGetsIn, found=Depends(guards.require_admin)):
        channels = load_channels(ctx)
        if not 0 <= index < len(channels):
            raise HTTPException(404, "Channel not found")
        channels[index]["gets"] = body.gets
        save_channels(ctx, channels)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.changed",
                      f"{channels[index]['name']} gets {body.gets}")
            s.commit()
        return {"ok": True}

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
                [c["url"]], "vulnwatch: test notification",
                "If you can read this, vulnwatch notifications work.")
            if not ok:
                failed.append(c["name"])
        error = f"Delivery failed for: {', '.join(failed)}" if failed else None
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.notifications.tested", "ok" if not failed else error)
            s.commit()
        return {"ok": not failed, "error": error}

    return router
