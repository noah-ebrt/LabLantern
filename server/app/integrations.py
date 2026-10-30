from typing import Literal
import json
import re
import time
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .claude import ClaudeError
from .context import Context
from .guards import Guards
from .mail import MailError, SmtpConfig, send_mail
from .models import put_setting, setting
from . import notify as notify_mod
from .notify import is_valid_url, load_channels, save_channels, scheme_of

CLAUDE_SECRET = "claude.api_key"
CLAUDE_MODEL = "claude-haiku-5-5"   # nur Rückfall, wenn die Modellliste von Anthropic nicht erreichbar ist
MODEL_KEY = "claude.model"           # gewähltes Modell; fehlt = automatisch das neueste Haiku
MODELS_CACHE = "ai.models"           # Modellliste von Anthropic, 24 h zwischengespeichert
RESEARCH_MODEL = "claude-sonnet-5-5"  # Rückfall für die Web-Recherche
LAST_USED_KEY = "ai.last_used"       # letzter Aufruf durch die Frühwarnung
MODELS_TTL = 24 * 3600
_MODEL_ID = re.compile(r"^claude-[a-z0-9.-]{3,80}$")


def claude_client(ctx: Context, key: str):
    from .claude import make_client
    return make_client(ctx.settings.anthropic_base_url, key, ctx.claude_factory)


def fetch_models(ctx: Context, key: str) -> list[dict]:
    """Verfügbare Modelle direkt von Anthropic, neueste zuerst. Wirft ClaudeError (der Aufrufer fällt zurück)."""
    from .claude import list_models
    return [m for m in list_models(claude_client(ctx, key)) if _MODEL_ID.match(m["id"])]


def available_models(ctx: Context, refresh: bool = False) -> list[dict]:
    """Modellliste aus dem Cache; älter als 24 h (oder refresh) wird neu geholt, solange ein Schlüssel da ist."""
    with ctx.session_factory() as s:
        cache = setting(s, MODELS_CACHE) or {}
    key = ctx.secrets.get(CLAUDE_SECRET)
    if key and (refresh or time.time() - cache.get("at", 0) > MODELS_TTL):
        try:
            items = fetch_models(ctx, key)
            cache = {"at": time.time(), "items": items}
            with ctx.session_factory() as s:
                put_setting(s, MODELS_CACHE, cache)
                s.commit()
        except ClaudeError:
            pass   # alte Liste behalten
    return cache.get("items") or []


def latest_haiku(models: list[dict]) -> str:
    haiku = [m for m in models if "haiku" in m["id"]]
    return haiku[0]["id"] if haiku else CLAUDE_MODEL


def latest_sonnet(models: list[dict]) -> str:
    sonnet = [m for m in models if "sonnet" in m["id"]]
    return sonnet[0]["id"] if sonnet else RESEARCH_MODEL


def resolve_model(ctx: Context) -> str:
    """Das Modell für die Frühwarnung: das gewählte, sonst das neueste Haiku laut Anthropic."""
    with ctx.session_factory() as s:
        chosen = setting(s, MODEL_KEY)
    return chosen or latest_haiku(available_models(ctx))
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


class ModelIn(BaseModel):
    model: str | None = Field(default=None, max_length=100)   # None = automatisch das neueste Haiku


class ClaudeIn(BaseModel):
    api_key: str = Field(min_length=20, max_length=400, pattern=r"^[^\s]+$")


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

    # --- Claude API (Frühwarnung, Phase 6) ---

    @router.get("/claude", dependencies=[Depends(guards.require_session)])
    def get_claude():
        meta = ctx.secrets.meta(CLAUDE_SECRET)
        with ctx.session_factory() as s:
            chosen, last = setting(s, MODEL_KEY), setting(s, LAST_USED_KEY)
        models = available_models(ctx)
        return {"configured": meta["set"], "api_key": meta, "model": chosen or latest_haiku(models),
                "selected": chosen, "auto_model": latest_haiku(models), "last_used": last}

    @router.get("/claude/models", dependencies=[Depends(guards.require_session)])
    def get_models(refresh: bool = False):
        models = available_models(ctx, refresh=refresh)
        return {"items": models, "auto": latest_haiku(models)}

    @router.put("/claude/model")
    def put_model(body: ModelIn, found=Depends(guards.require_admin)):
        if body.model is not None and not _MODEL_ID.match(body.model):
            raise HTTPException(422, "Unknown model id")
        with ctx.session_factory() as s:
            put_setting(s, MODEL_KEY, body.model)
            ctx.audit(s, found[0].username, "integration.claude.model", body.model or "automatic (latest Haiku)")
            s.commit()
        return {"ok": True, "model": body.model or latest_haiku(available_models(ctx))}

    @router.put("/claude")
    def put_claude(body: ClaudeIn, found=Depends(guards.require_admin)):
        ctx.secrets.set(CLAUDE_SECRET, body.api_key)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.claude.saved", "API key changed")
            s.commit()
        return {"ok": True}

    @router.delete("/claude")
    def delete_claude(found=Depends(guards.require_admin)):
        ctx.secrets.delete(CLAUDE_SECRET)
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.claude.removed", "API key deleted")
            s.commit()
        return {"ok": True}

    @router.post("/claude/test")
    def test_claude(found=Depends(guards.require_admin)):
        key = ctx.secrets.get(CLAUDE_SECRET)
        if key is None:
            raise HTTPException(409, "No Claude API key configured")
        from .claude import check_key
        result = check_key(claude_client(ctx, key))
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "integration.claude.tested", "ok" if result["ok"] else "error")
            s.commit()
        return result

    return router
