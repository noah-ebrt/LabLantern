"""FRITZ!Box-Connector: liest per TR-064 die IPv4-Portfreigaben (extern -> interne IP:Port) und ordnet sie wie der
NPM-Connector einem Container oder dem Host zu. Damit sind auch Dienste erfasst, die am Proxy vorbei freigegeben
sind (Spielserver, VPN). Zugang mit einem eigenen FRITZ!Box-Benutzer (Recht „FRITZ!Box Einstellungen“); das
Passwort liegt im Geheimnisspeicher. Gelesen wird nur die Freigabeliste, nie etwas geschrieben.

IPv6-Freigaben liefert TR-064 nicht; solche Dienste bleiben von Hand zu markieren."""
import logging
import re
import time
import urllib.error
import urllib.request
from xml.etree import ElementTree

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .connectors import _URL, PortIndex, _note
from .context import Context
from .guards import Guards
from .models import System, put_setting, setting
from .secrets_store import kept_secret_error

log = logging.getLogger("lablantern.fritzbox")

FRITZ_CONFIG = "fritz.config"
FRITZ_SECRET = "fritz.password"
FRITZ_STATE = "fritz.state"
SERVICE = "urn:dslforum-org:service:WANIPConnection:1"
CONTROL = "/upnp/control/wanipconnection1"
MAX_FORWARDS = 500


class FritzError(Exception):
    pass


def tr064_url(url: str) -> str:
    """TR-064 läuft auf Port 49000 (HTTPS 49443); ohne Port landet der Aufruf in der Weboberfläche (HTTP 404)."""
    url = url.strip().rstrip("/")
    if re.search(r":\d+$", url):
        return url
    return url + (":49443" if url.startswith("https:") else ":49000")


def _soap(opener, base: str, action: str, args: dict | None = None, *, service: str = SERVICE, control: str = CONTROL,
          timeout: float = 10) -> dict[str, str]:
    """Ein TR-064-Aufruf; liefert die Ausgabefelder (NewExternalPort …) als Text."""
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    body = ('<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{inner}</u:{action}></s:Body></s:Envelope>')
    req = urllib.request.Request(base.rstrip("/") + control, data=body.encode(), method="POST",
                                 headers={"Content-Type": 'text/xml; charset="utf-8"', "SoapAction": f"{service}#{action}"})
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(200_000)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise FritzError("FRITZ!Box rejected the login (user needs the right “FRITZ!Box settings”)") from None
        raise FritzError(f"FRITZ!Box answered HTTP {e.code} on {action}") from None
    except (urllib.error.URLError, OSError) as e:
        raise FritzError(f"FRITZ!Box unreachable ({getattr(e, 'reason', e)})") from None
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        raise FritzError(f"FRITZ!Box sent no valid XML on {action}") from None
    return {el.tag.rsplit("}", 1)[-1]: (el.text or "") for el in root.iter() if el.tag.rsplit("}", 1)[-1].startswith("New")}


def digest_opener(url: str, user: str, password: str):
    pw = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pw.add_password(None, url, user, password)
    return urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(pw))


def fetch_forwards(url: str, user: str, password: str) -> list[dict]:
    """Alle IPv4-Portfreigaben: {external_port, protocol, internal_client, internal_port, enabled, description}."""
    url = tr064_url(url)
    opener = digest_opener(url, user, password)
    try:
        count = int(_soap(opener, url, "GetPortMappingNumberOfEntries").get("NewPortMappingNumberOfEntries") or 0)
    except ValueError:
        raise FritzError("FRITZ!Box sent no number of port forwards") from None
    out = []
    for i in range(min(count, MAX_FORWARDS)):
        e = _soap(opener, url, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
        try:
            out.append({"external_port": int(e.get("NewExternalPort") or 0), "protocol": e.get("NewProtocol", ""),
                        "internal_client": e.get("NewInternalClient", ""), "internal_port": int(e.get("NewInternalPort") or 0),
                        "enabled": e.get("NewEnabled") == "1", "description": e.get("NewPortMappingDescription", "")[:100]})
        except ValueError:
            continue
    return out


def match_forwards(s, forwards: list[dict],
                   via: dict[int, dict[str, list[str]]] | None = None) -> tuple[dict[int, list[str]], list[dict]]:
    """{System-ID: [Containername oder HOST]} und die Freigaben ohne eindeutiges Ziel. `via` sammelt die Ports."""
    index = PortIndex(s.scalars(select(System).where(System.status == "active")).all())
    exposed: dict[int, set[str]] = {}
    unmatched = []
    for f in forwards:
        if not f["enabled"]:
            continue
        hit = index.match(f["internal_client"], f["internal_port"])
        if isinstance(hit, tuple):
            exposed.setdefault(hit[0], set()).add(hit[1])
            _note(via, hit[0], hit[1], [f"port {f['external_port']}"])
            continue
        if hit == "no matching container":
            hit = "device is not monitored by lablantern"
        unmatched.append({"forward": f"{f['protocol']} {f['external_port']} → {f['internal_client']}:{f['internal_port']}",
                          "description": f["description"], "reason": hit})
    return {k: sorted(v) for k, v in exposed.items()}, unmatched


def refresh_fritz(ctx: Context) -> dict:
    """Liest die Freigaben und speichert die Zuordnung. Ohne Einrichtung: nichts zu tun (kein Fehler)."""
    from .exposure import last_success

    with ctx.session_factory() as s:
        cfg = setting(s, FRITZ_CONFIG)
    password = ctx.secrets.get(FRITZ_SECRET)
    if not cfg or not password:
        return {"configured": False}
    state = {"configured": True, "at": time.time()}
    try:
        forwards = fetch_forwards(cfg["url"], cfg["user"], password)
        with ctx.session_factory() as s:
            via: dict[int, dict[str, list[str]]] = {}
            exposed, unmatched = match_forwards(s, forwards, via)
        state.update(ok=True, error="", checked_at=state["at"], forwards=len(forwards),
                     exposed={str(k): v for k, v in exposed.items()}, via={str(k): v for k, v in via.items()},
                     unmatched=unmatched[:200])
    except FritzError as e:
        with ctx.session_factory() as s:
            old = setting(s, FRITZ_STATE) or {}
        # alte Zuordnung behalten: ein kurzer Ausfall der Box soll nichts herabstufen
        state.update(ok=False, error=str(e)[:300], forwards=old.get("forwards", 0), exposed=old.get("exposed", {}),
                     via=old.get("via", {}), checked_at=last_success(old), unmatched=old.get("unmatched", []))
        log.warning("FRITZ!Box connector: %s", e)
    with ctx.session_factory() as s:
        put_setting(s, FRITZ_STATE, state)
        s.commit()
    return state


class FritzIn(BaseModel):
    url: str = Field(max_length=300)
    user: str = Field(min_length=1, max_length=100)
    password: str | None = Field(default=None, min_length=1, max_length=512)   # None = unverändert


def build_fritzbox_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/fritzbox", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            cfg = setting(s, FRITZ_CONFIG)
            state = setting(s, FRITZ_STATE) or {}
        return {"config": cfg, "password": ctx.secrets.meta(FRITZ_SECRET), "state": state}

    @router.put("/fritzbox")
    def write(body: FritzIn, found=Depends(guards.require_admin)):
        url = body.url.strip()
        if not _URL.match(url):
            raise HTTPException(422, "URL must look like http://192.168.178.1:49000")
        with ctx.session_factory() as s:
            old = (setting(s, FRITZ_CONFIG) or {}).get("url")
        if body.password is None and (
                err := kept_secret_error(ctx.secrets, FRITZ_SECRET, old, tr064_url(url), "password")):
            raise HTTPException(422, err)
        if body.password is not None:
            ctx.secrets.set(FRITZ_SECRET, body.password)
        with ctx.session_factory() as s:
            put_setting(s, FRITZ_CONFIG, {"url": tr064_url(url), "user": body.user.strip()})
            ctx.audit(s, found[0].username, "connector.fritzbox.saved", url)
            s.commit()
        return {"ok": True}

    @router.delete("/fritzbox")
    def remove(found=Depends(guards.require_admin)):
        ctx.secrets.delete(FRITZ_SECRET)
        with ctx.session_factory() as s:
            for key in (FRITZ_CONFIG, FRITZ_STATE):
                put_setting(s, key, None)
            ctx.audit(s, found[0].username, "connector.fritzbox.removed", "")
            s.commit()
        return {"ok": True}

    @router.post("/fritzbox/test")
    def test(found=Depends(guards.require_admin)):
        state = refresh_fritz(ctx)
        if not state.get("configured"):
            raise HTTPException(409, "FRITZ!Box connector not configured")
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "connector.fritzbox.tested", "ok" if state["ok"] else state["error"])
            s.commit()
        return state

    return router
