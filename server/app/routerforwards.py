"""Portfreigaben aus OPNsense und UniFi (PLAN-extensions D2), als Expositionsquellen wie die FRITZ!Box: die Regeln
lesen, auf das Format von fritzbox.fetch_forwards bringen und mit fritzbox.match_forwards einem Container oder Host
zuordnen. Nur HTTPS, das Zertifikat wird beim Speichern gepinnt wie bei den Geräten in appliances.py.

API-Stand (Recherche 2026-10-31, nicht an echten Geräten geprüft):
- OPNsense: Portfreigaben gibt es über die API erst ab 26.1 („Port forward“ wurde dort zu „Destination NAT“ (MVC)):
  GET /api/firewall/d_nat/search_rule, Key und Secret als HTTP Basic. OPNsense vergibt Rechte je Seite, ohne
  Trennung von Lesen und Schreiben: der Benutzer bekommt nur das Recht für Destination NAT, mehr nicht.
- UniFi: klassische Network-API auf einer UniFi-OS-Konsole, GET /proxy/network/api/s/<site>/rest/portforward mit
  einem API-Key (Kopfzeile X-API-KEY, Network 9 und neuer). Ob ein Key nur lesen darf, hängt am Admin, der ihn
  anlegt: dafür einen Admin mit der Rolle „View Only“ nehmen.
pfSense hat keine solche API und ist nicht gebaut."""
import base64
import http.client
import ipaddress
import json
import logging
import ssl
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .appliances import TIMEOUT, ApplianceError, _check_pin, _split, _unverified, read_fingerprint
from .connectors import _URL
from .context import Context
from .fritzbox import match_forwards
from .guards import Guards
from .models import put_setting, setting

log = logging.getLogger("vulnwatch.routerforwards")

MAX_BYTES = 5_000_000
MAX_FORWARDS = 500
WELL_KNOWN = {"http": 80, "https": 443, "ssh": 22, "smtp": 25, "imap": 143, "imaps": 993, "ftp": 21}


def _get(url: str, fingerprint: str, path: str, headers: dict, label: str, hints: dict[int, str]):
    _, host, port = _split(url)
    conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=_unverified())
    try:
        conn.connect()
        _check_pin(conn.sock, fingerprint)
        conn.request("GET", path, headers={**headers, "User-Agent": "vulnwatch", "Accept": "application/json"})
        r = conn.getresponse()
        status, body = r.status, r.read(MAX_BYTES)
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        raise ApplianceError(f"{label} unreachable ({e})") from None
    finally:
        conn.close()
    if status != 200:
        raise ApplianceError(hints.get(status, f"{label} answered HTTP {status}"))
    try:
        return json.loads(body)
    except ValueError:
        raise ApplianceError(f"{label} sent no JSON") from None


def _port(value) -> int | None:
    """Erster Port einer Angabe wie 443, "8000-8010" oder "https"; Aliasnamen bleiben unaufgelöst (None)."""
    text = str(value or "").strip().lower()
    first = text.split("-")[0].split(":")[0]
    if first.isdigit() and 0 < int(first) < 65536:
        return int(first)
    return WELL_KNOWN.get(first)


def _forward(external, client, internal, protocol: str, enabled: bool, description: str) -> dict:
    ext, local = _port(external), _port(internal) if str(internal or "").strip() else _port(external)
    out = {"external_port": ext if ext is not None else str(external), "internal_client": str(client or ""),
           "internal_port": local if local is not None else str(internal or external), "protocol": protocol,
           "enabled": enabled, "description": str(description or "")[:200]}
    try:
        ipaddress.ip_address(out["internal_client"])
    except ValueError:
        out["problem"] = "target is an alias or host name, not resolved: mark the service by hand"
    if ext is None or local is None:
        out["problem"] = "port is an alias, not resolved: mark the service by hand"
    return out


def parse_opnsense(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows[:MAX_FORWARDS]:
        if str(r.get("nordr", "0")) == "1":   # „no redirect“: Ausnahme, keine Weiterleitung
            continue
        dest = r.get("destination") if isinstance(r.get("destination"), dict) else {}
        out.append(_forward(r.get("destination.port") or dest.get("port"), r.get("target"), r.get("local-port"),
                            str(r.get("protocol") or "TCP").upper(), str(r.get("disabled", "0")) != "1",
                            r.get("descr") or r.get("description")))
    return out


def parse_unifi(rows: list[dict]) -> list[dict]:
    protocols = {"tcp": "TCP", "udp": "UDP", "tcp_udp": "TCP/UDP"}
    return [_forward(r.get("dst_port"), r.get("fwd"), r.get("fwd_port"), protocols.get(r.get("proto"), "TCP/UDP"),
                     bool(r.get("enabled")), r.get("name")) for r in rows[:MAX_FORWARDS]]


def fetch_opnsense(cfg: dict, secret: str) -> list[dict]:
    auth = base64.b64encode(f"{cfg['key']}:{secret}".encode()).decode()
    data = _get(cfg["url"], cfg["fingerprint"], "/api/firewall/d_nat/search_rule?current=1&rowCount=-1",
                {"Authorization": f"Basic {auth}"}, "OPNsense",
                {401: "OPNsense rejected the API key and secret",
                 403: "OPNsense rejected the request: the user needs the privilege for Firewall: NAT: Destination NAT",
                 404: "no port forward API: OPNsense 26.1 or newer is needed"})
    if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
        raise ApplianceError("unexpected answer from OPNsense")
    return parse_opnsense(data["rows"])


def fetch_unifi(cfg: dict, secret: str) -> list[dict]:
    data = _get(cfg["url"], cfg["fingerprint"], f"/proxy/network/api/s/{quote(cfg.get('site') or 'default')}/rest/portforward",
                {"X-API-KEY": secret}, "UniFi",
                {401: "UniFi rejected the API key", 403: "UniFi rejected the API key",
                 404: "no UniFi Network API at this address or site: a UniFi OS console with Network 9 or newer is needed"})
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise ApplianceError("unexpected answer from UniFi")
    return parse_unifi(data["data"])


@dataclass(frozen=True)
class Router:
    kind: str
    label: str
    fetch: Callable[[dict, str], list[dict]]

    @property
    def config_key(self) -> str:
        return f"{self.kind}.config"

    @property
    def secret_key(self) -> str:
        return f"{self.kind}.secret"

    @property
    def state_key(self) -> str:
        return f"{self.kind}.state"


ROUTERS = {"opnsense": Router("opnsense", "OPNsense", fetch_opnsense), "unifi": Router("unifi", "UniFi", fetch_unifi)}


def _describe(f: dict) -> str:
    return f"{f['protocol']} {f['external_port']} → {f['internal_client']}:{f['internal_port']}"


def refresh_router(ctx: Context, kind: str) -> dict:
    """Wie refresh_fritz: ohne Einrichtung nichts zu tun, bei einem Fehler bleibt die letzte Zuordnung stehen."""
    from .exposure import last_success

    router = ROUTERS[kind]
    with ctx.session_factory() as s:
        cfg = setting(s, router.config_key)
    secret = ctx.secrets.get(router.secret_key)
    if not cfg or not secret:
        return {"configured": False}
    state = {"configured": True, "at": time.time()}
    try:
        forwards = router.fetch(cfg, secret)
        problems = [{"forward": _describe(f), "description": f["description"], "reason": f["problem"]}
                    for f in forwards if f["enabled"] and f.get("problem")]
        with ctx.session_factory() as s:
            via: dict[int, dict[str, list[str]]] = {}
            exposed, unmatched = match_forwards(s, [f for f in forwards if not f.get("problem")], via)
        state.update(ok=True, error="", checked_at=state["at"], forwards=len(forwards),
                     exposed={str(k): v for k, v in exposed.items()}, via={str(k): v for k, v in via.items()},
                     unmatched=(unmatched + problems)[:200])
    except ApplianceError as e:
        with ctx.session_factory() as s:
            old = setting(s, router.state_key) or {}
        state.update(ok=False, error=str(e)[:300], forwards=old.get("forwards", 0), exposed=old.get("exposed", {}),
                     via=old.get("via", {}), checked_at=last_success(old), unmatched=old.get("unmatched", []))
        log.warning("%s connector: %s", router.label, e)
    with ctx.session_factory() as s:
        put_setting(s, router.state_key, state)
        s.commit()
    return state


class RouterIn(BaseModel):
    url: str = Field(max_length=300)
    secret: str | None = Field(default=None, min_length=4, max_length=512)   # None = unverändert
    key: str = Field(default="", max_length=200)                             # OPNsense: API-Key (Benutzername)
    site: str = Field(default="default", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")   # UniFi
    trust_certificate: bool = False


def build_routerforwards_router(ctx: Context, guards: Guards) -> APIRouter:
    api = APIRouter(prefix="/settings/router")

    def known(kind: str) -> Router:
        if kind not in ROUTERS:
            raise HTTPException(404, "Unknown router: opnsense or unifi")
        return ROUTERS[kind]

    @api.get("/{kind}", dependencies=[Depends(guards.require_session)])
    def read(kind: str):
        router = known(kind)
        with ctx.session_factory() as s:
            return {"config": setting(s, router.config_key), "secret": ctx.secrets.meta(router.secret_key),
                    "state": setting(s, router.state_key) or {}}

    @api.put("/{kind}")
    def write(kind: str, body: RouterIn, found=Depends(guards.require_admin)):
        router = known(kind)
        url = body.url.strip().rstrip("/")
        if not _URL.match(url) or not url.startswith("https://"):
            raise HTTPException(422, f"URL must look like https://{kind}.lan (HTTPS only)")
        if kind == "opnsense" and not body.key.strip():
            raise HTTPException(422, "API key required (the secret is the second half)")
        if body.secret is None and not ctx.secrets.get(router.secret_key):
            raise HTTPException(422, "Secret required")
        with ctx.session_factory() as s:
            old = setting(s, router.config_key) or {}
            fp = old.get("fingerprint", "")
            if not fp or old.get("url") != url or body.trust_certificate:
                try:
                    fp = read_fingerprint(url)
                except ApplianceError as e:
                    raise HTTPException(422, str(e)) from None
            cfg = {"url": url, "fingerprint": fp}
            cfg.update({"key": body.key.strip()} if kind == "opnsense" else {"site": body.site})
            put_setting(s, router.config_key, cfg)
            ctx.audit(s, found[0].username, f"connector.{kind}.saved", url)
            s.commit()
        if body.secret is not None:
            ctx.secrets.set(router.secret_key, body.secret)
        return {"ok": True, "fingerprint": fp}

    @api.delete("/{kind}")
    def remove(kind: str, found=Depends(guards.require_admin)):
        router = known(kind)
        ctx.secrets.delete(router.secret_key)
        with ctx.session_factory() as s:
            for key in (router.config_key, router.state_key):
                put_setting(s, key, None)
            ctx.audit(s, found[0].username, f"connector.{kind}.removed", "")
            s.commit()
        return {"ok": True}

    @api.post("/{kind}/test")
    def test(kind: str, found=Depends(guards.require_admin)):
        known(kind)
        state = refresh_router(ctx, kind)
        if not state.get("configured"):
            raise HTTPException(409, f"{ROUTERS[kind].label} not configured")
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, f"connector.{kind}.tested", "ok" if state["ok"] else state["error"])
            s.commit()
        return state

    return api
