"""Cloudflare-Tunnel-Connector (PLAN-extensions A5): liest die Ingress-Regeln der Tunnel eines Kontos und ordnet
jede öffentliche Route einem Container oder dem Host zu. Ein Tunnel ist per Definition aus dem Internet erreichbar,
deshalb keine DNS-Prüfung. Zugang mit einem API-Token, Recht „Account · Cloudflare Tunnel · Read“; es wird nie
etwas geschrieben. Lokal verwaltete Tunnel (config.yml auf dem Host) haben keine lesbaren Regeln und stehen als
„nicht zugeordnet“ da, nie stillschweigend als „nicht erreichbar“."""
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .connectors import PortIndex, _note
from .containers import containers_of
from .context import Context
from .guards import Guards
from .models import System, put_setting, setting

log = logging.getLogger("lablantern.cftunnel")

API = "https://api.cloudflare.com/client/v4"
CF_CONFIG = "cftunnel.config"
CF_SECRET = "cftunnel.token"
CF_STATE = "cftunnel.state"
LOCAL = {"localhost", "127.0.0.1", "::1"}
DEFAULT_PORT = {"http": 80, "https": 443, "ssh": 22, "rdp": 3389}
_ACCOUNT = re.compile(r"^[0-9a-f]{32}$")


class CfError(Exception):
    pass


def _get(path: str, token: str) -> dict:
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {token}", "User-Agent": "lablantern"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read(5_000_000))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise CfError(f"Cloudflare rejected the token (HTTP {e.code}); it needs “Cloudflare Tunnel: Read” "
                          "on this account") from None
        raise CfError(f"Cloudflare answered HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise CfError(f"Cloudflare unreachable ({getattr(e, 'reason', e)})") from None
    except json.JSONDecodeError:
        raise CfError("Cloudflare sent no JSON") from None
    if not data.get("success", False):
        raise CfError("Cloudflare: " + "; ".join(str(e.get("message", e)) for e in data.get("errors") or [])[:200])
    return data


def fetch_tunnels(account_id: str, token: str) -> list[dict]:
    return _get(f"/accounts/{account_id}/cfd_tunnel?is_deleted=false&per_page=100", token).get("result") or []


def fetch_ingress(account_id: str, token: str, tunnel: dict) -> list[dict] | None:
    """Ingress-Regeln eines Tunnels; None bei lokal verwalteter Konfiguration."""
    if not tunnel.get("remote_config"):
        return None
    result = _get(f"/accounts/{account_id}/cfd_tunnel/{tunnel['id']}/configurations", token).get("result") or {}
    return ((result.get("config") or {}).get("ingress")) or []


def _cloudflared_hosts(systems: list[System]) -> list[System]:
    return [sys for sys in systems
            if any("cloudflare/cloudflared" in (c.get("image") or "") for c in containers_of(sys))]


def map_ingress(rules: list[dict], systems: list[System]) -> tuple[dict[int, list[str]], dict, list[dict]]:
    """{System-ID: [Container oder HOST]}, {System-ID: {Name: [Hostnamen]}} und die Regeln ohne eindeutiges Ziel.
    Jede Regel trägt zusätzlich "tunnel" (Name des Tunnels)."""
    index = PortIndex(systems)
    by_name: dict[str, list[System]] = {}
    for sys in systems:
        for c in containers_of(sys):
            if c.get("name"):
                by_name.setdefault(c["name"], []).append(sys)
    by_sysname = {sys.name: sys for sys in systems}
    tunnel_hosts = _cloudflared_hosts(systems)
    exposed: dict[int, set[str]] = {}
    via: dict[int, dict[str, list[str]]] = {}
    unmatched = []
    for r in rules:
        hostname, service = r.get("hostname"), (r.get("service") or "").strip()
        if not hostname or "://" not in service:   # Sammelregel (http_status:404), hello_world: kein Ursprung
            continue
        u = urllib.parse.urlsplit(service)
        try:
            port = u.port or DEFAULT_PORT.get(u.scheme)
        except ValueError:
            port = None
        host = (u.hostname or "").lower()
        hit: tuple[int, str] | str
        if not host or not port:
            hit = f"cannot read the target {service}"
        elif host in LOCAL:
            if len(tunnel_hosts) == 1:
                hit = index.match(tunnel_hosts[0].ip, port)
            else:
                hit = "ambiguous: cloudflared on several hosts" if tunnel_hosts else \
                    "cloudflared not found in a monitored host's containers"
        elif host in by_name:
            owners = by_name[host]
            near = [x for x in owners if x in tunnel_hosts]   # gleicher Docker-Host wie cloudflared: eindeutig
            owners = near if len(near) == 1 else owners
            hit = (owners[0].id, host) if len(owners) == 1 else "several systems have a container with this name"
        elif host in by_sysname:
            hit = index.match(by_sysname[host].ip, port)
        else:
            hit = index.match(host, port)
            if hit == "no matching container":
                hit = f"target {host} is not a monitored host or container, mark it by hand"
        if isinstance(hit, tuple):
            exposed.setdefault(hit[0], set()).add(hit[1])
            _note(via, hit[0], hit[1], [hostname])
        else:
            unmatched.append({"what": hostname, "why": hit, "tunnel": r.get("tunnel", ""), "service": service})
    return {k: sorted(v) for k, v in exposed.items()}, via, unmatched


def refresh_cftunnel(ctx: Context) -> dict:
    """Liest alle Tunnel und speichert die Zuordnung. Ohne Einrichtung: nichts zu tun (kein Fehler)."""
    from .exposure import last_success

    with ctx.session_factory() as s:
        cfg = setting(s, CF_CONFIG)
    token = ctx.secrets.get(CF_SECRET)
    if not cfg or not token:
        return {"configured": False}
    state = {"configured": True, "at": time.time()}
    try:
        tunnels = fetch_tunnels(cfg["account_id"], token)
        rules, local = [], []
        for t in tunnels:
            ingress = fetch_ingress(cfg["account_id"], token, t)
            if ingress is None:
                local.append({"what": t.get("name", t.get("id", "?")),
                              "why": "ingress not readable (locally managed config.yml)"})
            else:
                rules += [{**r, "tunnel": t.get("name", "")} for r in ingress]
        with ctx.session_factory() as s:
            systems = list(s.query(System).filter(System.status == "active"))
            exposed, via, unmatched = map_ingress(rules, systems)
        state.update(ok=True, error="", checked_at=state["at"], tunnels=len(tunnels),
                     exposed={str(k): v for k, v in exposed.items()}, via={str(k): v for k, v in via.items()},
                     unmatched=(local + unmatched)[:200])
    except CfError as e:
        with ctx.session_factory() as s:
            old = setting(s, CF_STATE) or {}
        # alte Zuordnung behalten: ein kurzer Ausfall der API soll nichts herabstufen
        state.update(ok=False, error=str(e)[:300], tunnels=old.get("tunnels", 0), exposed=old.get("exposed", {}),
                     via=old.get("via", {}), checked_at=last_success(old), unmatched=old.get("unmatched", []))
        log.warning("Cloudflare Tunnel connector: %s", e)
    with ctx.session_factory() as s:
        put_setting(s, CF_STATE, state)
        s.commit()
    return state


class CfIn(BaseModel):
    account_id: str = Field(min_length=32, max_length=32)
    token: str | None = Field(default=None, min_length=20, max_length=200)   # None = unverändert


def build_cftunnel_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/cftunnel", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            cfg = setting(s, CF_CONFIG)
            state = setting(s, CF_STATE) or {}
        return {"config": cfg, "token": ctx.secrets.meta(CF_SECRET), "state": state}

    @router.put("/cftunnel")
    def write(body: CfIn, found=Depends(guards.require_admin)):
        account = body.account_id.strip().lower()
        if not _ACCOUNT.match(account):
            raise HTTPException(422, "Account ID is the 32-character hex ID from the Cloudflare dashboard")
        if body.token is None and not ctx.secrets.get(CF_SECRET):
            raise HTTPException(422, "API token required")
        if body.token is not None:
            ctx.secrets.set(CF_SECRET, body.token.strip())
        with ctx.session_factory() as s:
            put_setting(s, CF_CONFIG, {"account_id": account})
            ctx.audit(s, found[0].username, "connector.cftunnel.saved", account)
            s.commit()
        return {"ok": True}

    @router.delete("/cftunnel")
    def remove(found=Depends(guards.require_admin)):
        ctx.secrets.delete(CF_SECRET)
        with ctx.session_factory() as s:
            for key in (CF_CONFIG, CF_STATE):
                put_setting(s, key, None)
            ctx.audit(s, found[0].username, "connector.cftunnel.removed", "")
            s.commit()
        return {"ok": True}

    @router.post("/cftunnel/test")
    def test(found=Depends(guards.require_admin)):
        state = refresh_cftunnel(ctx)
        if not state.get("configured"):
            raise HTTPException(409, "Cloudflare Tunnel connector not configured")
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "connector.cftunnel.tested", "ok" if state["ok"] else state["error"])
            s.commit()
        return state

    return router
