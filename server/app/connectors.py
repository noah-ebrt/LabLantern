"""NPM-Connector (PLAN Abschnitt 4.3): liest aus Nginx Proxy Manager, welche Ziele aus dem Internet erreichbar sind,
und ordnet sie Containern zu. Zugang mit einem eigenen NPM-Benutzer; das Passwort liegt im Geheimnisspeicher.
Nur die Liste der Proxy-Hosts (Domain -> Ziel) wird gelesen, nie Zertifikate oder Zugangslisten.

Zuordnung: Ziel = Containername auf einem System -> dieser Container. Ziel = IP eines Systems -> der Container,
der den Port veröffentlicht oder im Host-Netz auf ihm lauscht, sonst ein Dienst des Hosts auf dem Port (Agent ab
0.14). Was so nicht eindeutig wird, erscheint als „nicht zugeordnet“ und lässt sich unter Systeme von Hand
markieren. Nichts fällt still weg."""
import json
import logging
import re
import time
import urllib.error
from datetime import datetime, timezone
import urllib.request

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from .containers import HOST, containers_of, host_ports_of
from .context import Context
from .guards import Guards
from .models import Finding, System, put_setting, setting
from .rules import classify_certificate

log = logging.getLogger("vulnwatch.connectors")

NPM_CONFIG = "npm.config"
NPM_SECRET = "npm.password"
NPM_STATE = "npm.state"
_URL = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?/?$")
MAX_HOSTS = 2000
SAME_HOST = ("127.0.0.1", "localhost", "host.docker.internal", "172.17.0.1")


class NpmError(Exception):
    pass


def _call(base: str, path: str, token: str | None = None, body: dict | None = None, timeout: float = 15):
    headers = {"Content-Type": "application/json", "User-Agent": "vulnwatch"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(body).encode() if body else None,
                                 headers=headers, method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (Admin-URL, Muster geprüft)
            return json.loads(r.read(5_000_000))
    except urllib.error.HTTPError as e:
        raise NpmError(f"NPM answered HTTP {e.code} on {path}") from None
    except (urllib.error.URLError, OSError) as e:
        raise NpmError(f"NPM unreachable ({getattr(e, 'reason', e)})") from None
    except json.JSONDecodeError:
        raise NpmError(f"NPM sent no JSON on {path}") from None


def fetch_npm(url: str, email: str, password: str) -> tuple[list[dict], list[dict]]:
    """(Proxy-Hosts, Zertifikate). Von den Zertifikaten nur Name, Domains, Ablauf und Anbieter: `meta` kann
    Zugangsdaten für DNS-Challenges enthalten und wird nie übernommen."""
    token = _call(url, "/api/tokens", body={"identity": email, "secret": password}).get("token")
    if not token:
        raise NpmError("NPM login returned no token")
    hosts = _call(url, "/api/nginx/proxy-hosts", token=token)
    certs = _call(url, "/api/nginx/certificates", token=token)
    if not isinstance(hosts, list) or not isinstance(certs, list):
        raise NpmError("unexpected answer from the NPM API")
    return ([{"domains": [str(d)[:253] for d in (h.get("domain_names") or [])][:20],
              "forward_host": str(h.get("forward_host", ""))[:253], "forward_port": int(h.get("forward_port") or 0),
              "certificate_id": int(h.get("certificate_id") or 0), "enabled": bool(h.get("enabled", True))}
             for h in hosts[:MAX_HOSTS] if isinstance(h, dict)],
            [{"id": int(c.get("id") or 0), "name": str(c.get("nice_name") or "")[:200],
              "domains": [str(d)[:253] for d in (c.get("domain_names") or [])][:20],
              "expires_on": str(c.get("expires_on") or "")[:40], "provider": str(c.get("provider") or "")[:40]}
             for c in certs[:MAX_HOSTS] if isinstance(c, dict)])


def _expires(text: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(text.replace(" ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def certificate_status(hosts: list[dict], certs: list[dict], now: datetime) -> tuple[list[dict], list[dict]]:
    """(Übersicht, Soll-Funde). Geprüft werden nur Zertifikate aktiver Proxy-Hosts: alte Zertifikate
    abgeschalteter Hosts erneuert niemand, sie wären nur Rauschen."""
    used = {h["certificate_id"] for h in hosts if h["enabled"] and h["certificate_id"]}
    overview, desired = [], []
    for c in certs:
        if c["id"] not in used:
            continue
        exp = _expires(c["expires_on"])
        days = None if exp is None else round((exp - now).total_seconds() / 86400, 1)
        overview.append({"name": c["name"] or ", ".join(c["domains"]), "domains": c["domains"],
                         "expires_on": exp.isoformat() if exp else c["expires_on"], "days_left": days,
                         "provider": c["provider"]})
        sev = "hoch" if days is None else classify_certificate(days)
        if sev:
            domains = ", ".join(c["domains"]) or c["name"]
            when = "has an unreadable expiry date" if days is None else (
                f"expired {abs(days):.0f} days ago" if days < 0 else f"expires in {days:.0f} days")
            desired.append({"target": f"certificate:{c['id']}", "cve_id": "VW-CERT-EXPIRY", "severity": sev,
                            "component": domains[:300], "installed_version": (exp.date().isoformat() if exp else "?"),
                            "fixed_version": "renew in NPM",
                            "title": f"TLS certificate for {domains} {when}: NPM renews 30 days ahead, check the renewal"[:500]})
    overview.sort(key=lambda x: (x["days_left"] is not None, x["days_left"] or 0))
    return overview, desired


def sync_cert_findings(s, system_id: int, desired: list[dict], now: datetime, source: str = "npm") -> None:
    """Funde einer Quelle auf den Soll-Stand bringen, Schlüssel ist `target` (auch für TrueNAS/Home Assistant)."""
    existing = {f.target: f for f in s.scalars(select(Finding).where(
        Finding.system_id == system_id, Finding.source == source, Finding.status.in_(["open", "accepted"])))}
    for d in desired:
        f = existing.pop(d["target"], None)
        if f is None:
            s.add(Finding(system_id=system_id, status="open", source=source, **d))
        else:
            for k, v in d.items():
                setattr(f, k, v)
            if f.status == "accepted" and f.accepted_until is not None and f.accepted_until <= now:
                f.status = "open"
    for f in existing.values():
        f.status, f.resolved_at = "resolved", now


class PortIndex:
    """(IP, Port) -> Container (veröffentlicht oder im Host-Netz) und Dienste der Hosts; gemeinsam für NPM und Router."""

    def __init__(self, systems: list[System]):
        self.ips = {sys.ip: sys for sys in systems if sys.ip}
        self.by_port: dict[tuple[str, int], list[str]] = {}
        self.host: set[tuple[str, int]] = set()
        for sys in systems:
            for c in containers_of(sys):
                for port in c.get("ports") or []:
                    self.by_port.setdefault((sys.ip, port), []).append(c.get("name", ""))
            self.host |= {(sys.ip, port) for port in host_ports_of(sys)}

    def match(self, ip: str, port: int) -> tuple[int, str] | str:
        """(System-ID, Containername oder HOST), sonst der Grund, warum nichts eindeutig passt."""
        sys = self.ips.get(ip)
        if sys is None:
            return "no matching container"
        on_port = self.by_port.get((ip, port), [])
        if len(on_port) == 1:
            return sys.id, on_port[0]
        if on_port:
            return f"IP of {sys.name}: several containers publish port {port}, mark it by hand"
        if (ip, port) in self.host:
            return sys.id, HOST
        return (f"IP of {sys.name}: nothing reported listening on port {port} (agent 0.14 reports host-network "
                "containers and host services), mark it by hand")


def match_hosts(s, hosts: list[dict], npm_system_id: int | None) -> tuple[dict[int, list[str]], list[dict]]:
    """{System-ID: [Containernamen]} und die Einträge ohne eindeutigen Container."""
    systems = s.scalars(select(System).where(System.status == "active")).all()
    by_name: dict[str, list[int]] = {}
    for sys in systems:
        for c in containers_of(sys):
            if c.get("name"):
                by_name.setdefault(c["name"], []).append(sys.id)
    ids = {sys.id: sys for sys in systems}
    index = PortIndex(systems)
    exposed: dict[int, set[str]] = {}
    unmatched = []
    for h in hosts:
        if not h["enabled"]:
            continue
        target = h["forward_host"]
        owners = by_name.get(target, [])
        if npm_system_id in owners:   # gleicher Docker-Host wie NPM: eindeutig
            owners = [npm_system_id]
        if len(owners) == 1:
            exposed.setdefault(owners[0], set()).add(target)
            continue
        host = target
        if target in SAME_HOST and npm_system_id in ids:   # NPM leitet auf den eigenen Docker-Host
            host = ids[npm_system_id].ip
        hit = index.match(host, h["forward_port"])
        if isinstance(hit, tuple):
            exposed.setdefault(hit[0], set()).add(hit[1])
            continue
        why = "several systems have a container with this name" if owners else hit
        unmatched.append({"domains": h["domains"], "target": f"{target}:{h['forward_port']}", "reason": why})
    return {k: sorted(v) for k, v in exposed.items()}, unmatched


def refresh_npm(ctx: Context) -> dict:
    """Ruft NPM ab und speichert die Zuordnung. Ohne Einrichtung: nichts zu tun (kein Fehler)."""
    with ctx.session_factory() as s:
        cfg = setting(s, NPM_CONFIG)
    password = ctx.secrets.get(NPM_SECRET)
    if not cfg or not password:
        return {"configured": False}
    state = {"configured": True, "at": time.time()}
    try:
        hosts, certs = fetch_npm(cfg["url"], cfg["email"], password)
        now = datetime.now(timezone.utc)
        overview, desired = certificate_status(hosts, certs, now)
        with ctx.session_factory() as s:
            exposed, unmatched = match_hosts(s, hosts, cfg.get("system_id"))
            npm_system = s.get(System, cfg["system_id"]) if cfg.get("system_id") else None
            if npm_system is not None:   # Funde hängen am Host, auf dem NPM läuft
                sync_cert_findings(s, npm_system.id, desired, now)
                s.commit()
        state.update(ok=True, error="", hosts=len(hosts), exposed={str(k): v for k, v in exposed.items()},
                     unmatched=unmatched[:200], certificates=overview[:200],
                     cert_note="" if npm_system is not None else "choose the host running NPM to get certificate findings")
    except NpmError as e:
        with ctx.session_factory() as s:
            old = setting(s, NPM_STATE) or {}
        # alte Zuordnung behalten: ein kurzer Ausfall von NPM soll nichts herabstufen
        state.update(ok=False, error=str(e)[:300], hosts=old.get("hosts", 0), exposed=old.get("exposed", {}),
                     unmatched=old.get("unmatched", []), certificates=old.get("certificates", []))
        log.warning("NPM connector: %s", e)
    with ctx.session_factory() as s:
        put_setting(s, NPM_STATE, state)
        s.commit()
    return state


def connector_exposed(s) -> dict[int, dict[str, list[str]]]:
    """{System-ID: {Containername oder HOST: [Quellen]}} aus NPM und Router: automatisch erkannte Erreichbarkeit."""
    from .fritzbox import FRITZ_STATE

    out: dict[int, dict[str, list[str]]] = {}
    for key, source in ((NPM_STATE, "NPM"), (FRITZ_STATE, "router")):
        for sid, names in ((setting(s, key) or {}).get("exposed") or {}).items():
            for name in names:
                out.setdefault(int(sid), {}).setdefault(name, []).append(source)
    return out


class NpmIn(BaseModel):
    url: str = Field(max_length=300)
    email: str = Field(min_length=3, max_length=254)
    password: str | None = Field(default=None, min_length=1, max_length=512)   # None = unverändert
    system_id: int | None = None


def build_connectors_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/npm", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            cfg = setting(s, NPM_CONFIG)
            state = setting(s, NPM_STATE) or {}
        return {"config": cfg, "password": ctx.secrets.meta(NPM_SECRET), "state": state}

    @router.put("/npm")
    def write(body: NpmIn, found=Depends(guards.require_admin)):
        url = body.url.strip()
        if not _URL.match(url):
            raise HTTPException(422, "URL must look like http://npm.lan:81")
        if body.password is None and not ctx.secrets.get(NPM_SECRET):
            raise HTTPException(422, "Password required")
        if body.password is not None:
            ctx.secrets.set(NPM_SECRET, body.password)
        with ctx.session_factory() as s:
            put_setting(s, NPM_CONFIG, {"url": url.rstrip("/"), "email": body.email.strip(), "system_id": body.system_id})
            ctx.audit(s, found[0].username, "connector.npm.saved", url)
            s.commit()
        return {"ok": True}

    @router.delete("/npm")
    def remove(found=Depends(guards.require_admin)):
        ctx.secrets.delete(NPM_SECRET)
        with ctx.session_factory() as s:
            for key in (NPM_CONFIG, NPM_STATE):
                put_setting(s, key, None)
            ctx.audit(s, found[0].username, "connector.npm.removed", "")
            s.commit()
        return {"ok": True}

    @router.post("/npm/test")
    def test(found=Depends(guards.require_admin)):
        state = refresh_npm(ctx)
        if not state.get("configured"):
            raise HTTPException(409, "NPM connector not configured")
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "connector.npm.tested", "ok" if state["ok"] else state["error"])
            s.commit()
        return state

    return router
