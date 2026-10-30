"""Traefik-Router aus Docker-Labels als Expositionsquelle (PLAN-extensions B1). Kein Zugang nötig: der Agent meldet
die Router-Labels (Regel, Entrypoints) seiner Container, nie Middlewares oder Services (Basic-Auth …).

Jeder Hostname einer Regel durchläuft dieselbe Entscheidung wie NPM (öffentliches DNS, Namen und Entrypoints von
Hand). Was sich nicht prüfen lässt (HostRegexp, HostSNI(`*`), keine Regel), steht als „nicht zugeordnet“ da.
Grenze: nur der Docker-Provider auf demselben Host; Routen aus dem File-Provider fehlen."""
import functools
import re
import time

from fastapi import APIRouter, Depends
from sqlalchemy import select

from .connectors import _note
from .containers import containers_of
from .context import Context
from .guards import Guards
from .models import System, put_setting, setting
from .publicdns import CHECK_FAILED, classify_hostname, decide, load_overrides

TRAEFIK_STATE = "traefik.state"
_ROUTER = re.compile(r"^traefik\.(?:http|tcp)\.routers\.([^.]+)\.(rule|entrypoints)$")
_CALL = re.compile(r"\b(Host|HostSNI|HostRegexp|HostSNIRegexp)\(([^)]*)\)")
_ARG = re.compile(r"[`\"]([^`\"]+)[`\"]")


def parse_rule(rule: str) -> tuple[list[str], str | None]:
    """(Hostnamen, Grund falls nicht prüfbar) einer Router-Regel; Pfade und andere Bedingungen zählen nicht."""
    calls = _CALL.findall(rule or "")
    if any(fn.endswith("Regexp") for fn, _ in calls):
        return [], "HostRegexp rules cannot be checked, mark it by hand"
    hosts: list[str] = []
    for _, args in calls:
        for arg in _ARG.findall(args):
            if arg == "*":
                return [], "HostSNI(`*`) matches every name, mark it by hand"
            if arg.lower() not in hosts:
                hosts.append(arg.lower())
    return (hosts, None) if hosts else ([], "rule has no Host(), mark it by hand")


def _routers(labels: dict[str, str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for key, value in labels.items():
        m = _ROUTER.match(key)
        if m:
            out.setdefault(m.group(1), {})[m.group(2)] = value
    return out


def refresh_traefik(ctx: Context) -> dict:
    """Wertet die gemeldeten Labels aller Hosts aus. Ohne Traefik-Labels: keine Quelle, keine Zeile."""
    exposed: dict[int, set[str]] = {}
    via: dict[int, dict[str, list[str]]] = {}
    unmatched, lan_only, failed = [], [], []
    seen_entrypoints: set[str] = set()
    seen = routers_total = 0
    classify = functools.lru_cache(maxsize=None)(classify_hostname)   # je Abgleich jeden Namen nur einmal
    with ctx.session_factory() as s:
        overrides = load_overrides(s)
        systems = s.scalars(select(System).where(System.status == "active")).all()
        for sys in systems:
            for c in containers_of(sys):
                labels = c.get("labels") or {}
                routers = _routers(labels)
                if not routers and labels.get("traefik.enable") != "true":
                    continue
                seen += 1
                if labels.get("traefik.enable") == "false" or c.get("state", "running") != "running":
                    continue   # Traefik leitet nur auf laufende, freigegebene Container
                what = f"{c.get('name', '?')} on {sys.name}"
                if not routers:
                    unmatched.append({"what": what, "why": "traefik.enable without a router rule (Traefik's default "
                                                            "rule), mark it by hand"})
                    continue
                for name, router in sorted(routers.items()):
                    routers_total += 1
                    hosts, why = parse_rule(router.get("rule", ""))
                    if why:
                        unmatched.append({"what": what, "router": name, "why": why})
                        continue
                    entrypoints = [e.strip() for e in router.get("entrypoints", "").split(",") if e.strip()]
                    seen_entrypoints.update(entrypoints)
                    verdicts = [(h, *decide(h, entrypoints, overrides, classify)) for h in hosts]
                    failed += [h for h, _, r in verdicts if r == CHECK_FAILED and h not in failed]
                    public = [h for h, exp, _ in verdicts if exp]
                    if public:
                        exposed.setdefault(sys.id, set()).add(c["name"])
                        _note(via, sys.id, c["name"], public)
                    else:
                        lan_only.append({"what": what, "router": name, "domains": hosts, "reason": verdicts[0][2]})
        if not seen:
            put_setting(s, TRAEFIK_STATE, None)
            s.commit()
            return {"configured": False}
        now = time.time()
        state = {"configured": True, "ok": True, "error": "", "at": now, "checked_at": now, "routers": routers_total,
                 "entrypoints": sorted(seen_entrypoints),
                 "exposed": {str(k): sorted(v) for k, v in exposed.items()}, "via": {str(k): v for k, v in via.items()},
                 "unmatched": unmatched[:200], "lan_only": lan_only[:200], "dns_failed": failed[:50]}
        put_setting(s, TRAEFIK_STATE, state)
        s.commit()
    return state


def build_traefik_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/traefik", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            return {"state": setting(s, TRAEFIK_STATE) or {"configured": False}}

    return router
