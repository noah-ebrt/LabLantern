"""Die ganze Konfiguration als ein JSON-Dokument (Einstellungen → „Configuration as JSON“, auch per API skriptbar).

Lesen setzt das Dokument aus den gespeicherten Werten zusammen. Schreiben ruft für jeden geänderten Abschnitt
dieselben Endpunkte auf wie die Formulare: gleiche Prüfung, gleiche Folgen (Zeitplan neu, Audit-Eintrag), gleiche
Behandlung von Geheimnissen. Geheimnisse stehen als null im Dokument (= unverändert); ein Text setzt sie neu, sie
kommen nie heraus. Jeder Abschnitt gilt für sich: schlägt einer fehl, bleiben die übrigen gespeichert.

Bewusst nicht enthalten: Benutzer, Passkeys und ihre Vertrauensliste, Agent- und Metrik-Tokens. Anmeldung und
Vertrauen gehören nicht in eine Textdatei, die man kopiert und weitergibt."""
import typing

from fastapi import APIRouter, Depends, HTTPException
from fastapi.routing import APIRoute
from pydantic import ValidationError

from .context import Context
from .guards import Guards
from sqlalchemy import select

from .models import put_setting, setting


class SectionError(Exception):
    pass


def _route(routers: list[APIRouter], method: str, path: str) -> APIRoute:
    for router in routers:
        for r in router.routes:
            if isinstance(r, APIRoute) and r.path == path and method in r.methods:
                return r
    raise RuntimeError(f"route {method} {path} missing")


def build_config_router(ctx: Context, guards: Guards, routers: list[APIRouter]) -> APIRouter:
    """`routers`: die Router der Endpunkte (Pfade ohne /api), über die geschrieben wird."""
    from .appliances import CONFIG_KEY as APPLIANCES_KEY, _configs
    from .connectors import NPM_CONFIG, NPM_SECRET
    from .aiproviders import MODEL_ID, TASKS, TASKS_KEY
    from .earlywarning import DEFAULT_FEEDS, FEEDS_KEY, PRODUCTS_KEY, ai_config, research_config
    from .fritzbox import FRITZ_CONFIG, FRITZ_SECRET
    from .integrity import drop_config
    from .models import CoverageExclusion, Snooze, System
    from .notify import load_channels
    from .reportpolicy import get_report_policy
    from .schedule import get_schedule, get_short_schedule, get_timezone
    from .watchdog import get_config as watchdog_config

    router = APIRouter(prefix="/settings")

    def call(found, method: str, path: str, value=None, **params):
        """Den Endpunkt der Formulare aufrufen; Fehler als Text ohne die eingegebenen Werte (Geheimnisse)."""
        route = _route(routers, method, path)
        kwargs = dict(params, found=found)
        if value is not None:
            model = typing.get_type_hints(route.endpoint)["body"]
            try:
                kwargs["body"] = model.model_validate(value)
            except ValidationError as e:
                raise SectionError("; ".join(f"{'.'.join(map(str, x['loc'])) or 'value'}: {x['msg']}"
                                             for x in e.errors(include_input=False, include_url=False))) from None
        try:
            return route.endpoint(**kwargs)
        except HTTPException as e:
            raise SectionError(str(e.detail)) from None

    def simple(path: str):
        return lambda found, value, current: call(found, "PUT", path, value)

    # --- Lesen je Abschnitt: genau die Form, die der Endpunkt annimmt ---
    def read_claude(s):
        """Das Modell für „classify“, soweit es von Anthropic ist (so wie alte Exporte es kennen); alles andere: leer."""
        ref = (setting(s, TASKS_KEY) or {}).get("classify") or ""
        return {"model": ref.removeprefix("anthropic:") if ref.startswith("anthropic:") else None, "api_key": None}

    def read_watchdog(s):
        cfg = watchdog_config(ctx)
        return {"provider": cfg["provider"], "heartbeat_minutes": cfg["heartbeat_minutes"],
                "heartbeat_url": None, "run_url": None, "short_url": None}

    def read_npm(s):
        cfg = setting(s, NPM_CONFIG)
        return {**cfg, "password": None} if cfg else None

    def read_fritzbox(s):
        cfg = setting(s, FRITZ_CONFIG)
        return {**cfg, "password": None} if cfg else None

    def read_notifications(s):
        return [{"name": c["name"], "url": None, "gets": c["gets"]} for c in load_channels(ctx)]

    def read_appliances(s):
        return [{"system_id": int(sid), "kind": c["kind"], "name": s.get(System, int(sid)).name, "url": c["url"],
                 "token": None} for sid, c in _configs(s).items()]

    # --- Schreiben, wo ein Abschnitt mehr als einen Endpunkt braucht ---
    def write_claude(found, value, current):
        value = value or {}
        model = value.get("model") or None
        if model != current["model"]:
            # Alte Exporte tragen das eine Modell; es wird zur Wahl für „classify“ (leer = automatisch). Direkt
            # geschrieben, ohne Abgleich mit der Modellliste: der Anbieter muss dafür nicht eingerichtet sein.
            if model is not None and not (isinstance(model, str) and MODEL_ID.fullmatch(model)):
                raise SectionError("model: invalid model id")
            with ctx.session_factory() as s:
                tasks = {t: (setting(s, TASKS_KEY) or {}).get(t) or "" for t in TASKS}
                tasks["classify"] = f"anthropic:{model}" if model else ""
                put_setting(s, TASKS_KEY, tasks)
                ctx.audit(s, found[0].username, "ai.tasks",
                          ", ".join(f"{t}={r or 'automatic'}" for t, r in tasks.items()))
                s.commit()
        if value.get("api_key"):
            call(found, "PUT", "/ai/providers/{pid}", {"api_key": value["api_key"]}, pid="anthropic")

    def write_npm(found, value, current):
        if value is None:
            call(found, "DELETE", "/settings/npm")
        else:
            if value.get("password") is None and current is None and not ctx.secrets.get(NPM_SECRET):
                raise SectionError("password required")
            call(found, "PUT", "/settings/npm", value)

    def write_fritzbox(found, value, current):
        if value is None:
            call(found, "DELETE", "/settings/fritzbox")
        else:
            if value.get("password") is None and current is None and not ctx.secrets.get(FRITZ_SECRET):
                raise SectionError("password required")
            call(found, "PUT", "/settings/fritzbox", value)

    def write_notifications(found, value, current):
        """Bestehende Kanäle stehen mit url null darin; fehlt einer, wird er entfernt. Neue haben eine URL."""
        if not isinstance(value, list):
            raise SectionError("must be a list")
        keep = [c.get("name") for c in value if isinstance(c, dict) and c.get("url") is None]
        names = [c["name"] for c in current]
        for n in keep:
            if n not in names:
                raise SectionError(f"no channel named {n!r}: a new channel needs its url")
        for i in reversed(range(len(names))):
            if names[i] in keep:
                keep.remove(names[i])
            else:
                call(found, "DELETE", "/integrations/notifications/{index}", index=i)
        for c in value:
            if isinstance(c, dict) and c.get("url") is not None:
                call(found, "POST", "/integrations/notifications", c)
        # Was ein bestehender Kanal bekommt; Positionen erst nach dem Entfernen und Anlegen bestimmen
        wanted = {c["name"]: c["gets"] for c in value if isinstance(c, dict) and c.get("url") is None and "gets" in c}
        for i, c in enumerate(load_channels(ctx)):
            if c["name"] in wanted and wanted[c["name"]] != c["gets"]:
                call(found, "PUT", "/integrations/notifications/{index}", {"gets": wanted[c["name"]]}, index=i)

    def write_appliances(found, value, current):
        """Mit system_id: ändern, ohne: neu anlegen, fehlende: entfernen (samt System und Funden)."""
        if not isinstance(value, list):
            raise SectionError("must be a list")
        now = {c["system_id"]: c for c in current}
        wanted = {c.get("system_id") for c in value if isinstance(c, dict)}
        for sid in now:
            if sid not in wanted:
                call(found, "DELETE", "/settings/appliances/{sid}", sid=sid)
        for c in value:
            if not isinstance(c, dict):
                raise SectionError("each entry must be an object")
            body = {k: v for k, v in c.items() if k != "system_id"}
            sid = c.get("system_id")
            if sid is None:
                call(found, "POST", "/settings/appliances", body)
            elif sid not in now:
                raise SectionError(f"no connector with system_id {sid}")
            elif c != now[sid]:
                call(found, "PUT", "/settings/appliances/{sid}", body, sid=sid)

    def read_snoozes(s):
        names = {x.id: x.name for x in s.scalars(select(System))}
        return [{"id": sn.id, "scope": sn.scope, "cve_id": sn.cve_id, "component": sn.component,
                 "system": names.get(sn.system_id) if sn.system_id else None, "target": sn.target_key or "host",
                 "until": sn.until.date().isoformat(), "reason": sn.reason}
                for sn in s.scalars(select(Snooze).where(Snooze.ended_at.is_(None)).order_by(Snooze.id))]

    def write_snoozes(found, value, current):
        """Mit id: bleibt (unverändert), ohne id: neu, fehlende: entfernt. Ändern = id weglassen und neu anlegen."""
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise SectionError("must be a list of objects")
        now = {x["id"]: x for x in current}
        keep = {x["id"] for x in value if x.get("id") is not None}
        for x in value:
            if x.get("id") is not None and now.get(x["id"]) != x:
                raise SectionError(f"snooze {x['id']} cannot be changed: leave out its id to create it anew")
        for sid in now.keys() - keep:
            call(found, "DELETE", "/snoozes/{snooze_id}", snooze_id=sid)
        with ctx.session_factory() as s:
            ids = {x.name: x.id for x in s.scalars(select(System))}
        for x in value:
            if x.get("id") is None:
                if x.get("system") is not None and x["system"] not in ids:
                    raise SectionError(f"no system named {x['system']!r}")
                body = {k: x.get(k) for k in ("scope", "cve_id", "component", "until", "reason")}
                call(found, "POST", "/snoozes", {**body, "target": x.get("target") or "host",
                                                 "system_id": ids.get(x.get("system"))})

    def read_exclusions(s):
        names = {x.id: x.name for x in s.scalars(select(System))}
        return [{"id": ex.id, "system": names.get(int(ex.subject.split(":", 1)[1])), "until": ex.until.date().isoformat(),
                 "reason": ex.reason}
                for ex in s.scalars(select(CoverageExclusion).where(CoverageExclusion.ended_at.is_(None))
                                    .order_by(CoverageExclusion.id)) if ex.subject.startswith("system:")]

    def write_exclusions(found, value, current):
        """Wie bei den Snoozes: mit id bleibt, ohne id neu, fehlende werden entfernt."""
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise SectionError("must be a list of objects")
        now = {x["id"]: x for x in current}
        keep = {x["id"] for x in value if x.get("id") is not None}
        for x in value:
            if x.get("id") is not None and now.get(x["id"]) != x:
                raise SectionError(f"exclusion {x['id']} cannot be changed: leave out its id to create it anew")
        for eid in now.keys() - keep:
            call(found, "DELETE", "/coverage/exclusions/{exclusion_id}", exclusion_id=eid)
        with ctx.session_factory() as s:
            ids = {x.name: x.id for x in s.scalars(select(System))}
        for x in value:
            if x.get("id") is None:
                if x.get("system") not in ids:
                    raise SectionError(f"no system named {x.get('system')!r}")
                call(found, "POST", "/coverage/exclusions", {"subject": f"system:{ids[x['system']]}",
                                                             "until": x.get("until"), "reason": x.get("reason")})

    sections = {   # Name: (lesen, schreiben); Reihenfolge = Reihenfolge im Dokument
        "schedule": (lambda s: {k: get_schedule(ctx)[k] for k in ("enabled", "time")}, simple("/settings/schedule")),
        "short_schedule": (lambda s: {k: get_short_schedule(ctx)[k] for k in ("enabled", "hours")},
                           simple("/settings/short-schedule")),
        "timezone": (lambda s: {"timezone": get_timezone(ctx)}, simple("/settings/timezone")),
        "report_policy": (lambda s: {k: get_report_policy(ctx)[k] for k in ("frequency", "weekday", "paused_until")},
                          simple("/settings/report-policy")),
        "finding_drop": (drop_config, simple("/settings/finding-drop")),
        "notifications": (read_notifications, write_notifications),
        "watchdog": (read_watchdog, simple("/settings/watchdog")),
        "early_warning": (lambda s: {"feeds": setting(s, FEEDS_KEY, DEFAULT_FEEDS), "products": setting(s, PRODUCTS_KEY, [])},
                          simple("/early-warnings/config")),
        "research": (research_config, simple("/early-warnings/research")),
        "early_warning_ai": (ai_config, simple("/early-warnings/ai-level")),
        "claude": (read_claude, write_claude),
        "npm": (read_npm, write_npm),
        "fritzbox": (read_fritzbox, write_fritzbox),
        "appliances": (read_appliances, write_appliances),
        "snoozes": (read_snoozes, write_snoozes),
        "coverage_exclusions": (read_exclusions, write_exclusions),
    }

    def document() -> dict:
        with ctx.session_factory() as s:
            return {name: read(s) for name, (read, _) in sections.items()}

    @router.get("/config", dependencies=[Depends(guards.require_session)])
    def read():
        return document()

    @router.put("/config")
    def write(body: dict, found=Depends(guards.require_admin)):
        """Nur Abschnitte, die im Dokument stehen und sich geändert haben, werden geschrieben."""
        current = document()
        results = {}
        for name, value in body.items():
            if name == "releases":   # Dokumente von vor dem lokalen Agent-Build: die GitLab-Quelle gibt es nicht mehr
                results[name] = "ignored: agents are built by this install"
                continue
            if name not in sections:
                results[name] = "error: unknown section"
                continue
            if value == current[name]:
                results[name] = "unchanged"
                continue
            try:
                sections[name][1](found, value, current[name])
                results[name] = "saved"
            except SectionError as e:
                results[name] = f"error: {e}"[:500]
        return {"ok": not any(r.startswith("error") for r in results.values()), "results": results,
                "config": document()}

    return router
