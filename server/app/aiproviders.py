"""KI-Anbieter einrichten und zuordnen: Schlüssel/Adresse je Anbieter, das Modell je Aufgabe, die automatische Wahl.

Anbieter: `anthropic`, `openai` und ein eigener OpenAI-kompatibler Endpunkt `c1` (Ollama, vLLM, LiteLLM …).
Aufgaben: classify (Meldung lesen), research und verify (beide brauchen Websuche).
Es gibt keinen stillen Wechsel zu einem anderen Anbieter: Scheitert eine Aufgabe, wird der Fehler festgehalten.
"""
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .aibase import AiError, Provider
from .claude import AnthropicProvider, anthropic_web, make_client
from .context import Context
from .guards import Guards
from .models import Setting, put_setting, setting
from .openai_client import OPENAI_BASE, OpenAIProvider, make_openai_client, openai_web

CLAUDE_SECRET = "claude.api_key"          # Name unverändert: bestehende Installationen behalten ihren Schlüssel
OPENAI_SECRET = "openai.api_key"
COMPAT_URL_SECRET = "compat.c1.url"       # die Adresse kann Zugangsdaten tragen (user:pw@, ?token=), ist also ein Geheimnis
COMPAT_KEY_SECRET = "compat.c1.api_key"
COMPAT_KEY = "ai.compat"                  # [{"id", "name", "display_url"}]: nur Unbedenkliches, für die Anzeige
TASKS_KEY = "ai.tasks"                    # {"classify": ref, "research": ref, "verify": ref}
MODELS_PREFIX = "ai.models."              # + pid: {"at", "items"}, 24 h zwischengespeichert
LAST_USED_PREFIX = "ai.last_used."        # + pid: {"at", "task", "model", "ok", "error"?}
MODELS_TTL = 24 * 3600
FAILED_TTL = 300                          # nach einem Fehlschlag 5 Minuten nicht neu versuchen (außer mit refresh)

CLAUDE_MODEL = "claude-haiku-5-5"         # nur Rückfall, wenn die Modellliste von Anthropic nicht erreichbar ist
RESEARCH_MODEL = "claude-sonnet-5-5"      # Rückfall für die Web-Recherche
MODEL_ID = re.compile(r"^claude-[a-z0-9.-]{3,80}$")
_ANTHROPIC_KEY = re.compile(r"[^\s]{20,400}")
_OPENAI_KEY = re.compile(r"sk-[A-Za-z0-9_-]{20,300}")
_COMPAT_KEY = re.compile(r"[^\s]{1,500}")
_OPENAI_FLAGSHIP = re.compile(r"^gpt-\d+(\.\d+)?$")

TASKS = ("classify", "research", "verify")
WEB_TASKS = ("research", "verify")        # nur mit Anbietern, die im Web suchen können
PIDS = ("anthropic", "openai", "c1")
COMPAT_ID = "c1"


def latest_haiku(models: list[dict]) -> str:
    haiku = [m for m in models if "haiku" in m["id"]]
    return haiku[0]["id"] if haiku else CLAUDE_MODEL


def latest_sonnet(models: list[dict]) -> str:
    sonnet = [m for m in models if "sonnet" in m["id"]]
    return sonnet[0]["id"] if sonnet else RESEARCH_MODEL


# ---------- Anbieter ----------

def _compat_entry(ctx: Context) -> dict | None:
    with ctx.session_factory() as s:
        entries = setting(s, COMPAT_KEY) or []
    return next((e for e in entries if e.get("id") == COMPAT_ID), None)


def _configured(ctx: Context, pid: str) -> bool:
    """„Eingerichtet“ heißt: Schlüssel (oder Adresse) ist gespeichert, nie das Ergebnis des letzten Aufrufs."""
    if pid == "anthropic":
        return ctx.secrets.meta(CLAUDE_SECRET)["set"]
    if pid == "openai":
        return ctx.secrets.meta(OPENAI_SECRET)["set"]
    return ctx.secrets.meta(COMPAT_URL_SECRET)["set"] and _compat_entry(ctx) is not None


def _make(ctx: Context, pid: str) -> Provider | None:
    if not _configured(ctx, pid):
        return None
    if pid == "anthropic":
        key = ctx.secrets.get(CLAUDE_SECRET)
        return AnthropicProvider(make_client(ctx.settings.anthropic_base_url, key, ctx.claude_factory))
    if pid == "openai":
        key = ctx.secrets.get(OPENAI_SECRET)
        return OpenAIProvider(make_openai_client(OPENAI_BASE, key, ctx.openai_factory), "openai", "OpenAI", False)
    url = ctx.secrets.get(COMPAT_URL_SECRET)
    return OpenAIProvider(make_openai_client(url, ctx.secrets.get(COMPAT_KEY_SECRET), ctx.openai_factory),
                          COMPAT_ID, _compat_entry(ctx)["name"], True)


def providers(ctx: Context) -> dict[str, Provider]:
    """Die eingerichteten Anbieter, in der Reihenfolge Anthropic, OpenAI, eigener Endpunkt."""
    return {pid: p for pid in PIDS if (p := _make(ctx, pid)) is not None}


def any_configured(ctx: Context) -> bool:
    return any(_configured(ctx, pid) for pid in PIDS)


# ---------- Modelle ----------

def _web(pid: str, model_id: str) -> bool:
    if pid == "anthropic":
        return anthropic_web(model_id)
    return pid == "openai" and openai_web(model_id)


def models_for(ctx: Context, pid: str, refresh: bool = False) -> list[dict]:
    """Modellliste des Anbieters aus dem Cache; älter als 24 h (oder refresh) wird neu geholt, solange er eingerichtet ist.
    Schlägt das Holen fehl, bleibt die alte Liste. Jeder Eintrag trägt `web`: darf für Recherche gewählt werden."""
    key = MODELS_PREFIX + pid
    with ctx.session_factory() as s:
        cache = setting(s, key) or {}
    provider = _make(ctx, pid)
    if provider is None:
        return []
    now = time.time()
    if refresh or (now - cache.get("at", 0) > MODELS_TTL and now - cache.get("failed_at", 0) > FAILED_TTL):
        try:
            items = provider.list_models()
            if pid == "anthropic":
                items = [m for m in items if MODEL_ID.match(m["id"])]
            cache = {"at": now, "items": items}
        except AiError:
            cache = {**cache, "failed_at": now}   # alte Liste behalten, aber nicht bei jedem Aufruf neu anfragen
        with ctx.session_factory() as s:
            put_setting(s, key, cache)
            s.commit()
    return [{**m, "web": _web(pid, m["id"])} for m in cache.get("items") or []]


# ---------- Wahl je Aufgabe ----------

def _tasks(ctx: Context) -> dict:
    with ctx.session_factory() as s:
        return setting(s, TASKS_KEY) or {}


def _split(ref: str) -> tuple[str, str]:
    """„<pid>:<Modell>“ am ERSTEN Doppelpunkt trennen: Ollama-Modelle heißen z. B. `qwen3.8:27b`."""
    pid, _, model = ref.partition(":")
    return pid, model


def resolve(ctx: Context, task: str) -> tuple[Provider, str]:
    """Anbieter und Modell für eine Aufgabe: die ausdrückliche Wahl, sonst automatisch (Anthropic vor OpenAI).
    Wirft AiError mit einer Meldung, die die Oberfläche unverändert zeigt."""
    provs = providers(ctx)
    ref = _tasks(ctx).get(task) or ""
    if ref:
        pid, model = _split(ref)
        provider = provs.get(pid)
        if provider is None or not model:
            raise AiError("no model — provider removed")
        if task in WEB_TASKS and not provider.web_search:
            raise AiError("needs a provider with web search")
        return provider, model
    if not provs:
        raise AiError("no AI provider configured")
    if task in WEB_TASKS and not any(p.web_search for p in provs.values()):
        raise AiError("needs a provider with web search")
    web = task in WEB_TASKS
    if "anthropic" in provs:
        models = models_for(ctx, "anthropic")
        if web:
            models = [m for m in models if m["web"]]   # nur Modelle mit Websuche
        return provs["anthropic"], latest_haiku(models) if task == "classify" else latest_sonnet(models)
    if "openai" in provs:
        items = models_for(ctx, "openai")
        ids = [m["id"] for m in items if m["web"] or not web]
        want = (lambda i: "-mini" in i) if task == "classify" else _OPENAI_FLAGSHIP.match
        model = next((i for i in ids if want(i)), None)
        if model:
            return provs["openai"], model
    raise AiError("choose a model (no automatic choice for this provider)")


def record_use(ctx: Context, provider: Provider, task: str, model: str, ok: bool, error: str | None = None) -> None:
    """Den letzten Aufruf je Anbieter festhalten (für die Anzeige in den Einstellungen)."""
    last = {"at": datetime.now(timezone.utc).isoformat(), "task": task, "model": model, "ok": ok}
    if error:
        last["error"] = error[:300]
    with ctx.session_factory() as s:
        put_setting(s, LAST_USED_PREFIX + provider.pid, last)
        s.commit()


# ---------- Eingaben ----------

class ProviderIn(BaseModel):
    # Keine Muster hier: Fehlermeldungen von Pydantic würden sonst Schlüssel oder Adresse wiederholen (und sie
    # hängen vom Anbieter ab). Geprüft wird unten, die Meldungen nennen nur das Feld.
    api_key: str | None = Field(default=None, max_length=600)
    base_url: str | None = Field(default=None, max_length=500)
    name: str | None = Field(default=None, max_length=60)


class TasksIn(BaseModel):
    classify: str = Field(default="", max_length=300)
    research: str = Field(default="", max_length=300)
    verify: str = Field(default="", max_length=300)


def _invalid(field: str, msg: str) -> HTTPException:
    """422 in der Form der Pydantic-Fehler, ohne die Eingabe zu wiederholen."""
    return HTTPException(422, [{"loc": ["body", field], "msg": msg, "type": "value_error"}])


def clean_url(raw: str) -> tuple[str, str]:
    """(Adresse, Anzeigeadresse): die Anzeige ohne Zugangsdaten, Query und Fragment. Wirft ValueError."""
    if len(raw) > 500:
        raise ValueError
    parts = urlsplit(raw.strip())
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError
    parts.port   # noqa: B018 - wirft ValueError bei einem ungültigen Port
    shown_host = f"[{host}]" if ":" in host else host
    port = f":{parts.port}" if parts.port else ""
    return raw.strip(), f"{parts.scheme}://{shown_host}{port}{parts.path}"


def _drop_settings(s: Session, *keys: str) -> None:
    for k in keys:
        row = s.get(Setting, k)
        if row is not None:
            s.delete(row)


def _unknown() -> HTTPException:
    return HTTPException(404, "Unknown AI provider")


# ---------- Routen ----------

def build_ai_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/ai")

    def last_used(pid: str):
        with ctx.session_factory() as s:
            return setting(s, LAST_USED_PREFIX + pid)

    def listing(pid: str) -> list[dict]:
        return [{"id": m["id"], "name": m["name"], "web": m["web"]} for m in models_for(ctx, pid)]

    def provider_row(pid: str, entry: dict | None) -> dict:
        configured = _configured(ctx, pid)
        if pid == "anthropic":
            row = {"id": pid, "kind": "anthropic", "label": "Anthropic", "key": ctx.secrets.meta(CLAUDE_SECRET)}
        elif pid == "openai":
            row = {"id": pid, "kind": "openai", "label": "OpenAI", "key": ctx.secrets.meta(OPENAI_SECRET)}
        else:
            row = {"id": pid, "kind": "compat", "label": entry["name"] if configured else "Custom endpoint",
                   "key": ctx.secrets.meta(COMPAT_KEY_SECRET)}
            if configured:
                row["display_url"] = entry["display_url"]
        row.update(configured=configured, last_used=last_used(pid), models=listing(pid) if configured else [])
        return row

    @router.get("", dependencies=[Depends(guards.require_session)])
    def get_ai():
        entry = _compat_entry(ctx)
        chosen = _tasks(ctx)
        tasks = {}
        for task in TASKS:
            try:
                provider, model = resolve(ctx, task)
                tasks[task] = {"ref": chosen.get(task) or "", "resolved": f"{provider.pid}:{model}", "error": None}
            except AiError as e:
                tasks[task] = {"ref": chosen.get(task) or "", "resolved": None, "error": str(e)}
        return {"providers": [provider_row(pid, entry) for pid in PIDS], "tasks": tasks}

    @router.put("/providers/{pid}")
    def put_provider(pid: str, body: ProviderIn, found=Depends(guards.require_admin)):
        if pid not in PIDS:
            raise _unknown()
        changed = []
        if pid == COMPAT_ID:
            entry = _compat_entry(ctx)
            if body.base_url is None and entry is None:
                raise _invalid("base_url", "Required")
            url = display = None
            if body.base_url is not None:
                try:
                    url, display = clean_url(body.base_url)
                except ValueError:
                    raise _invalid("base_url", "Must be an http or https address with a host") from None
            key = body.api_key
            if key and not _COMPAT_KEY.fullmatch(key):
                raise _invalid("api_key", "Invalid key")
            name = (body.name or "").strip()
            if any(c in name for c in "\r\n\t"):
                raise _invalid("name", "Invalid name")
            if url is not None:
                ctx.secrets.set(COMPAT_URL_SECRET, url)
                changed.append("address")
            if key:
                ctx.secrets.set(COMPAT_KEY_SECRET, key)
                changed.append("key")
            elif key == "":
                ctx.secrets.delete(COMPAT_KEY_SECRET)
                changed.append("key removed")
            new = {"id": COMPAT_ID, "name": name or (entry or {}).get("name") or urlsplit(url).hostname,
                   "display_url": display or (entry or {}).get("display_url")}
            with ctx.session_factory() as s:
                put_setting(s, COMPAT_KEY, [new])
                if changed:
                    _drop_settings(s, MODELS_PREFIX + pid)   # neue Adresse oder neuer Schlüssel: Liste neu holen
                ctx.audit(s, found[0].username, "ai.provider.saved", f"{pid}: {', '.join(changed) or 'name'}")
                s.commit()
            return {"ok": True}
        secret, pattern = (CLAUDE_SECRET, _ANTHROPIC_KEY) if pid == "anthropic" else (OPENAI_SECRET, _OPENAI_KEY)
        if body.api_key is None:
            if not ctx.secrets.meta(secret)["set"]:
                raise _invalid("api_key", "Required")
        elif not pattern.fullmatch(body.api_key):
            raise _invalid("api_key", "Invalid key")
        else:
            ctx.secrets.set(secret, body.api_key)
            changed.append("key")
        with ctx.session_factory() as s:
            if changed:
                _drop_settings(s, MODELS_PREFIX + pid)
            ctx.audit(s, found[0].username, "ai.provider.saved", f"{pid}: {', '.join(changed) or 'no change'}")
            s.commit()
        return {"ok": True}

    @router.delete("/providers/{pid}")
    def delete_provider(pid: str, found=Depends(guards.require_admin)):
        if pid not in PIDS:
            raise _unknown()
        secrets = {"anthropic": (CLAUDE_SECRET,), "openai": (OPENAI_SECRET,),
                   COMPAT_ID: (COMPAT_URL_SECRET, COMPAT_KEY_SECRET)}[pid]
        for name in secrets:
            ctx.secrets.delete(name)
        with ctx.session_factory() as s:
            _drop_settings(s, MODELS_PREFIX + pid, LAST_USED_PREFIX + pid)   # die Aufgaben-Wahl bleibt stehen
            if pid == COMPAT_ID:
                _drop_settings(s, COMPAT_KEY)
            ctx.audit(s, found[0].username, "ai.provider.removed", pid)
            s.commit()
        return {"ok": True}

    def configured_provider(pid: str) -> Provider:
        if pid not in PIDS:
            raise _unknown()
        provider = _make(ctx, pid)
        if provider is None:
            raise HTTPException(409, "This AI provider is not configured")
        return provider

    @router.post("/providers/{pid}/test")
    def test_provider(pid: str, found=Depends(guards.require_admin)):
        result = configured_provider(pid).check()
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "ai.provider.tested", f"{pid}: {'ok' if result['ok'] else 'error'}")
            s.commit()
        return result

    @router.post("/providers/{pid}/refresh", dependencies=[Depends(guards.require_admin)])
    def refresh_provider(pid: str):
        configured_provider(pid)
        models_for(ctx, pid, refresh=True)
        return {"models": listing(pid)}

    @router.put("/tasks")
    def put_tasks(body: TasksIn, found=Depends(guards.require_admin)):
        refs = {t: getattr(body, t) for t in TASKS}
        for task, ref in refs.items():
            if not ref:
                continue
            pid, model = _split(ref)
            if pid not in PIDS or not model or not _configured(ctx, pid):
                raise _invalid(task, "Provider is not configured")
            listed = models_for(ctx, pid)
            if listed:
                match = next((m for m in listed if m["id"] == model), None)
                if match is None:
                    raise _invalid(task, "Unknown model for this provider")
                is_web = match["web"]
            else:   # Anbieter nicht erreichbar: jede vernünftige Kennung annehmen
                if len(model) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in model):
                    raise _invalid(task, "Invalid model id")
                is_web = _web(pid, model)
            if task in WEB_TASKS and not is_web:
                raise _invalid(task, "This model cannot search the web")
        with ctx.session_factory() as s:
            put_setting(s, TASKS_KEY, refs)
            ctx.audit(s, found[0].username, "ai.tasks", ", ".join(f"{t}={r or 'automatic'}" for t, r in refs.items()))
            s.commit()
        return {"ok": True}

    return router
