"""Alle Aufrufe an Claude (offizielles anthropic-SDK). Nur hier spricht vulnwatch mit Anthropic.

- Schlüssel prüfen und Modelle auflisten (Einstellungen)
- eine Meldung lesen: Fakten über ein festes Werkzeug-Schema (Frühwarnung, Feeds)
- Web-Recherche: aktuelle Sicherheitsmeldungen zu den Produkten im Inventar, weltweit (Frühwarnung)

Texte aus Feeds und Webseiten sind Daten, keine Anweisungen: Sie gehen nur als Nachrichteninhalt hinein, und die
Antwort wird ausschließlich über das Schema ausgewertet. Bewertet und verglichen wird im Code (earlywarning.py)."""
import logging
from typing import Any, Callable

import anthropic

from .aibase import AiError, short_error

log = logging.getLogger("vulnwatch.claude")

# Modelle, die den serverseitigen Refusal-Fallback ("default") annehmen; für sie wird er immer mitgeschickt
FALLBACK_MODELS = ("claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5")
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Websuche mit dynamischer Filterung gibt es ab Sonnet/Opus 4.6; ältere und Haiku-Modelle nehmen die Basisvariante
WEB_SEARCH_DYNAMIC = ("claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-5",
                      "claude-sonnet-4-6", "claude-fable")
MAX_PAUSES = 4


ClaudeError = AiError   # Alias: bestehende Importe und `earlywarning.AiError` bleiben unverändert


def make_client(base_url: str, key: str, factory: Callable[[str], Any] | None = None) -> anthropic.Anthropic:
    if factory:
        return factory(key)
    return anthropic.Anthropic(api_key=key, base_url=base_url, timeout=120.0, max_retries=2)


def _call(client, fn):
    """SDK-Fehler in einen Satz übersetzen; bei sonstigen HTTP-Fehlern mit der Meldung des Anbieters, ohne Schlüssel."""
    try:
        return fn()
    except anthropic.AuthenticationError:
        raise ClaudeError("Anthropic: key invalid (HTTP 401)") from None
    except anthropic.PermissionDeniedError:
        raise ClaudeError("Anthropic: key not permitted (HTTP 403)") from None
    except anthropic.RateLimitError:
        raise ClaudeError("Anthropic: rate limit (HTTP 429)") from None
    except anthropic.APIStatusError as e:
        raise ClaudeError(short_error("Anthropic", e.status_code, e.body, getattr(client, "api_key", None))) from None
    except anthropic.APIConnectionError:
        raise ClaudeError("Anthropic: API unreachable") from None


def check_key(client: anthropic.Anthropic) -> dict:
    try:
        _call(client, lambda: client.models.list(limit=1))
        return {"ok": True}
    except ClaudeError as e:
        return {"ok": False, "error": str(e)}


def list_models(client: anthropic.Anthropic) -> list[dict]:
    """Alle Modelle des Schlüssels, neueste zuerst."""
    def fetch():
        return [{"id": m.id, "name": m.display_name or m.id,
                 "created_at": m.created_at.isoformat() if m.created_at else ""} for m in client.models.list(limit=100)]
    return sorted(_call(client, fetch), key=lambda m: m["created_at"], reverse=True)


def _create(client: anthropic.Anthropic, **params):
    model = params["model"]
    if model in FALLBACK_MODELS:   # Ablehnung durch Sicherheitsfilter: Anthropic leitet an ein passendes Modell weiter
        return _call(client, lambda: client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **params))
    return _call(client, lambda: client.messages.create(**params))


def _tool_input(resp, name: str) -> dict:
    if resp.stop_reason == "refusal":
        raise ClaudeError("Claude declined the request")
    block = next((b for b in resp.content if b.type == "tool_use" and b.name == name), None)
    if block is None:
        raise ClaudeError("answer without the expected tool call")
    return block.input


def ask_tool(client: anthropic.Anthropic, model: str, system: str, text: str, tool: dict) -> tuple[dict, dict]:
    """Ein Aufruf mit genau einem Werkzeug (strict). Liefert (Eingabe des Werkzeugs, Archiv ohne Inhalte)."""
    resp = _create(client, model=model, max_tokens=4000, system=system, tools=[{**tool, "strict": True}],
                   messages=[{"role": "user", "content": text}])
    return _tool_input(resp, tool["name"]), {"id": resp.id, "model": resp.model, "stop_reason": resp.stop_reason,
                                               "usage": resp.usage.model_dump() if resp.usage else None}


def web_search_tool(model: str, max_uses: int) -> dict:
    kind = "web_search_20260209" if model.startswith(WEB_SEARCH_DYNAMIC) else "web_search_20250305"
    return {"type": kind, "name": "web_search", "max_uses": max_uses}


def research(client: anthropic.Anthropic, model: str, system: str, text: str, tool: dict,
             max_searches: int = 15) -> tuple[dict, dict]:
    """Recherche mit Websuche (serverseitig bei Anthropic) in zwei Schritten: erst nur suchen (ohne Bericht-Werkzeug
    kann das Modell die Suche nicht überspringen), dann das Ergebnis über `tool` melden.
    `pause_turn` (Server-Werkzeug braucht mehr Runden) wird fortgesetzt, höchstens MAX_PAUSES-mal."""
    search = web_search_tool(model, max_searches)
    user = {"role": "user", "content": text}
    found: list = []
    searches, sources, usage = 0, [], []

    def call(messages, tools):
        nonlocal searches
        resp = _create(client, model=model, max_tokens=16000, system=system, tools=tools, messages=messages,
                       output_config={"effort": "medium"})
        searches += sum(1 for b in resp.content if b.type == "server_tool_use")
        sources.extend(r.url for b in resp.content if b.type == "web_search_tool_result" and isinstance(b.content, list)
                       for r in b.content if getattr(r, "url", None))
        usage.append(resp.usage.model_dump() if resp.usage else None)
        return resp

    resp = None
    for _ in range(MAX_PAUSES + 1):
        resp = call([user, {"role": "assistant", "content": found}] if found else [user], [search])
        found = [*found, *resp.content]
        if resp.stop_reason != "pause_turn":
            break
    if resp.stop_reason == "refusal":
        raise ClaudeError("Claude declined the request")
    report = {"role": "user", "content": f"Now report what you found by calling {tool['name']} exactly once. "
                                         f"Leave fields empty (or lists empty) where nothing was found."}
    # Die Websuche muss im zweiten Schritt definiert bleiben (der Verlauf enthält ihre Blöcke), sucht aber kaum noch
    resp = call([user, {"role": "assistant", "content": found}, report],
                [web_search_tool(model, 1), {**tool, "strict": True}])
    archive = {"id": resp.id, "model": resp.model, "stop_reason": resp.stop_reason, "searches": searches,
               "usage": usage, "sources": list(dict.fromkeys(sources))[:50]}
    return _tool_input(resp, tool["name"]), archive
