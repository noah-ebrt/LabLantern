"""Alle Aufrufe an OpenAI und an OpenAI-kompatible Endpunkte (Ollama, LM Studio, OpenRouter …), offizielles openai-SDK.

- Schlüssel prüfen und Modelle auflisten (Einstellungen)
- eine Meldung lesen: Fakten über ein festes Werkzeug-Schema (Chat Completions)
- Web-Recherche über das `web_search`-Werkzeug der Responses-API (nur bei OpenAI selbst, nicht bei eigenen Endpunkten)

Texte aus Feeds und Webseiten sind Daten, keine Anweisungen: Sie gehen nur als Nachrichteninhalt hinein, und die
Antwort wird ausschließlich über das Schema ausgewertet. Bewertet und verglichen wird im Code (earlywarning.py)."""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

import openai

from .aibase import AiError, quick, short_error

log = logging.getLogger("vulnwatch.openai")

OPENAI_BASE = "https://api.openai.com/v1"
# Chat-Modelle bei OpenAI (Präfixe); alles andere in der Modellliste (Bilder, Audio, Embeddings …) wird nicht angeboten
CHAT_PREFIX = ("gpt-", "o1", "o3", "o4", "chatgpt-")
NOT_CHAT = ("audio", "realtime", "transcribe", "tts", "image", "embedding", "search", "instruct", "moderation",
            "-pro", "codex")   # -pro/codex: nur über die Responses-API, Chat Completions lehnt sie ab
# Modelle mit dem `web_search`-Werkzeug der Responses-API (Präfixe, Stand der OpenAI-Doku); nano-Modelle nehmen es nicht
OPENAI_WEB = ("gpt-4o", "gpt-4.1", "gpt-5", "gpt-6", "o3")
MAX_SOURCES = 50


def chat_model(model_id: str) -> bool:
    return model_id.startswith(CHAT_PREFIX) and not any(w in model_id for w in NOT_CHAT)


def openai_web(model_id: str) -> bool:
    return model_id.startswith(OPENAI_WEB) and "nano" not in model_id


def make_openai_client(base_url: str, key: str | None, factory: Callable[[str, str], Any] | None = None):
    if factory:
        return factory(base_url, key or "none")
    # Das SDK folgt Weiterleitungen von sich aus; hier nicht: Schlüssel und Anfrage gehen nur an die eingestellte Adresse
    return openai.OpenAI(api_key=key or "none", base_url=base_url, timeout=120.0, max_retries=2,
                         http_client=openai.DefaultHttpxClient(follow_redirects=False))


def _message(resp):
    """Die Antwortnachricht, oder None, wenn der Endpunkt keine Auswahl liefert (leeres `choices`)."""
    return resp.choices[0].message if resp.choices else None


def _usage(u) -> dict | None:
    return u.model_dump() if u is not None and hasattr(u, "model_dump") else None


def _first_object(text: str) -> dict | None:
    """Das erste `{…}`-Objekt im Text (Modelle ohne Werkzeug-Unterstützung schreiben oft Prosa drumherum)."""
    dec, i = json.JSONDecoder(), text.find("{")
    while i != -1:
        try:
            obj, _ = dec.raw_decode(text, i)
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        i = text.find("{", i + 1)
    return None


class OpenAIProvider:
    """OpenAI oder ein OpenAI-kompatibler Endpunkt hinter der gemeinsamen Anbieter-Schnittstelle (aibase.Provider).
    `compat` = eigener Endpunkt: kein Strict-Schema, JSON-Rückfall ohne Werkzeuge, keine Websuche."""

    def __init__(self, client, pid: str, label: str, compat: bool):
        self.client, self.pid, self.label, self.compat = client, pid, label, compat
        self.web_search = not compat

    def _secret(self) -> str | None:
        key = getattr(self.client, "api_key", None)
        return None if key in (None, "", "none") else key

    def _call(self, fn, soft: bool = False):
        """SDK-Fehler in einen Satz übersetzen: Meldung des Anbieters, ohne Schlüssel.
        `soft`: eine abgelehnte Anfrage (HTTP 400) ergibt None statt eines Fehlers."""
        try:
            return fn()
        except openai.BadRequestError as e:
            if soft:
                return None
            raise AiError(short_error(self.label, e.status_code, e.body, self._secret())) from None
        except openai.APIStatusError as e:
            raise AiError(short_error(self.label, e.status_code, e.body, self._secret())) from None
        except openai.APIConnectionError:
            raise AiError(f"{self.label}: API unreachable") from None

    def check(self) -> dict:
        try:
            self._call(lambda: list(quick(self.client).models.list()))
            return {"ok": True}
        except AiError as e:
            return {"ok": False, "error": str(e)}

    def list_models(self) -> list[dict]:
        """Alle Chat-Modelle des Schlüssels (bei eigenen Endpunkten alle gelisteten), neueste zuerst."""
        models = self._call(lambda: list(quick(self.client).models.list()))
        rows = [(m.id, m.created or 0) for m in models if self.compat or chat_model(m.id)]
        rows.sort(key=lambda r: r[1], reverse=True)
        return [{"id": i, "name": i, "created_at": datetime.fromtimestamp(c, timezone.utc).isoformat() if c else ""}
                for i, c in rows]

    # ---------- eine Meldung lesen ----------

    def _chat(self, soft: bool = False, **params):
        """Chat Completions; Token-Grenze je nach Endpunkt (OpenAI-Modelle mit Reasoning kennen max_tokens nicht)."""
        limit = {"max_tokens": 8000} if self.compat else {"max_completion_tokens": 16000}
        return self._call(lambda: self.client.chat.completions.create(**params, **limit), soft)

    def ask_tool(self, model: str, system: str, text: str, tool: dict) -> tuple[dict, dict]:
        """Ein Aufruf mit genau einem Werkzeug. Liefert (Eingabe des Werkzeugs, Archiv ohne Inhalte).
        Eigene Endpunkte ohne Werkzeug-Unterstützung bekommen einmal den Rückfall auf JSON-Ausgabe."""
        fn = {"name": tool["name"], "description": tool["description"], "parameters": tool["input_schema"]}
        if not self.compat:
            fn["strict"] = True
        resp = self._chat(soft=self.compat, model=model,
                          messages=[{"role": "system", "content": system}, {"role": "user", "content": text}],
                          tools=[{"type": "function", "function": fn}],
                          tool_choice={"type": "function", "function": {"name": tool["name"]}})
        args = self._tool_arguments(resp, tool["name"]) if resp is not None else None
        if args is None and self.compat:
            schema = json.dumps(tool["input_schema"])
            resp = self._chat(model=model, response_format={"type": "json_object"}, messages=[
                {"role": "system", "content": f"{system}\n\nAnswer with one JSON object matching this schema: {schema}"},
                {"role": "user", "content": text}])
            msg = _message(resp)
            args = _first_object(msg.content or "") if msg is not None else None
            if args is None:
                raise AiError(f"{self.label}: answer is not valid JSON")
        if args is None:
            raise AiError(f"{self.label}: answer without the expected tool call")
        return args, self._archive(resp)

    def _tool_arguments(self, resp, name: str) -> dict | None:
        msg = _message(resp)
        if msg is None:
            return None
        if getattr(msg, "refusal", None):
            raise AiError(f"{self.label} declined the request")
        call = next((c for c in (msg.tool_calls or []) if c.function.name == name), None)
        if call is None:
            return None
        try:
            args = json.loads(call.function.arguments)
        except ValueError:
            args = None
        if not isinstance(args, dict):
            if self.compat:
                return None
            raise AiError(f"{self.label}: answer is not valid JSON")
        return args

    def _archive(self, resp) -> dict:
        return {"id": resp.id, "model": resp.model, "stop_reason": resp.choices[0].finish_reason if resp.choices else None,
                "usage": _usage(resp.usage)}

    # ---------- Recherche (nur OpenAI selbst) ----------

    def research(self, model: str, system: str, text: str, tool: dict, max_searches: int = 15) -> tuple[dict, dict]:
        """Recherche mit Websuche (serverseitig bei OpenAI, Responses-API) in zwei Schritten: erst nur suchen (ohne
        Bericht-Werkzeug kann das Modell die Suche nicht überspringen), dann das Ergebnis über `tool` melden."""
        if self.compat:
            raise AiError(f"{self.label}: no web search")
        searches, sources, usage = 0, [], []

        def call(**params):
            nonlocal searches
            resp = self._call(lambda: self.client.responses.create(model=model, instructions=system,
                                                                   max_output_tokens=16000, **params))
            for item in resp.output or []:
                if item.type == "web_search_call":
                    searches += 1
                elif item.type == "message":
                    sources.extend(a.url for c in item.content or [] for a in getattr(c, "annotations", None) or []
                                   if a.type == "url_citation" and getattr(a, "url", None))
            usage.append(_usage(resp.usage))
            return resp

        found = call(input=text, tools=[{"type": "web_search"}], max_tool_calls=max_searches)
        report = (f"Now report what you found by calling {tool['name']} exactly once. "
                  f"Leave fields empty (or lists empty) where nothing was found.")
        fn = {"type": "function", "name": tool["name"], "description": tool["description"],
              "parameters": tool["input_schema"], "strict": True}
        resp = call(input=report, previous_response_id=found.id, tools=[fn],
                    tool_choice={"type": "function", "name": tool["name"]})
        item = next((i for i in resp.output or [] if i.type == "function_call" and i.name == tool["name"]), None)
        if item is None:
            raise AiError(f"{self.label}: answer without the expected tool call")
        try:
            args = json.loads(item.arguments)
        except ValueError:
            args = None
        if not isinstance(args, dict):
            raise AiError(f"{self.label}: answer is not valid JSON")
        archive = {"id": resp.id, "model": resp.model, "stop_reason": getattr(resp, "status", None),
                   "searches": searches, "usage": usage, "sources": list(dict.fromkeys(sources))[:MAX_SOURCES]}
        return args, archive
