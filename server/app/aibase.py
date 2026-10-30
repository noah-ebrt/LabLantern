"""Gemeinsame Grundlage aller KI-Anbieter: ein Fehlertyp und die Kurzfassung einer Anbieter-Fehlerantwort."""

from typing import Protocol

MAX_ERROR = 300


class AiError(Exception):
    """Jeder Fehler beim Aufruf eines Anbieters; die Frühwarnung macht daraus „needs review“, nie eine Lücke."""


def short_error(provider: str, status: int | None, body, secret: str | None) -> str:
    """„<Anbieter>: <Meldung des Anbieters> (HTTP <Code>)“: Meldung auf 300 Zeichen gekürzt, Schlüssel entfernt."""
    msg = None
    if isinstance(body, dict):
        err = body.get("error")
        msg = err.get("message") if isinstance(err, dict) else err
        if msg is None:
            msg = body.get("message")
    elif body is not None:
        msg = body
    text = str(msg) if msg else "request failed"
    if secret:
        text = text.replace(secret, "***")
    text = " ".join(text.split())[:MAX_ERROR] or "request failed"
    return f"{provider}: {text}" + (f" (HTTP {status})" if status is not None else "")


class Provider(Protocol):
    """Was die Frühwarnung von einem KI-Anbieter braucht; jede Implementierung wirft bei Fehlern AiError."""
    pid: str            # "anthropic" | "openai" | "c1"
    label: str          # "Anthropic" | "OpenAI" | Anzeigename des Endpunkts
    web_search: bool    # der Anbietertyp kann überhaupt im Web suchen

    def check(self) -> dict: ...         # {"ok": bool, "error"?: str}

    def list_models(self) -> list[dict]: ...   # [{"id", "name", "created_at"}], neueste zuerst

    def ask_tool(self, model: str, system: str, text: str, tool: dict) -> tuple[dict, dict]: ...

    def research(self, model: str, system: str, text: str, tool: dict, max_searches: int = 15) -> tuple[dict, dict]: ...
