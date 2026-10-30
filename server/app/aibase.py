"""Gemeinsame Grundlage aller KI-Anbieter: ein Fehlertyp und die Kurzfassung einer Anbieter-Fehlerantwort."""

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
