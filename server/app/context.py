import logging
from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy.orm import Session, sessionmaker

from .auth import RateLimiter
from .config import Settings
from .secrets_store import SecretStore

log = logging.getLogger("lablantern")


@dataclass
class Context:
    settings: Settings
    session_factory: sessionmaker[Session]
    secrets: SecretStore
    clock: Callable[[], float]
    setup_limiter: RateLimiter
    login_limiter: RateLimiter
    login_ip_limiter: RateLimiter
    worker_token: str = ""
    # erzeugt den Claude-Client zu einem Schlüssel; in Tests ersetzbar (Standard: anthropic.Anthropic)
    claude_factory: Optional[Callable[[str], object]] = None
    # erzeugt den OpenAI-Client zu (Adresse, Schlüssel); in Tests ersetzbar (Standard: openai.OpenAI)
    openai_factory: Optional[Callable[[str, str], object]] = None
    # wird nach einer Zeitplan-Änderung aufgerufen (hängt den laufenden Planer um)
    on_schedule_change: Optional[Callable[[], None]] = None
    # (Titel, Text, HTML für Mail oder None) -> (ok, Fehler); in main.py an Apprise gebunden, in Tests ersetzbar
    notifier: Optional[Callable[..., tuple[bool, Optional[str]]]] = None

    def _release(self):
        from .releases import current_release  # verzögert: vermeidet Importzyklus

        return current_release(self)

    def agent_dir(self):
        """Ausgelieferte Agent-Binaries: das zuletzt geprüfte signierte Release, sonst die mitgebauten."""
        from pathlib import Path

        rel = self._release()
        return Path(rel["dir"]) if rel else self.settings.agent_dir

    def settings_agent_version(self) -> str:
        rel = self._release()
        return rel["version"] if rel else self.settings.agent_version

    def audit(self, s: Session, actor: str, action: str, detail: str = "") -> None:
        from .models import AuditLog

        s.add(AuditLog(ts=self.clock(), actor=actor, action=action, detail=detail))
