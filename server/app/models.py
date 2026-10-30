import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String, Text
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """SQLite speichert keine Zone: geschrieben wird UTC ohne Offset, gelesen kommt UTC mit Offset zurück.
    So trägt jedes isoformat() der API "+00:00" und der Browser liest es nicht als Ortszeit."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


class Secret(Base):
    __tablename__ = "secrets"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String)


def setting(s, key: str, default=None, *, raw: bool = False):
    """Wert aus `settings` lesen: JSON-dekodiert, mit raw=True der gespeicherte Text."""
    row = s.get(Setting, key)
    if row is None:
        return default
    return row.value if raw else json.loads(row.value)


def put_setting(s, key: str, value, *, raw: bool = False) -> None:
    """Wert in `settings` anlegen oder ersetzen (commit macht der Aufrufer)."""
    text = value if raw else json.dumps(value)
    row = s.get(Setting, key)
    if row is None:
        s.add(Setting(key=key, value=text))
    else:
        row.value = text


class AdminUser(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="admin")
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class SessionRow(Base):
    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String)
    expires_at: Mapped[float] = mapped_column(Float)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[float] = mapped_column(Float)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    detail: Mapped[str] = mapped_column(String, default="")


class System(Base):
    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    host_type: Mapped[str] = mapped_column(String, default="linux")
    ip: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, active, revoked
    agent_token_hash: Mapped[str] = mapped_column(String, default="")
    agent_version: Mapped[str] = mapped_column(String, default="")
    enrolled_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    security_updates_count: Mapped[int] = mapped_column(Integer, default=0)
    reboot_required: Mapped[bool] = mapped_column(Boolean, default=False)
    container_count: Mapped[int] = mapped_column(Integer, default=0)
    inventory_json: Mapped[str] = mapped_column(Text, default="{}")
    collection_errors: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # {packages|containers|security_updates: Text}
    sbom_updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    last_contact: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)  # letzter Long-Poll
    # Freigabezeit, solange der erste Report danach noch aussteht (dann None): „Initialisierung“, nach 3 min Fehler
    awaiting_report_since: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    # Soll-Zustand (PLAN Abschnitt 6): Namen der Container, die laufen sollen. Leer = noch nie festgelegt,
    # dann übernimmt der erste Report die laufenden Container. Fehlende oder unbekannte sind ein Fund.
    expected_containers: Mapped[str] = mapped_column(Text, default="", server_default="")
    # Von Hand als internet-erreichbar markierte Container (JSON-Liste von Namen), dazu die aus dem NPM-Connector
    exposed_containers: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")


class ImageSbom(Base):
    """SBOM eines Container-Images, vom Agenten lokal mit Syft erzeugt (Datei unter data/images/<System>/).
    Je System getrennt: Sonst könnte ein übernommener Agent die SBOM eines Images für alle Hosts ersetzen.
    Die alte, globale Tabelle `image_sboms` wird nicht mehr benutzt; die Agenten liefern beim nächsten Report neu."""

    __tablename__ = "system_image_sboms"

    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), primary_key=True)
    image_id: Mapped[str] = mapped_column(String, primary_key=True)
    error: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    expires_at: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    status: Mapped[str] = mapped_column(String, default="running")  # queued, running, success, failed
    canary_status: Mapped[str] = mapped_column(String, default="ok")  # ok, fehler
    canary_details: Mapped[str] = mapped_column(Text, default="")
    summary_counts: Mapped[str] = mapped_column(Text, default="{}")
    trigger: Mapped[str] = mapped_column(String, default="manual", server_default="manual")  # manual, scheduled
    db_status: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # Frische-Gate der Scanner-DB
    error: Mapped[str] = mapped_column(Text, default="", server_default="")
    notify_status: Mapped[str] = mapped_column(String, default="", server_default="")
    archive_status: Mapped[str] = mapped_column(String, default="", server_default="")  # ok, failed: …
    config_version: Mapped[str] = mapped_column(String, default="", server_default="")
    coverage_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)  # für den Verlauf


class Finding(Base):
    __tablename__ = "findings"
    # Die Tabelle wächst auf >100 000 Zeilen (Grype meldet auch „negligible“); ohne Index wird jede Liste langsam.
    __table_args__ = (Index("ix_findings_status_severity", "status", "severity"),
                      Index("ix_findings_system_status", "system_id", "status"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"))
    cve_id: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String, default="")
    severity: Mapped[str] = mapped_column(String)  # kritisch, hoch, mittel, info
    component: Mapped[str] = mapped_column(String)
    installed_version: Mapped[str] = mapped_column(String, default="")
    fixed_version: Mapped[str] = mapped_column(String, default="")
    cvss_score: Mapped[float] = mapped_column(Float, default=0.0)
    epss_score: Mapped[float] = mapped_column(Float, default=0.0)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String, default="grype")  # grype, osv, both
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String, default="open")  # open, accepted, resolved
    accepted_reason: Mapped[str] = mapped_column(String, default="")
    accepted_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen_run_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    target: Mapped[str] = mapped_column(String, default="host", server_default="host")  # host oder image:<Referenz>
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)


class Snooze(Base):
    """Zurückgestellter Fund (PLAN-extensions A2). Quelle der Wahrheit; Finding.status "accepted" folgt daraus."""
    __tablename__ = "snoozes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String)                      # occurrence oder everywhere
    cve_id: Mapped[str] = mapped_column(String)
    component: Mapped[str] = mapped_column(String)
    system_id: Mapped[int | None] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), nullable=True)
    target_key: Mapped[str] = mapped_column(String, default="")    # host oder image:<Registry/Repository>
    reason: Mapped[str] = mapped_column(String)
    until: Mapped[datetime] = mapped_column(UTCDateTime())
    created_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    baseline_severity: Mapped[str] = mapped_column(String, default="info")
    baseline_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    baseline_has_fix: Mapped[bool] = mapped_column(Boolean, default=False)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    end_reason: Mapped[str] = mapped_column(String, default="", server_default="")


class CoverageExclusion(Base):
    """Ausnahme von der Abdeckung mit Grund (z. B. gestoppte Test-VM); gleiche Regeln wie ein Snooze."""
    __tablename__ = "coverage_exclusions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(String)   # system:<id>, später pve-guest:<node>/<vmid>
    reason: Mapped[str] = mapped_column(String)
    until: Mapped[datetime] = mapped_column(UTCDateTime())
    created_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    end_reason: Mapped[str] = mapped_column(String, default="", server_default="")


class SystemScanResult(Base):
    """Ergebnis der Paketprüfung je System und Lauf. Ohne Eintrag oder mit `fehler` gilt die Prüfung nicht als ok."""

    __tablename__ = "system_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"))
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String)  # ok, fehler
    error: Mapped[str] = mapped_column(Text, default="", server_default="")
    findings_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    image_errors: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # {Image-ID: Fehler}
    # keine frischen Daten in diesem Lauf (Fehler oder Agent seit über 2 h still); zweimal in Folge = Sofort-Alarm
    no_data: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String)  # system, canary
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, running, done, failed
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    error_message: Mapped[str] = mapped_column(Text, default="")
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    queued_at: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    claimed_at: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    payload: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # Systeme des Laufs
    progress: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")  # aktueller Schritt (Worker)



class AgentCommand(Base):
    """Befehl an einen Agenten aus der festen Liste (commands.py); Ergebnis als Text."""

    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("systems.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String)
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String, default="queued")  # queued, sent, done, failed, rejected, expired
    created_by: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[float] = mapped_column(Float)
    sent_at: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    output: Mapped[str] = mapped_column(Text, default="")


class Passkey(Base):
    """WebAuthn-Passkey eines Admins (nur ES256). Der öffentliche Schlüssel geht signiert auch an die Agenten."""

    __tablename__ = "passkeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(String, unique=True)  # base64url
    public_key: Mapped[bytes] = mapped_column(LargeBinary)  # COSE
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[float] = mapped_column(Float)
    last_used: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)


class Pairing(Base):
    """Anfrage eines neuen Agenten über `vulnwatch-agent setup`; wird erst nach Code-Vergleich freigegeben."""

    __tablename__ = "pairings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String)
    host_type: Mapped[str] = mapped_column(String, default="linux")
    agent_version: Mapped[str] = mapped_column(String, default="")
    ip: Mapped[str] = mapped_column(String, default="")
    code: Mapped[str] = mapped_column(String)   # leer, bis der Agent sein Geheimnis aufgedeckt hat
    secret_hash: Mapped[str] = mapped_column(String)   # = Commitment des Agenten: SHA-256 des Geheimnisses
    nonce: Mapped[str] = mapped_column(String, default="", server_default="")   # Zufall des Masters, geht in den Code ein
    status: Mapped[str] = mapped_column(String, default="pending")  # committed, pending, approved, rejected, collected
    created_at: Mapped[float] = mapped_column(Float)
    system_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)


class EarlyWarning(Base):
    """KI-Frühwarnung (PLAN Abschnitt 5): ein vorgefilterter Feed-Eintrag mit Klassifikation.
    `ai_json` archiviert Anfrage und Antwort (ohne Schlüssel), damit jede Einstufung nachvollziehbar bleibt."""

    __tablename__ = "early_warnings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_key: Mapped[str] = mapped_column(String, unique=True)   # SHA-256 aus Feed und Eintrags-ID
    feed: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String, default="")
    link: Mapped[str] = mapped_column(String, default="")
    published: Mapped[str] = mapped_column(String, default="")
    matched: Mapped[str] = mapped_column(Text, default="[]")       # Produkte aus dem Inventar, die der Vorfilter fand
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, betroffen, nicht_betroffen, unklar
    exploited: Mapped[str] = mapped_column(String, default="unbekannt")
    cves: Mapped[str] = mapped_column(Text, default="[]")
    detail: Mapped[str] = mapped_column(Text, default="")           # Begründung der Einstufung (Code, nicht KI)
    affected: Mapped[str] = mapped_column(Text, default="[]")       # [{system_id, system, product, version}]
    ai_json: Mapped[str] = mapped_column(Text, default="{}")
    origin: Mapped[str | None] = mapped_column(String, nullable=True, default="feed")      # feed, research
    severity: Mapped[str | None] = mapped_column(String, nullable=True, default=None)      # rules.classify_early_warning
    actions: Mapped[str | None] = mapped_column(Text, nullable=True, default="[]")         # empfohlene Schritte (Code)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    classified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    notified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, default=None)
    duplicate_of: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)  # schon gemeldetes Problem
