import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, or_, select

from . import auth
from .connectors import connector_exposed
from .containers import container_diff, exposed_names, learn_baseline, running_names, set_expected
from .context import Context
from .guards import Guards, client_ip
from .models import AgentCommand, EnrollmentToken, ImageSbom, System
from .sbom import build_cyclonedx
from .scanrun import (IMAGE_ID, advance_collecting_runs, agent_should_report, image_sbom_path, remove_system_files,
                      system_images)
from .trust import ca_fingerprint

ARCHES = ("amd64", "arm64")
# Ausgelieferte Dateien: Pakete (.deb/.rpm) für Installation und Update, rohe Binaries nur zum Herunterladen.
PACKAGES = tuple(f"{a}.{p}" for a in ARCHES for p in ("deb", "rpm"))
DOWNLOADS = ARCHES + PACKAGES
ERROR_KEYS = ("packages", "containers", "security_updates")
SAFE_LABEL_PREFIXES = ("com.docker.compose.", "org.opencontainers.")   # gleiche Liste im Agenten (collector)
INIT_WINDOW = 180.0     # so lange darf ein frisch freigegebener Agent bis zum ersten Report brauchen
STALE_HOURS = 24
ONLINE_WINDOW = 120.0   # letzter Long-Poll jünger als das: verbunden


def system_state(ctx: Context, r: System) -> str:
    """pending | revoked | initializing | error (kein erster Report) | offline (veraltet) | online"""
    if r.status == "connector":   # TrueNAS/Home Assistant: letzter API-Abruf gelungen und frisch
        fresh = r.last_seen is not None and (datetime.now(timezone.utc) - r.last_seen).total_seconds() <= STALE_HOURS * 3600
        return "online" if fresh and "connector" not in json.loads(r.collection_errors or "{}") else "offline"
    if r.status != "active":
        return r.status
    if r.awaiting_report_since is not None:
        return "initializing" if ctx.clock() - r.awaiting_report_since < INIT_WINDOW else "error"
    seen = r.last_seen
    if seen is None:
        return "error"
    return "offline" if (datetime.now(timezone.utc) - seen).total_seconds() > STALE_HOURS * 3600 else "online"


def is_connected(ctx: Context, r: System) -> bool:
    return r.last_contact is not None and ctx.clock() - r.last_contact < ONLINE_WINDOW


SIGNED_TYPES = ("reboot", "update_agent", "uninstall")
COMMAND_TTL = 300.0     # nicht abgeholte Befehle verfallen nach 5 min
SENT_TIMEOUT = 900.0    # abgeholt, aber nach 15 min keine Antwort: gescheitert (Update braucht am längsten)


def pending_actions(ctx: Context, s) -> dict[int, str]:
    """Laufende gefährliche Aktion je System. Solange eine läuft, nimmt der Server keine weitere an."""
    now = ctx.clock()
    rows = s.execute(select(AgentCommand.system_id, AgentCommand.type).where(
        AgentCommand.type.in_(SIGNED_TYPES),
        or_(and_(AgentCommand.status == "queued", AgentCommand.created_at >= now - COMMAND_TTL),
            and_(AgentCommand.status == "sent", AgentCommand.sent_at >= now - SENT_TIMEOUT)))).all()
    return {sid: typ for sid, typ in rows}


def live_snapshot(ctx: Context) -> dict:
    """Zeitabhängige Anzeige je System; ändert sie sich, meldet der Live-Wächter „systems“."""
    with ctx.session_factory() as s:
        actions = pending_actions(ctx, s)
        return {r.id: (system_state(ctx, r), is_connected(ctx, r), actions.get(r.id))
                for r in s.scalars(select(System))}


class EnrollIn(BaseModel):
    enrollment_token: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=100)
    ip: str = Field(default="", max_length=64)
    host_type: str = Field(default="linux", max_length=20)
    agent_version: str = Field(default="0.1.0", max_length=32)


class ContainerInfo(BaseModel):
    id: str = Field(default="", max_length=80)
    name: str = Field(default="", max_length=200)
    image: str = Field(default="", max_length=500)
    image_id: str = Field(default="", max_length=200)
    repo_digests: list[str] = Field(default_factory=list, max_length=50)
    ports: list[int] = Field(default_factory=list, max_length=200)
    labels: dict[str, str] = Field(default_factory=dict)

    @field_validator("labels")
    @classmethod
    def _harmless_labels(cls, v: dict[str, str]) -> dict[str, str]:
        # Labels tragen oft Zugangsdaten (Traefik-Basic-Auth, OAuth …); gespeichert wird nur Unverfängliches.
        return {k: val for k, val in v.items() if k.startswith(SAFE_LABEL_PREFIXES)}
    created: str = Field(default="", max_length=40)
    state: str = Field(default="running", max_length=40)


class PackageIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=200)
    arch: str = Field(default="", max_length=40)
    source: str = Field(default="", max_length=300)
    source_version: str = Field(default="", max_length=200)
    type: str = Field(default="deb", max_length=16)


class UpdateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    to: str = Field(default="", max_length=200)
    from_: str = Field(default="", max_length=200, alias="from")


class AgentReportIn(BaseModel):
    agent_version: str = Field(default="0.1.0", max_length=32)
    os_name: str = Field(default="", max_length=200)
    os_id: str = Field(default="", max_length=40, pattern=r"^[a-z0-9._-]*$")
    os_version_id: str = Field(default="", max_length=40, pattern=r"^[A-Za-z0-9._-]*$")
    kernel: str = Field(default="", max_length=100)
    arch: str = Field(default="", max_length=40)
    security_updates_count: int = Field(default=0, ge=0, le=1_000_000)
    security_updates_known: bool = True
    security_updates: list[UpdateIn] = Field(default_factory=list, max_length=2000)   # welche (ab 0.15)
    reboot_required: bool = False
    containers: list[ContainerInfo] = Field(default_factory=list, max_length=5000)
    host_ports: list[int] = Field(default_factory=list, max_length=2000)   # Dienste des Hosts (ab 0.14)
    packages: list[PackageIn] = Field(default_factory=list, max_length=100_000)
    collection_errors: dict[str, str] = Field(default_factory=dict)


def agent_packages(ctx: Context) -> dict[str, str | None]:
    """SHA-256 der Agent-Pakete, die dieser Server ausliefert (None = nicht vorhanden)."""
    out: dict[str, str | None] = {}
    for name in PACKAGES:
        path = ctx.agent_dir() / f"vulnwatch-agent-linux-{name}" if ctx.agent_dir() else None
        out[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path and path.is_file() else None
    return out


def _public_endpoint(ctx: Context, host_header: str) -> str:
    """Adresse, unter der Agenten den Server erreichen. Der Host-Header zählt nur, wenn er ein konfigurierter
    Name ist; sonst käme eine fremde Adresse in einen Befehl, den der Admin kopiert und als root ausführt."""
    allowed = [h for h in ctx.settings.hostnames if h.lower() != "localhost"] or ["localhost"]
    m = re.match(r"^(?P<host>\[[0-9a-fA-F:]+\]|[^:]+)(?::(?P<port>\d{1,5}))?$", host_header or "")
    if m and m["host"].lower() in {h.lower() for h in allowed}:
        return f"https://{m['host']}:{m['port'] or ctx.settings.public_port}"
    return f"https://{allowed[0]}:{ctx.settings.public_port}"


def _agent_endpoint(ctx: Context, host_header: str) -> str:
    """Adresse für Agenten: bevorzugt eine konfigurierte IP. Neue Hosts nutzen oft nicht den DNS, der
    Namen wie vulnwatch.lan kennt; Agenten brauchen den Namen nicht (der ist nur für Passkeys im Browser)."""
    for h in ctx.settings.hostnames:
        try:
            ipaddress.ip_address(h.strip("[]"))
        except ValueError:
            continue
        return f"https://{h}:{ctx.settings.public_port}"
    return _public_endpoint(ctx, host_header)


# Ab dieser Agent-Version: Pairing mit Commit/Reveal, `setup --ca-fingerprint` und `--passkeys-sha256`.
# Ältere Agenten kennen die Optionen nicht; ihnen wird `setup` gar nicht erst angeboten.
SECURE_SETUP_VERSION = (0, 12, 0)


def _trust_pin(ctx: Context, version: str) -> str:
    """`--passkeys-sha256 …` für den Befehl, den der Admin kopiert: Der Agent übernimmt dann als erste Passkey-Liste
    nur genau diese (statt irgendeiner, die ein übernommener Master später liefert)."""
    if _version(version) < SECURE_SETUP_VERSION:
        return ""
    from .passkeys import trust_for_agents   # spät importiert: passkeys importiert agent_api
    with ctx.session_factory() as s:
        trust = trust_for_agents(s)
    return f" --passkeys-sha256 {hashlib.sha256(trust['envelope'].encode()).hexdigest()}" if trust else ""


def _install_cmd(base: str, token: str, fp: str, sums: dict[str, str | None], pin: str = "") -> str | None:
    part = _package_part(base, sums)
    if part is None:
        return None
    # enroll startet den Daemon neu, danach meldet er sofort
    return f"{part} && sudo vulnwatch-agent enroll --server {base} --token {token} --ca-fingerprint {fp}{pin}"


class ImageSbomIn(BaseModel):
    image_id: str = Field(max_length=80)
    sbom: dict[str, Any] | None = None
    error: str = Field(default="", max_length=500)


def _version(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in (v or "0").split("."))


def _package_part(base: str, sums: dict[str, str | None]) -> str | None:
    """Lädt das passende Paket, prüft die Prüfsumme und installiert es. Das Paket legt den Benutzer
    vulnwatch und die systemd-Units an und räumt eine alte Handinstallation (bis 0.5.x) weg."""
    available = {n: s for n, s in sums.items() if s}
    if not available:
        return None
    cases = " ".join(f"{n}) SUM={s};;" for n, s in available.items())
    return (
        "ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && "
        "if command -v dpkg >/dev/null; then PKG=deb; else PKG=rpm; fi && "
        f"case \"$ARCH.$PKG\" in {cases} *) echo \"no agent package for $ARCH.$PKG\" >&2; exit 1;; esac && "
        "T=$(mktemp -d) && "
        f"curl -fsSLk \"{base}/api/agent/download/$ARCH.$PKG\" -o \"$T/vulnwatch-agent.$PKG\" && "
        "echo \"$SUM  $T/vulnwatch-agent.$PKG\" | sha256sum -c - && "
        "if [ \"$PKG\" = deb ]; then sudo dpkg -i \"$T/vulnwatch-agent.deb\"; "
        "else sudo rpm -U --replacepkgs \"$T/vulnwatch-agent.rpm\"; fi && "
        "rm -rf \"$T\""
    )


def _sbom_path(ctx: Context, system_id: int):
    return ctx.settings.data_dir / "sboms" / f"{system_id}.json"


def agent_system(s, authorization: str | None) -> System:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header with bearer token required")
    token_hash = auth.sha256_hex(authorization.removeprefix("Bearer ").strip())
    system = s.scalar(select(System).where(System.agent_token_hash == token_hash))
    if not system:
        raise HTTPException(401, "Invalid agent token")
    if system.status == "pending":
        raise HTTPException(403, "System is waiting for approval by the administrator")
    if system.status == "revoked":
        raise HTTPException(403, "Agent access for this system was revoked")
    if system.status == "connector":   # hat kein Token; nur zur Sicherheit
        raise HTTPException(403, "System is read through a connector")
    return system


def build_agent_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    # --- Verwaltung (Admin) ---

    @router.post("/systems/enrollment-token")
    def create_enrollment_token(request: Request, _found=Depends(guards.require_admin)):
        fp = ca_fingerprint(ctx.settings)
        if fp is None:
            raise HTTPException(503, "Root certificate of the TLS layer unreadable: without its fingerprint "
                                     "no agent can be set up securely")
        raw_token = auth.new_token(24)
        expires_at = ctx.clock() + 3600.0
        with ctx.session_factory() as s:
            s.add(EnrollmentToken(token_hash=auth.sha256_hex(raw_token), expires_at=expires_at))
            s.commit()
        base = _agent_endpoint(ctx, request.headers.get("host", ""))
        version = ctx.settings_agent_version()
        pin = _trust_pin(ctx, version)
        part = _package_part(base, agent_packages(ctx))
        return {
            "token": raw_token,
            "expires_at": expires_at,
            "server_url": base,
            "ca_fingerprint": fp,
            "enroll_cmd": f"vulnwatch-agent enroll --server {base} --token {raw_token} --ca-fingerprint {fp}{pin}",
            "install_cmd": _install_cmd(base, raw_token, fp, agent_packages(ctx), pin),
            # ohne Token, mit Pairing-Code; der Fingerabdruck im Befehl macht einen falschen Master sofort sichtbar
            "setup_cmd": (f"{part} && sudo vulnwatch-agent setup --master {base} --ca-fingerprint {fp}{pin}"
                          if part and _version(version) >= SECURE_SETUP_VERSION else None),
        }

    def system_dict(r: System, detail: bool = False, actions: dict[int, str] | None = None) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        seen = r.last_seen
        age = round((now - seen).total_seconds() / 3600, 1) if seen else None
        out = {
            "id": r.id, "name": r.name, "host_type": r.host_type, "ip": r.ip, "status": r.status,
            "state": system_state(ctx, r),
            "pending_action": (actions or {}).get(r.id),   # update_agent | reboot | uninstall, solange offen
            "agent_version": r.agent_version,
            "enrolled_at": r.enrolled_at.isoformat() if r.enrolled_at else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "age_hours": age, "is_stale": age is None or age > STALE_HOURS,
            "security_updates_count": r.security_updates_count, "reboot_required": r.reboot_required,
            "container_count": r.container_count,
            "collection_errors": json.loads(r.collection_errors or "{}"),
            "sbom_updated_at": r.sbom_updated_at.isoformat() if r.sbom_updated_at else None,
            # Connectors (Home Assistant, TrueNAS) haben keinen Agenten
            "agent_outdated": r.status != "connector" and _version(r.agent_version) < _version(ctx.settings_agent_version()),
            # hält gerade eine Long-Poll-Verbindung (ab 0.7): Befehle kommen in Sekunden an
            "online": is_connected(ctx, r),
            # vor 0.3.0: kein CA-Pinning und kein systemd-Dienst, ein Binary-Update reicht nicht
            "needs_reenroll": r.status != "connector" and _version(r.agent_version) < (0, 3, 0),
        }
        if r.status == "connector":
            data = json.loads(r.inventory_json or "{}").get("connector") or {}
            out["connector"] = {"kind": r.host_type, "version": data.get("version", "")}
        if detail:
            try:
                out["inventory"] = json.loads(r.inventory_json)
            except json.JSONDecodeError:
                out["inventory"] = {}
            out["containers_expected"] = container_diff(r)
            out["exposed_containers"] = sorted(exposed_names(r))
        return out

    @router.get("/systems/agent-update")
    def agent_update(request: Request, _found=Depends(guards.require_session)):
        """Aktualisieren installiert das neue Paket; Konfiguration und Token bleiben, kein neues enroll nötig.
        Das Paket startet den Daemon neu, der dann sofort mit der neuen Version meldet."""
        from .models import setting
        from .releases import STATUS_KEY

        base = _agent_endpoint(ctx, request.headers.get("host", ""))
        with ctx.session_factory() as s:
            check = setting(s, STATUS_KEY)
        # last_check: wann der Master zuletzt nach einem neuen Release gesucht hat (stündlich) und mit welchem Ergebnis
        return {"version": ctx.settings_agent_version(), "update_cmd": _package_part(base, agent_packages(ctx)),
                "last_check": check}

    @router.get("/systems")
    def list_systems(_found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            actions = pending_actions(ctx, s)
            return [system_dict(r, actions=actions) for r in s.scalars(select(System).order_by(System.name))]

    @router.get("/systems/{system_id}")
    def get_system(system_id: int, _found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if not system:
                raise HTTPException(404, "System not found")
            out = system_dict(system, detail=True, actions=pending_actions(ctx, s))
            out["exposed_auto"] = connector_exposed(s).get(system_id, {})   # NPM/Router: {Name: [Quellen]}
            return out

    def set_status(system_id: int, status: str, action: str, text: str, found):
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if not system:
                raise HTTPException(404, "System not found")
            if status == "deleted":
                s.delete(system)
            else:
                if status == "active" and system.status != "active":
                    system.awaiting_report_since = ctx.clock()   # bis zum ersten Report: „Initialisierung“
                system.status = status
            ctx.audit(s, found[0].username, action, f"System {system.name} {text}")
            s.commit()
        return {"ok": True}

    @router.post("/systems/{system_id}/approve")
    def approve_system(system_id: int, found=Depends(guards.require_admin)):
        return set_status(system_id, "active", "system.approved", "approved", found)

    @router.post("/systems/{system_id}/revoke")
    def revoke_system(system_id: int, found=Depends(guards.require_admin)):
        return set_status(system_id, "revoked", "system.revoked", "revoked", found)

    @router.delete("/systems/{system_id}")
    def delete_system(system_id: int, found=Depends(guards.require_admin)):
        result = set_status(system_id, "deleted", "system.deleted", "deleted", found)
        remove_system_files(ctx, system_id)
        return result

    @router.post("/systems/{system_id}/containers/expected")
    def accept_containers(system_id: int, found=Depends(guards.require_admin)):
        """Die gerade laufenden Container werden der neue Soll-Zustand."""
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if not system:
                raise HTTPException(404, "System not found")
            names = running_names(system)
            set_expected(system, names)
            ctx.audit(s, found[0].username, "system.containers_expected",
                      f"System {system.name}: {len(names)} running containers set as expected")
            s.commit()
        return {"ok": True, "expected": sorted(names)}

    class ExposedIn(BaseModel):
        containers: list[str] = Field(default_factory=list, max_length=500)

    @router.put("/systems/{system_id}/exposed")
    def set_exposed(system_id: int, body: ExposedIn, found=Depends(guards.require_admin)):
        """Von Hand als internet-erreichbar markierte Container (Portfreigaben, eigene Proxys). Wirkt ab dem
        nächsten Lauf auf die Stufen (PLAN Abschnitt 5)."""
        names = sorted({n.strip()[:200] for n in body.containers if n.strip()})
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if not system:
                raise HTTPException(404, "System not found")
            system.exposed_containers = json.dumps(names)
            ctx.audit(s, found[0].username, "system.exposed",
                      f"System {system.name}: internet-exposed containers = {', '.join(names) or 'none'}")
            s.commit()
        return {"ok": True, "exposed": names}

    # --- Agent ---

    @router.get("/agent/download/{name}")
    def download(name: str):
        if name not in DOWNLOADS or not ctx.agent_dir():
            raise HTTPException(404, "Unknown architecture or package type")
        path = ctx.agent_dir() / f"vulnwatch-agent-linux-{name}"
        if not path.is_file():
            raise HTTPException(404, "Agent file not available")
        suffix = name.partition(".")[2]
        return FileResponse(path, media_type="application/octet-stream",
                            filename=f"vulnwatch-agent.{suffix}" if suffix else "vulnwatch-agent")

    @router.get("/agent/release/{name}")
    def release_manifest(name: str):
        """Signiertes Manifest des ausgelieferten Releases; der Agent prüft es selbst gegen den Release-Schlüssel."""
        if name not in ("manifest.json", "manifest.json.sig") or not ctx.agent_dir():
            raise HTTPException(404, "Unknown file")
        path = ctx.agent_dir() / name
        if not path.is_file():
            raise HTTPException(404, "No signed release available")
        return FileResponse(path, media_type="application/octet-stream")

    @router.post("/agent/enroll")
    def agent_enroll(body: EnrollIn, request: Request):
        token_hash = auth.sha256_hex(body.enrollment_token)
        with ctx.session_factory() as s:
            token_row = s.get(EnrollmentToken, token_hash)
            if token_row is None or token_row.expires_at <= ctx.clock():
                raise HTTPException(400, "Invalid or expired one-time token")
            s.delete(token_row)  # nur einmal verwendbar
            agent_token = auth.new_token(32)
            ip = body.ip or client_ip(request)
            system = s.scalar(select(System).where(System.name == body.hostname))
            if system is None:
                system = System(name=body.hostname, host_type=body.host_type, ip=ip, status="pending",
                                agent_token_hash=auth.sha256_hex(agent_token), agent_version=body.agent_version)
                s.add(system)
            else:  # erneute Anmeldung: neues Token, alte Freigabe erlischt
                system.ip, system.status = ip, "pending"
                system.agent_token_hash = auth.sha256_hex(agent_token)
                system.agent_version = body.agent_version
            s.flush()
            system_id = system.id
            ctx.audit(s, body.hostname, "agent.enrolled", f"Agent {body.hostname} enrolled (waiting for approval)")
            s.commit()
        return {"ok": True, "system_id": system_id, "agent_token": agent_token, "status": "pending"}

    @router.post("/agent/poll")
    def agent_poll(authorization: str | None = Header(None)):
        """Der Agent fragt alle paar Minuten: soll ich jetzt melden? (fällig oder frische Daten angefordert)"""
        with ctx.session_factory() as s:
            system = agent_system(s, authorization)
        return {"report": agent_should_report(ctx, system)}

    @router.post("/agent/image-sbom")
    def image_sbom(body: ImageSbomIn, authorization: str | None = Header(None)):
        with ctx.session_factory() as s:
            system = agent_system(s, authorization)
            if not IMAGE_ID.match(body.image_id):
                raise HTTPException(422, "invalid image ID")
            if body.image_id not in {i["id"] for i in system_images(system)}:
                raise HTTPException(403, "According to the inventory this image does not run on this host")
            path = image_sbom_path(ctx, system.id, body.image_id)
            row = s.get(ImageSbom, (system.id, body.image_id)) or ImageSbom(system_id=system.id, image_id=body.image_id)
            if body.sbom is None:
                row.error = body.error.strip()[:300] or "agent sent no SBOM"
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(body.sbom), encoding="utf-8")
                os.replace(tmp, path)
                row.error = ""
            row.created_at = datetime.now(timezone.utc)
            s.merge(row)
            s.commit()
        advance_collecting_runs(ctx)
        return {"ok": True}

    @router.post("/agent/report")
    def agent_report(body: AgentReportIn, request: Request, authorization: str | None = Header(None)):
        # Erst das Token, dann die teure Umwandlung: Ohne gültiges Token soll niemand CPU-Zeit verbrauchen können.
        with ctx.session_factory() as s:
            agent_system(s, authorization)

        errors ={k: v.strip()[:300] for k, v in body.collection_errors.items() if k in ERROR_KEYS and v.strip()}
        if not body.security_updates_known:
            errors.setdefault("security_updates", "security updates could not be determined")
        if "packages" not in errors:
            if not body.os_id:
                errors["packages"] = "agent reports no OS ID (update the agent)"
            elif not body.packages:
                errors["packages"] = "agent reported no packages"
        sbom = None
        if "packages" not in errors:
            sbom = build_cyclonedx("", body.os_id, body.os_version_id, body.os_name,
                                   [p.model_dump() for p in body.packages])
            if not any(c["type"] == "library" for c in sbom["components"]):
                sbom, errors["packages"] = None, "no usable packages (unknown package manager)"

        now = datetime.now(timezone.utc)
        with ctx.session_factory() as s:
            system = agent_system(s, authorization)
            system.last_seen = now
            system.awaiting_report_since = None   # erster Report nach der Freigabe ist da
            system.ip = client_ip(request)   # folgt DHCP-Wechseln; Caddy reicht die echte Adresse durch
            system.agent_version = body.agent_version or system.agent_version
            system.security_updates_count = body.security_updates_count
            system.reboot_required = body.reboot_required
            system.container_count = len(body.containers)
            system.collection_errors = json.dumps(errors)
            system.inventory_json = json.dumps({
                "os_name": body.os_name, "os_id": body.os_id, "os_version_id": body.os_version_id,
                "kernel": body.kernel, "arch": body.arch,
                "containers": [c.model_dump() for c in body.containers], "host_ports": body.host_ports,
                "packages_count": len(body.packages), "has_sbom": sbom is not None,
                "security_updates": [{"name": u.name, "from": u.from_, "to": u.to} for u in body.security_updates],
            })
            if "containers" not in errors:
                learn_baseline(system)
            path = _sbom_path(ctx, system.id)
            if sbom is None:
                path.unlink(missing_ok=True)  # nie Veraltetes als aktuell weiterscannen
                system.sbom_updated_at = None
            else:
                sbom["metadata"]["component"]["name"] = system.name
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(sbom), encoding="utf-8")
                os.replace(tmp, path)
                system.sbom_updated_at = now
            s.commit()
            ids = [i["id"] for i in system_images(system)]
            system_id = system.id
            ok_ids = {r.image_id for r in s.scalars(select(ImageSbom).where(
                ImageSbom.system_id == system_id, ImageSbom.image_id.in_(ids), ImageSbom.error == ""))}
        # Nur Images ohne vorhandene SBOM (oder mit Fehler beim letzten Versuch) anfordern.
        needed = [i for i in ids if i not in ok_ids or not image_sbom_path(ctx, system_id, i).is_file()]
        advance_collecting_runs(ctx)
        return {"ok": True, "needed_sboms": needed}

    return router
