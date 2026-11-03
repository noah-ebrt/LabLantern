"""Pairing neuer Agenten: `lablantern-agent setup` findet den Master per mDNS und fragt hier an.

Beide Seiten berechnen denselben Code aus dem Fingerabdruck des Wurzelzertifikats, einem Geheimnis des Agenten und
einer Zufallszahl des Masters. Stimmt der Code in der Oberfläche mit dem auf dem Host überein, spricht der Agent mit
dem echten Master; erst dann gibt der Admin frei (mit Passkey, sobald einer eingerichtet ist). Das Agent-Token
bekommt nur, wer das Geheimnis kennt, und nur einmal.

Ablauf mit Festlegung vor dem Aufdecken (sonst könnte ein Mann in der Mitte das Geheimnis, das er an den Master
weitergibt, so lange durchprobieren, bis die 30-Bit-Codes passen):
  1. Agent → Master: commitment = SHA-256(Geheimnis)      → Master antwortet mit einer frischen Zufallszahl
  2. Agent → Master: Geheimnis (muss zum Commitment passen) → erst jetzt gibt es einen Code
Wer dazwischen sitzt, muss sich beim Master auf ein Geheimnis festlegen, bevor er die Zufallszahl kennt, und hat
damit je Anfrage nur eine Chance von 1 : 2^30 (Anfragen sind je Adresse begrenzt).
"""
import base64
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from . import auth
from .context import Context
from .guards import Guards, client_ip
from .models import Pairing, System
from .trust import ca_fingerprint

PAIRING_TTL = 15 * 60
MAX_PENDING = 20
MAX_OPEN_PER_IP = 2   # sonst könnte ein einzelner Host die Warteschlange für alle füllen
OPEN = ("committed", "pending")
HOSTNAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"


class PairIn(BaseModel):
    hostname: str = Field(pattern=HOSTNAME)
    commitment: str = Field(pattern=r"^[0-9a-f]{64}$")   # SHA-256 des Geheimnisses; das Geheimnis selbst kommt später
    host_type: str = Field(default="linux", pattern=r"^[a-z]{1,20}$")
    agent_version: str = Field(default="", max_length=32)


class StatusIn(BaseModel):
    secret: str = Field(pattern=r"^[0-9a-f]{64}$")


def pairing_code(ca_fp: str, secret: str, nonce: str) -> str:
    """Muss genau so im Agenten berechnet werden (internal/pairing)."""
    fp = ca_fp.replace(":", "").replace(" ", "").upper()   # wie config.NormalizeFingerprint im Agenten
    digest = hashlib.sha256(f"{fp}:{secret}:{nonce}".encode()).digest()
    raw = base64.b32encode(digest).decode()[:6]
    return f"{raw[:3]}-{raw[3:]}"


def expire_pairings(ctx: Context, s) -> None:
    """Abgelaufene Anfragen schließen und ihre Tokens löschen (committet selbst; der Geheimnisspeicher
    schreibt über eine eigene Verbindung)."""
    gone = []
    for p in s.scalars(select(Pairing).where(Pairing.status.in_(("committed", "pending", "approved")),
                                             Pairing.created_at < ctx.clock() - PAIRING_TTL)):
        p.status = "expired"
        gone.append(p.id)
    s.commit()
    for pid in gone:
        ctx.secrets.delete(f"pairing.{pid}")


def approve_pairing(ctx: Context, s, pairing: Pairing, actor: str) -> System:
    """Legt das System an oder hängt das Pairing an ein bestehendes gleichen Namens (Funde bleiben erhalten).
    Committet selbst, weil das Token danach im Geheimnisspeicher landet."""
    token = auth.new_token(32)
    system = s.scalar(select(System).where(System.name == pairing.hostname))
    if system is None:
        system = System(name=pairing.hostname, host_type=pairing.host_type, ip=pairing.ip,
                        agent_version=pairing.agent_version)
        s.add(system)
    system.status, system.ip = "active", pairing.ip
    system.awaiting_report_since = ctx.clock()          # bis zum ersten Report: „Initialisierung“
    system.agent_token_hash = auth.sha256_hex(token)   # ein altes Token gilt ab jetzt nicht mehr
    s.commit()
    ctx.secrets.set(f"pairing.{pairing.id}", token)   # vor der Freigabe, damit der Status nie ohne Token "approved" ist
    pairing.status, pairing.system_id = "approved", system.id
    ctx.audit(s, actor, "agent.paired", f"{pairing.hostname} ({pairing.ip}), code {pairing.code}")
    s.commit()
    return system


def build_pairing_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()
    limiter = auth.RateLimiter(ctx.clock, max_failures=10, window=600)

    @router.post("/agent/pair")
    def request_pairing(body: PairIn, request: Request):
        key = f"pair:{client_ip(request)}"
        if limiter.blocked(key):
            raise HTTPException(429, "Too many pairing requests", headers={"Retry-After": str(limiter.retry_after(key))})
        limiter.fail(key)   # jede Anfrage zählt
        fp = ca_fingerprint(ctx.settings)
        if fp is None:
            raise HTTPException(503, "Root certificate unreadable")
        ip = client_ip(request)
        with ctx.session_factory() as s:
            expire_pairings(ctx, s)
            open_ = select(func.count()).select_from(Pairing).where(Pairing.status.in_(OPEN))
            if s.scalar(open_) >= MAX_PENDING:
                raise HTTPException(429, "Too many open pairing requests")
            if s.scalar(open_.where(Pairing.ip == ip)) >= MAX_OPEN_PER_IP:
                raise HTTPException(429, "This address already has open pairing requests; finish or wait for them")
            p = Pairing(hostname=body.hostname, host_type=body.host_type, agent_version=body.agent_version,
                        ip=ip, code="", secret_hash=body.commitment, nonce=secrets.token_hex(16),
                        status="committed", created_at=ctx.clock())
            s.add(p)
            ctx.audit(s, body.hostname, "agent.pairing_requested", f"from {p.ip}")
            s.commit()
            return {"pairing_id": p.id, "nonce": p.nonce, "expires_in": PAIRING_TTL}

    @router.post("/agent/pair/{pairing_id}/reveal")
    def reveal(pairing_id: int, body: StatusIn):
        """Zweiter Schritt: Das Geheimnis muss zum Commitment passen; erst dann entsteht der Code für den Admin."""
        fp = ca_fingerprint(ctx.settings)
        if fp is None:
            raise HTTPException(503, "Root certificate unreadable")
        with ctx.session_factory() as s:
            expire_pairings(ctx, s)
            p = s.get(Pairing, pairing_id)
            if p is None or not auth.tokens_equal(p.secret_hash, auth.sha256_hex(body.secret)):
                raise HTTPException(404, "Unknown pairing")
            if p.status != "committed":
                raise HTTPException(409, f"Pairing is {p.status}")
            p.code, p.status = pairing_code(fp, body.secret, p.nonce), "pending"
            s.commit()
        return {"status": "pending"}

    @router.post("/agent/pair/{pairing_id}/status")
    def pairing_status(pairing_id: int, body: StatusIn):
        with ctx.session_factory() as s:
            expire_pairings(ctx, s)
            p = s.get(Pairing, pairing_id)
            if p is None or not auth.tokens_equal(p.secret_hash, auth.sha256_hex(body.secret)):
                raise HTTPException(404, "Unknown pairing")
            if p.status != "approved":
                return {"status": p.status}
            p.status = "collected"   # Token nur einmal
            system_id = p.system_id
            s.commit()
        token = ctx.secrets.get(f"pairing.{pairing_id}")
        ctx.secrets.delete(f"pairing.{pairing_id}")
        return {"status": "approved", "agent_token": token, "system_id": system_id}

    @router.get("/pairings")
    def list_pairings(_found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            expire_pairings(ctx, s)
            names = set(s.scalars(select(System.name)))
            rows = s.scalars(select(Pairing).where(Pairing.status == "pending").order_by(Pairing.id)).all()
            return [{"id": p.id, "hostname": p.hostname, "ip": p.ip, "code": p.code, "agent_version": p.agent_version,
                     "created_at": p.created_at, "replaces_existing": p.hostname in names} for p in rows]

    @router.post("/pairings/{pairing_id}/reject")
    def reject(pairing_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            p = s.get(Pairing, pairing_id)
            if p is None or p.status != "pending":
                raise HTTPException(404, "No open pairing with this ID")
            p.status = "rejected"
            ctx.audit(s, found[0].username, "agent.pairing_rejected", f"{p.hostname} ({p.ip})")
            s.commit()
        return {"ok": True}

    return router

