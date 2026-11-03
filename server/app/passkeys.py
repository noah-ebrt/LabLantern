"""Passkeys (WebAuthn): zweiter Faktor beim Login und Bestätigung gefährlicher Agent-Befehle.

Neustart und Agent-Update gehen nur mit einem frischen Passkey-Touch hinaus. Die Challenge ist der SHA-256 des
Befehls-Umschlags; der Agent prüft die Signatur selbst gegen die Passkey-Schlüssel, die er kennt. Diese Liste
bekommt er ebenfalls passkey-signiert (nur die allererste Liste wird ungeprüft übernommen). Ein übernommener
Master kann deshalb weder Hosts neu starten noch Updates anstoßen, noch den Agenten fremde Schlüssel unterschieben.
"""
import hashlib
import ipaddress
import json
import secrets
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import bytes_to_base64url, decode_credential_public_key
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from . import auth
from .agent_api import _version, pending_actions
from .api import open_session, set_session_cookie
from .context import Context
from .guards import Guards, client_ip
from .models import AdminUser, AgentCommand, Pairing, Passkey, System, put_setting, setting
from .pairing import approve_pairing

TRUST_KEY = "passkeys.trust"   # {"rev", "envelope", "assertion"}: die Liste, der die Agenten vertrauen
CHALLENGE_TTL = 300.0
COMMAND_TTL = 300
BATCH_UPDATE_SINCE = (0, 13, 0)   # ab dieser Agent-Version: ein Passkey-Touch aktualisiert mehrere Hosts
ES256 = [COSEAlgorithmIdentifier.ECDSA_SHA_256]


class CredentialIn(BaseModel):
    credential: dict[str, Any]


class RegisterIn(CredentialIn):
    name: str = Field(min_length=1, max_length=60)


class LoginOptionsIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginIn(CredentialIn):
    token: str = Field(min_length=10, max_length=100)


class OptionalCredentialIn(BaseModel):
    credential: dict[str, Any] | None = None


class PrepareIn(BaseModel):
    type: Literal["reboot", "update_agent", "uninstall"]


def rp_id(ctx: Context) -> str | None:
    """Passkeys brauchen einen Hostnamen; IP-Adressen und localhost lassen Browser nicht zu."""
    for h in ctx.settings.hostnames:
        try:
            ipaddress.ip_address(h.strip("[]"))
        except ValueError:
            if h.lower() != "localhost":
                return h.lower()
    return None


def _origins(rp: str, ctx: Context) -> list[str]:
    return [f"https://{rp}:{ctx.settings.public_port}", f"https://{rp}"]


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def assertion_fields(credential: dict) -> str:
    """Was der Agent zur Prüfung braucht, als kanonisches JSON (base64url-Felder)."""
    r = credential.get("response") or {}
    return canonical({"credential_id": credential.get("id", ""), "authenticator_data": r.get("authenticatorData", ""),
                      "client_data_json": r.get("clientDataJSON", ""), "signature": r.get("signature", "")})


def _get_trust(s) -> dict | None:
    return setting(s, TRUST_KEY)


def _set_trust(s, value: dict) -> None:
    put_setting(s, TRUST_KEY, value)


def _trusted_ids(trust: dict | None) -> set[str]:
    return {k["id"] for k in json.loads(trust["envelope"])["keys"]} if trust else set()


def _admin_keys(s) -> list[Passkey]:
    return s.scalars(select(Passkey).join(AdminUser, AdminUser.id == Passkey.user_id)
                     .where(AdminUser.role == "admin").order_by(Passkey.credential_id)).all()


def _trust_envelope(ctx: Context, s, rev: int, rp: str) -> str:
    keys = []
    for pk in _admin_keys(s):
        pub = decode_credential_public_key(pk.public_key)
        keys.append({"id": pk.credential_id, "x": bytes_to_base64url(pub.x), "y": bytes_to_base64url(pub.y)})
    return canonical({"kind": "passkeys", "rev": rev, "rp_id": rp, "keys": keys, "issued_at": int(ctx.clock())})


def trust_for_agents(s) -> dict | None:
    """Für den Long-Poll: die zuletzt gültige Liste samt Signatur (beim allerersten Schlüssel ohne)."""
    t = _get_trust(s)
    return {"rev": t["rev"], "envelope": t["envelope"], "assertion": t["assertion"] or ""} if t else None


class _Challenges:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.items: dict[str, tuple[float, bytes, dict]] = {}

    def put(self, key: str, challenge: bytes, **data) -> None:
        now = self.ctx.clock()
        self.items = {k: v for k, v in self.items.items() if v[0] > now}
        self.items[key] = (now + CHALLENGE_TTL, challenge, data)

    def pop(self, key: str) -> tuple[bytes, dict]:
        item = self.items.pop(key, None)
        if item is None or item[0] < self.ctx.clock():
            raise HTTPException(400, "Passkey request expired, please try again")
        return item[1], item[2]


def build_passkeys_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()
    challenges = _Challenges(ctx)

    def need_rp() -> str:
        rp = rp_id(ctx)
        if rp is None:
            raise HTTPException(409, "Passkeys need a hostname: add one (e.g. lablantern.lan) to LABLANTERN_HOSTNAMES "
                                     "and open the UI under that name")
        return rp

    def verify(s, credential: dict, challenge: bytes, allowed: set[str]) -> Passkey:
        cid = str(credential.get("id", ""))
        pk = s.scalar(select(Passkey).where(Passkey.credential_id == cid)) if cid in allowed else None
        if pk is None:
            raise HTTPException(400, "This passkey is not allowed here")
        try:
            res = verify_authentication_response(
                credential=credential, expected_challenge=challenge, expected_rp_id=need_rp(),
                expected_origin=_origins(need_rp(), ctx), credential_public_key=pk.public_key,
                credential_current_sign_count=pk.sign_count, require_user_verification=True)
        except Exception:
            raise HTTPException(400, "Passkey verification failed") from None
        pk.sign_count, pk.last_used = res.new_sign_count, ctx.clock()
        return pk

    def request_options(challenge: bytes, ids: set[str]) -> dict:
        opts = generate_authentication_options(
            rp_id=need_rp(), challenge=challenge, user_verification=UserVerificationRequirement.REQUIRED,
            allow_credentials=[PublicKeyCredentialDescriptor(id=_b64d(i)) for i in sorted(ids)])
        return json.loads(options_to_json(opts))

    # --- Verwaltung ---

    @router.get("/passkeys")
    def list_passkeys(found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            keys = s.scalars(select(Passkey).where(Passkey.user_id == found[0].id).order_by(Passkey.id)).all()
            trust = _get_trust(s)
            admin_ids = {k.credential_id for k in _admin_keys(s)}
            return {
                "rp_id": rp_id(ctx),
                "keys": [{"id": k.id, "name": k.name, "created_at": k.created_at, "last_used": k.last_used} for k in keys],
                "trust": {"rev": trust["rev"] if trust else 0, "signed": bool(trust and trust["assertion"]),
                          "outdated": bool(trust) and _trusted_ids(trust) != admin_ids},
            }

    @router.post("/passkeys/register/options")
    def register_options(found=Depends(guards.require_admin)):
        user = found[0]
        rp = need_rp()
        with ctx.session_factory() as s:
            existing = s.scalars(select(Passkey).where(Passkey.user_id == user.id)).all()
        opts = generate_registration_options(
            rp_id=rp, rp_name="LabLantern", user_name=user.username, user_id=f"ll-user-{user.id}".encode(),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=_b64d(k.credential_id)) for k in existing],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED),
            supported_pub_key_algs=ES256)
        challenges.put(f"reg:{user.id}", opts.challenge)
        return json.loads(options_to_json(opts))

    @router.post("/passkeys/register")
    def register(body: RegisterIn, found=Depends(guards.require_admin)):
        user = found[0]
        challenge, _ = challenges.pop(f"reg:{user.id}")
        rp = need_rp()
        try:
            res = verify_registration_response(
                credential=body.credential, expected_challenge=challenge, expected_rp_id=rp,
                expected_origin=_origins(rp, ctx), require_user_verification=True, supported_pub_key_algs=ES256)
        except Exception:
            raise HTTPException(400, "Passkey registration failed") from None
        with ctx.session_factory() as s:
            s.add(Passkey(user_id=user.id, credential_id=bytes_to_base64url(res.credential_id),
                          public_key=res.credential_public_key, sign_count=res.sign_count,
                          name=body.name, created_at=ctx.clock()))
            s.flush()
            if _get_trust(s) is None:   # allererster Schlüssel: Agenten übernehmen die Liste einmalig ungeprüft
                _set_trust(s, {"rev": 1, "envelope": _trust_envelope(ctx, s, 1, rp), "assertion": None})
            ctx.audit(s, user.username, "passkey.registered", body.name)
            s.commit()
        return {"ok": True}

    @router.delete("/passkeys/{key_id}")
    def delete_passkey(key_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            pk = s.get(Passkey, key_id)
            if pk is None or pk.user_id != found[0].id:
                raise HTTPException(404, "Passkey not found")
            s.delete(pk)
            ctx.audit(s, found[0].username, "passkey.deleted", pk.name)
            s.commit()
        return {"ok": True}

    @router.post("/passkeys/trust/options")
    def trust_options(found=Depends(guards.require_admin)):
        """Neue Schlüsselliste für die Agenten; signieren muss ein Passkey, dem sie schon vertrauen."""
        rp = need_rp()
        with ctx.session_factory() as s:
            trust = _get_trust(s)
            if trust is None:
                raise HTTPException(409, "Register a passkey first")
            envelope = _trust_envelope(ctx, s, trust["rev"] + 1, rp)
            allowed = _trusted_ids(trust)
        challenge = hashlib.sha256(envelope.encode()).digest()
        challenges.put(f"trust:{found[0].id}", challenge, envelope=envelope, allowed=allowed)
        return {"envelope": envelope, "options": request_options(challenge, allowed)}

    @router.post("/passkeys/trust")
    def trust_sign(body: CredentialIn, found=Depends(guards.require_admin)):
        challenge, data = challenges.pop(f"trust:{found[0].id}")
        with ctx.session_factory() as s:
            verify(s, body.credential, challenge, data["allowed"])
            env = json.loads(data["envelope"])
            _set_trust(s, {"rev": env["rev"], "envelope": data["envelope"], "assertion": assertion_fields(body.credential)})
            ctx.audit(s, found[0].username, "passkey.trust_signed", f"revision {env['rev']}, {len(env['keys'])} key(s)")
            s.commit()
        return {"ok": True}

    # --- Anmeldung mit Passwort + Passkey (statt TOTP) ---

    @router.post("/login/passkey/options")
    def login_options(body: LoginOptionsIn, request: Request):
        ip_key, user_key = f"ip:{client_ip(request)}", f"user:{body.username.lower()}@{client_ip(request)}"   # wie api.login
        for limiter, key in ((ctx.login_ip_limiter, ip_key), (ctx.login_limiter, user_key)):
            if limiter.blocked(key):
                raise HTTPException(429, "Too many failed attempts", headers={"Retry-After": str(limiter.retry_after(key))})
        with ctx.session_factory() as s:
            user = s.scalar(select(AdminUser).where(AdminUser.username == body.username))
            ok = auth.verify_password(user.password_hash if user else None, body.password)
            ids = {k.credential_id for k in s.scalars(select(Passkey).where(Passkey.user_id == user.id))} if user else set()
        if not (user and ok and ids):
            ctx.login_ip_limiter.fail(ip_key)
            ctx.login_limiter.fail(user_key)
            raise HTTPException(401, "Login failed")
        token = auth.new_token(24)
        challenge = secrets.token_bytes(32)
        challenges.put(f"login:{token}", challenge, user_id=user.id, ids=ids)
        return {"token": token, "options": request_options(challenge, ids)}

    @router.post("/login/passkey")
    def login(body: LoginIn, request: Request, response: Response):
        challenge, data = challenges.pop(f"login:{body.token}")
        with ctx.session_factory() as s:
            try:
                verify(s, body.credential, challenge, data["ids"])
            except HTTPException:
                ctx.login_ip_limiter.fail(f"ip:{client_ip(request)}")
                raise
            user = s.get(AdminUser, data["user_id"])
            raw, result = open_session(ctx, s, user, request, " with passkey")
        set_session_cookie(ctx, response, raw)
        return result

    # --- Gefährliche Befehle: jeder einzelne mit Passkey-Touch ---

    @router.post("/systems/{system_id}/commands/prepare")
    def prepare(system_id: int, body: PrepareIn, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if system is None or system.status != "active":
                raise HTTPException(404, "No active system with this ID")
            trust = _get_trust(s)
            if trust is None:
                raise HTTPException(409, "Register a passkey first (Settings → Passkeys)")
            if running := pending_actions(ctx, s).get(system_id):
                raise HTTPException(409, f"Another action ({running.replace('_', ' ')}) is still running on this host")
            params: dict[str, Any] = ({"delay": 30} if body.type == "reboot" else {} if body.type == "uninstall"
                                      else {"version": ctx.settings_agent_version()})
            if body.type == "update_agent" and _version(params["version"]) <= _version(system.agent_version):
                raise HTTPException(409, f"Agent already runs version {system.agent_version}")
            now = int(ctx.clock())
            envelope = canonical({"kind": "command", "system_id": system_id, "type": body.type, "params": params,
                                  "issued_at": now, "expires_at": now + COMMAND_TTL, "nonce": secrets.token_hex(16)})
            allowed = _trusted_ids(trust)
        challenge = hashlib.sha256(envelope.encode()).digest()
        challenges.put(f"cmd:{found[0].id}", challenge, envelope=envelope, allowed=allowed, system_id=system_id)
        return {"envelope": envelope, "options": request_options(challenge, allowed)}

    @router.post("/systems/{system_id}/commands/confirm")
    def confirm(system_id: int, body: CredentialIn, found=Depends(guards.require_admin)):
        challenge, data = challenges.pop(f"cmd:{found[0].id}")
        if data["system_id"] != system_id:
            raise HTTPException(400, "Confirmation does not match the prepared command")
        env = json.loads(data["envelope"])
        with ctx.session_factory() as s:
            if pending_actions(ctx, s).get(system_id):   # zwei Tabs gleichzeitig
                raise HTTPException(409, "Another action is still running on this host")
            verify(s, body.credential, challenge, data["allowed"])
            system = s.get(System, system_id)
            cmd = AgentCommand(system_id=system_id, type=env["type"], created_by=found[0].username,
                               created_at=ctx.clock(), params_json=json.dumps({
                                   **{k: str(v) for k, v in env["params"].items()},
                                   "envelope": data["envelope"], "assertion": assertion_fields(body.credential)}))
            s.add(cmd)
            ctx.audit(s, found[0].username, "command.create", f"{env['type']} on {system.name} (passkey confirmed)")
            s.commit()
            return {"id": cmd.id, "status": cmd.status}

    # --- Alle veralteten Agenten aktualisieren ---

    def outdated_systems(s) -> list[System]:
        busy = pending_actions(ctx, s)
        newest = _version(ctx.settings_agent_version())
        return [x for x in s.scalars(select(System).where(System.status == "active").order_by(System.name))
                if _version(x.agent_version) < newest and _version(x.agent_version) >= (0, 3, 0) and x.id not in busy]

    @router.post("/systems/commands/update-all/prepare")
    def prepare_update_all(found=Depends(guards.require_admin)):
        """Agenten ab 0.13 bekommen einen gemeinsamen, signierten Befehl (ein Touch). Ältere prüfen nur ihre eigene
        system_id; für sie gibt die Antwort die IDs zurück, die Oberfläche bestätigt sie einzeln."""
        with ctx.session_factory() as s:
            trust = _get_trust(s)
            if trust is None:
                raise HTTPException(409, "Register a passkey first (Settings → Passkeys)")
            systems = outdated_systems(s)
            if not systems:
                raise HTTPException(409, "All agents already run the newest release")
            batch = [x.id for x in systems if _version(x.agent_version) >= BATCH_UPDATE_SINCE]
            single = [x.id for x in systems if x.id not in batch]
            allowed = _trusted_ids(trust)
        if not batch:
            return {"batch_ids": [], "single_ids": single, "options": None}
        now = int(ctx.clock())
        envelope = canonical({"kind": "command", "system_id": 0, "system_ids": batch, "type": "update_agent",
                              "params": {"version": ctx.settings_agent_version()}, "issued_at": now,
                              "expires_at": now + COMMAND_TTL, "nonce": secrets.token_hex(16)})
        challenge = hashlib.sha256(envelope.encode()).digest()
        challenges.put(f"cmdall:{found[0].id}", challenge, envelope=envelope, allowed=allowed)
        return {"batch_ids": batch, "single_ids": single, "envelope": envelope,
                "options": request_options(challenge, allowed)}

    @router.post("/systems/commands/update-all/confirm")
    def confirm_update_all(body: CredentialIn, found=Depends(guards.require_admin)):
        challenge, data = challenges.pop(f"cmdall:{found[0].id}")
        env = json.loads(data["envelope"])
        with ctx.session_factory() as s:
            verify(s, body.credential, challenge, data["allowed"])
            busy = pending_actions(ctx, s)
            created, skipped = [], []
            for sid in env["system_ids"]:
                system = s.get(System, sid)
                if system is None or system.status != "active" or sid in busy:
                    skipped.append(sid)
                    continue
                s.add(AgentCommand(system_id=sid, type="update_agent", created_by=found[0].username,
                                   created_at=ctx.clock(), params_json=json.dumps({
                                       **{k: str(v) for k, v in env["params"].items()},
                                       "envelope": data["envelope"], "assertion": assertion_fields(body.credential)})))
                created.append(system.name)
            ctx.audit(s, found[0].username, "command.create",
                      f"update_agent to {env['params']['version']} on {', '.join(created) or 'no host'} (one passkey touch)")
            s.commit()
        return {"created": created, "skipped": skipped}

    # --- Pairing neuer Agenten: Freigabe mit Passkey, sobald einer eingerichtet ist ---

    def open_pairing(s, pairing_id: int) -> Pairing:
        p = s.get(Pairing, pairing_id)
        if p is None or p.status != "pending":
            raise HTTPException(404, "No open pairing with this ID")
        return p

    def own_keys(s, user_id: int) -> set[str]:
        return {k.credential_id for k in s.scalars(select(Passkey).where(Passkey.user_id == user_id))}

    @router.post("/pairings/{pairing_id}/approve/options")
    def pairing_options(pairing_id: int, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            p = open_pairing(s, pairing_id)
            ids = own_keys(s, found[0].id)
            if not ids:
                return {"passkey": False}
            envelope = canonical({"kind": "pairing", "pairing_id": p.id, "hostname": p.hostname, "code": p.code,
                                  "issued_at": int(ctx.clock())})
        challenge = hashlib.sha256(envelope.encode()).digest()
        challenges.put(f"pair:{found[0].id}", challenge, allowed=ids, pairing_id=pairing_id)
        return {"passkey": True, "options": request_options(challenge, ids)}

    @router.post("/pairings/{pairing_id}/approve")
    def pairing_approve(pairing_id: int, body: OptionalCredentialIn, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            p = open_pairing(s, pairing_id)
            if own_keys(s, found[0].id):
                if body.credential is None:
                    raise HTTPException(400, "Approving a new agent requires your passkey")
                challenge, data = challenges.pop(f"pair:{found[0].id}")
                if data["pairing_id"] != pairing_id:
                    raise HTTPException(400, "Confirmation does not match this pairing")
                verify(s, body.credential, challenge, data["allowed"])
            system = approve_pairing(ctx, s, p, found[0].username)
            s.commit()
            return {"ok": True, "system_id": system.id}

    return router


def _b64d(value: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
