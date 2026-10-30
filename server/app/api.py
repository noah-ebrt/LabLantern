from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import auth
from .context import Context
from .guards import SESSION_COOKIE, Guards, client_ip
from .models import AdminUser, SessionRow, Setting, setting

SETUP_TOTP_SECRET = "setup.totp_pending"


class SetupTotpIn(BaseModel):
    setup_token: str = Field(min_length=1, max_length=200)


class SetupCompleteIn(BaseModel):
    setup_token: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=auth.MIN_PASSWORD_LEN, max_length=256)
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


def open_session(ctx: Context, s, user: AdminUser, request: Request, how: str = "") -> tuple[str, dict]:
    """Legt nach erfolgreicher Anmeldung (TOTP oder Passkey) eine Sitzung an und protokolliert sie."""
    raw = auth.new_token()
    csrf = auth.new_token()
    s.add(SessionRow(token_hash=auth.sha256_hex(raw), user_id=user.id, csrf_token=csrf,
                     expires_at=ctx.clock() + ctx.settings.session_ttl))
    ctx.audit(s, user.username, "login", f"from {client_ip(request)}{how}")
    s.commit()
    return raw, {"username": user.username, "role": user.role, "csrf_token": csrf}


def set_session_cookie(ctx: Context, response: Response, raw: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, raw, max_age=ctx.settings.session_ttl, httponly=True,
        secure=ctx.settings.secure_cookies, samesite="strict", path="/",
    )


def build_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()
    current_session = guards.current_session
    require_csrf = guards.require_csrf

    def setup_complete() -> bool:
        with ctx.session_factory() as s:
            return s.scalar(select(AdminUser.id).limit(1)) is not None

    def check_setup_token(request: Request, token: str) -> None:
        key = f"setup:{client_ip(request)}"
        if ctx.setup_limiter.blocked(key):
            raise HTTPException(
                429, "Too many failed attempts",
                headers={"Retry-After": str(ctx.setup_limiter.retry_after(key))},
            )
        if setup_complete():
            raise HTTPException(409, "Setup is already complete")
        with ctx.session_factory() as s:
            token_hash = setting(s, "setup.token_hash", raw=True)
        if token_hash is None or not auth.tokens_equal(auth.sha256_hex(token), token_hash):
            ctx.setup_limiter.fail(key)
            raise HTTPException(403, "Invalid setup token")

    @router.get("/state")
    def state(request: Request):
        found = current_session(request)
        body = {"setup_complete": setup_complete(), "authenticated": found is not None}
        if found:
            user, row = found
            body.update(username=user.username, role=user.role, csrf_token=row.csrf_token)
        return body

    @router.post("/setup/totp")
    def setup_totp(body: SetupTotpIn, request: Request):
        check_setup_token(request, body.setup_token)
        secret = auth.new_totp_secret()
        ctx.secrets.set(SETUP_TOTP_SECRET, secret)
        uri = auth.totp_uri(secret, "admin")
        return {"totp_secret": secret, "otpauth_uri": uri, "qr_svg": auth.totp_qr_svg(uri)}

    @router.post("/setup/complete")
    def setup_complete_route(body: SetupCompleteIn, request: Request):
        check_setup_token(request, body.setup_token)
        key = f"setup:{client_ip(request)}"
        secret = ctx.secrets.get(SETUP_TOTP_SECRET)
        step = auth.match_totp_step(secret, body.totp_code, ctx.clock()) if secret else None
        if step is None:
            ctx.setup_limiter.fail(key)
            raise HTTPException(400, "Invalid TOTP code or second factor not set up")
        with ctx.session_factory() as s:
            user = AdminUser(
                username=body.username,
                password_hash=auth.hash_password(body.password),
                role="admin",
                totp_last_step=step,
            )
            s.add(user)
            s.flush()
            token_row = s.get(Setting, "setup.token_hash")
            if token_row is not None:
                s.delete(token_row)
            ctx.audit(s, body.username, "setup.completed")
            s.commit()
            user_id = user.id
        ctx.secrets.set(f"totp.{user_id}", secret)
        ctx.secrets.delete(SETUP_TOTP_SECRET)
        ctx.setup_limiter.reset(key)
        return {"ok": True}

    @router.post("/login")
    def login(body: LoginIn, request: Request, response: Response):
        ip_key = f"ip:{client_ip(request)}"
        # Sperre je Benutzer *und* Adresse: Sonst könnte jeder im LAN den Admin mit fünf Fehlversuchen aussperren.
        user_key = f"user:{body.username.lower()}@{client_ip(request)}"
        for limiter, key in ((ctx.login_ip_limiter, ip_key), (ctx.login_limiter, user_key)):
            if limiter.blocked(key):
                raise HTTPException(
                    429, "Too many failed attempts",
                    headers={"Retry-After": str(limiter.retry_after(key))},
                )

        with ctx.session_factory() as s:
            user = s.scalar(select(AdminUser).where(AdminUser.username == body.username))
            password_ok = auth.verify_password(user.password_hash if user else None, body.password)
            totp_secret = ctx.secrets.get(f"totp.{user.id}") if user else None
            step = auth.match_totp_step(totp_secret, body.totp_code, ctx.clock()) if totp_secret else None
            if user and password_ok and step is not None and step > user.totp_last_step:
                user.totp_last_step = step
                raw, result = open_session(ctx, s, user, request)
            else:
                ctx.audit(s, body.username[:64], "login.failed", f"from {client_ip(request)}")
                s.commit()
                result = None
        if result is None:
            ctx.login_ip_limiter.fail(ip_key)
            ctx.login_limiter.fail(user_key)
            raise HTTPException(401, "Login failed")
        ctx.login_limiter.reset(user_key)
        set_session_cookie(ctx, response, raw)
        return result

    @router.post("/logout")
    def logout(response: Response, found=Depends(require_csrf)):
        user, row = found
        with ctx.session_factory() as s:
            db_row = s.get(SessionRow, row.token_hash)
            if db_row:
                s.delete(db_row)
            ctx.audit(s, user.username, "logout")
            s.commit()
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    return router
