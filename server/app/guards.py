from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, Request

from . import auth
from .context import Context
from .models import AdminUser, SessionRow

SESSION_COOKIE = "ll_session"


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unbekannt"


@dataclass(frozen=True)
class Guards:
    """FastAPI-Abhängigkeiten: Sitzung lesen, angemeldet sein, CSRF prüfen, Admin sein."""

    current_session: Callable
    require_session: Callable
    require_csrf: Callable
    require_admin: Callable


def make_guards(ctx: Context) -> Guards:
    def current_session(request: Request):
        raw = request.cookies.get(SESSION_COOKIE)
        if not raw:
            return None
        with ctx.session_factory() as s:
            row = s.get(SessionRow, auth.sha256_hex(raw))
            if row is None:
                return None
            if row.expires_at <= ctx.clock():
                s.delete(row)
                s.commit()
                return None
            return s.get(AdminUser, row.user_id), row

    def require_session(request: Request):
        found = current_session(request)
        if found is None:
            raise HTTPException(401, "Not logged in")
        return found

    def require_csrf(request: Request, found=Depends(require_session)):
        sent = request.headers.get("x-csrf-token", "")
        if not auth.tokens_equal(sent, found[1].csrf_token):
            raise HTTPException(403, "CSRF check failed")
        return found

    def require_admin(found=Depends(require_csrf)):
        if found[0].role != "admin":
            raise HTTPException(403, "Administrators only")
        return found

    return Guards(current_session, require_session, require_csrf, require_admin)
