import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from .agent_api import build_agent_router, live_snapshot
from .events import EventHub, build_events_router, install_db_hooks
from .commands import build_commands_router
from .pairing import build_pairing_router, expire_pairings
from .passkeys import build_passkeys_router
from .watchdog import build_watchdog_router
from .appliances import build_appliances_router
from .configdoc import build_config_router
from .integrity import build_integrity_router
from .connectors import build_connectors_router
from .cftunnel import build_cftunnel_router
from .collector_api import build_collector_router
from .routerforwards import build_routerforwards_router
from .traefik import build_traefik_router
from .fritzbox import build_fritzbox_router
from .products import build_versions_router
from .earlywarning import build_earlywarning_router
from .metrics import build_metrics_router
from .api import build_router
from .auth import RateLimiter, new_token, sha256_hex
from .config import Settings
from .context import Context
from .guards import make_guards
from .integrations import build_integrations_router
from .internal import build_internal_router
from .overview import build_overview_router
from .runs_api import build_runs_router
from .schedule import apply_schedule, build_schedule_router, build_scheduler
from .releases import build_releases_router
from .worker_api import build_worker_router, ensure_worker_token
from .db import init_db, make_engine
from .models import AdminUser, put_setting
from .notify import notify_via_apprise
from .secrets_store import SecretStore, load_or_create_master_key, migrate_master_key

log = logging.getLogger("vulnwatch")


def _prepare_setup_token(ctx: Context) -> None:
    """Solange kein Admin existiert, gibt es bei jedem Start ein frisches Einrichtungs-Token.
    Im Klartext steht es nur im Log, in der Datenbank nur sein Hash."""
    with ctx.session_factory() as s:
        if s.scalar(select(AdminUser.id).limit(1)) is not None:
            return
        token = new_token(24)
        put_setting(s, "setup.token_hash", sha256_hex(token), raw=True)
        s.commit()
    log.info("Setup not finished. Setup token: %s", token)


def create_app(settings: Settings, clock: Callable[[], float] = time.time) -> FastAPI:
    # Apprise protokolliert auf DEBUG jede geladene Kanal-URL samt Token. Das darf auch bei DEBUG-Logging nie ins Log.
    logging.getLogger("apprise").setLevel(logging.WARNING)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(settings.data_dir / "vulnwatch.db")
    init_db(engine)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    settings.master_key_path.parent.mkdir(parents=True, exist_ok=True)
    migrate_master_key(settings.data_dir / "master.key", settings.master_key_path)
    master_key = load_or_create_master_key(settings.master_key_path)
    ctx = Context(
        settings=settings,
        session_factory=session_factory,
        secrets=SecretStore(session_factory, master_key),
        clock=clock,
        setup_limiter=RateLimiter(clock, max_failures=5, window=900),
        login_limiter=RateLimiter(clock, max_failures=5, window=900),
        login_ip_limiter=RateLimiter(clock, max_failures=20, window=900),
    )
    ctx.worker_token = ensure_worker_token(settings.worker_token_path)
    ctx.notifier = lambda title, body, html=None, kind="report": notify_via_apprise(ctx, title, body, html, kind)
    _prepare_setup_token(ctx)

    # Täglicher Lauf, Wartung (Läufe weiterschalten, hängende Jobs) und stündlicher Release-Abgleich.
    # Läuft nur im echten Serverprozess: Der Lebenszyklus startet ihn, Unit-Tests ohne Server lassen ihn aus.
    scheduler = build_scheduler(ctx)
    ctx.on_schedule_change = lambda: apply_schedule(scheduler, ctx)

    @asynccontextmanager
    async def lifespan(_app):
        scheduler.start()
        log.info("Scheduler started (daily run, maintenance, release check)")
        try:
            yield
        finally:
            scheduler.shutdown(wait=False)

    app = FastAPI(title="vulnwatch", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.scheduler = scheduler
    app.state.ctx = ctx
    # Live-Updates: jeder Commit meldet die berührten Themen an offene Browser-Ströme
    hub = EventHub()

    def live_tick():
        with session_factory() as s:
            expire_pairings(ctx, s)   # abgelaufene Anfragen verschwinden auch ohne Neuladen
        return live_snapshot(ctx)

    hub.snapshot = live_tick
    install_db_hooks(session_factory, hub)
    app.state.events = hub

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request, exc: RequestValidationError):
        # Pydantic würde die abgelehnte Eingabe zurückspiegeln, bei Geheimnissen (Schlüssel, Kanal-URLs) ungewollt.
        return JSONResponse(
            {"detail": [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]},
            status_code=422,
        )
    guards = make_guards(ctx)
    api_routers = [
        build_router(ctx, guards), build_integrations_router(ctx, guards), build_overview_router(ctx, guards),
        build_agent_router(ctx, guards), build_commands_router(ctx, guards), build_passkeys_router(ctx, guards),
        build_pairing_router(ctx, guards), build_runs_router(ctx, guards), build_schedule_router(ctx, guards),
        build_releases_router(ctx, guards), build_watchdog_router(ctx, guards), build_connectors_router(ctx, guards),
        build_appliances_router(ctx, guards), build_integrity_router(ctx, guards), build_versions_router(ctx, guards),
        build_earlywarning_router(ctx, guards), build_fritzbox_router(ctx, guards), build_cftunnel_router(ctx, guards),
        build_traefik_router(ctx, guards), build_collector_router(ctx, guards),
        build_routerforwards_router(ctx, guards),
    ]
    # Konfiguration als JSON: schreibt über die Endpunkte der Router oben, mit deren Prüfung und Folgen
    api_routers.append(build_config_router(ctx, guards, list(api_routers)))
    for router in api_routers:
        app.include_router(router, prefix="/api")
    app.include_router(build_metrics_router(ctx, guards))   # /metrics (Prometheus) und /api/settings/metrics
    app.include_router(build_worker_router(ctx), prefix="/api")
    app.include_router(build_internal_router(ctx), prefix="/api")
    app.include_router(build_events_router(ctx, guards, hub), prefix="/api")

    if settings.web_dir:
        _serve_spa(app, settings.web_dir)

    @app.middleware("http")
    async def security_headers(request, call_next):
        # Agent-Endpunkte sind vor der Token-Prüfung erreichbar: zu große Anfragen nie erst einlesen.
        if request.url.path.startswith("/api/agent/"):
            declared = request.headers.get("content-length", "0")
            if declared.isdigit() and int(declared) > settings.max_agent_body:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response
    return app


def _serve_spa(app: FastAPI, web_dir: Path) -> None:
    root = web_dir.resolve()
    index = root / "index.html"

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path == "api" or path.startswith("api/"):
            raise HTTPException(404)
        candidate = (root / path).resolve()
        if candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index)
