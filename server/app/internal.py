"""Interne Endpunkte, die nur der Proxy im Compose-Netz erreicht (Caddy blockt sie nach außen)."""
from fastapi import APIRouter, HTTPException, Query

from .context import Context


def build_internal_router(ctx: Context) -> APIRouter:
    router = APIRouter(prefix="/internal")

    @router.get("/tls-allowed")
    def tls_allowed(domain: str = Query(..., max_length=253)):
        """Caddy fragt hier, bevor es für einen Namen ein Zertifikat ausstellt (`on_demand_tls ask`).
        Ohne diese Prüfung könnte jeder im LAN beliebige Namen erzwingen."""
        if domain.lower() not in {h.lower() for h in ctx.settings.hostnames}:
            raise HTTPException(404, "Name not configured")
        return {"ok": True}

    return router
