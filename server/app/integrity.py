"""Alarm bei starkem Rückgang der Funde (Restrisiko aus dem Security-Review 2026-10-25): Ein übernommener Worker oder
ein Agent mit geschönter SBOM kann einen Host „sauber“ melden. Fallen die offenen Scanner-Funde eines Hosts in einem
Lauf stark, kommt ein Sofort-Alarm. Ein großes Update kann das auch auslösen; der Alarm sagt dann, was zu prüfen ist."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .context import Context
from .guards import Guards
from .models import put_setting, setting

DROP_KEY = "alerts.finding_drop"
DEFAULTS = {"enabled": True, "percent": 50, "min_findings": 20}


class DropAlarmIn(BaseModel):
    enabled: bool
    percent: int = Field(ge=10, le=100)          # Rückgang in Prozent, ab dem alarmiert wird
    min_findings: int = Field(ge=1, le=100_000)  # erst ab so vielen Funden vorher (kleine Hosts schwanken stark)


def drop_config(s) -> dict:
    return {**DEFAULTS, **(setting(s, DROP_KEY) or {})}


def is_sharp_drop(cfg: dict, before: int, after: int) -> bool:
    return (cfg["enabled"] and before >= cfg["min_findings"] and after < before
            and (before - after) * 100 >= cfg["percent"] * before)


def build_integrity_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings")

    @router.get("/finding-drop", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            return drop_config(s)

    @router.put("/finding-drop")
    def write(body: DropAlarmIn, found=Depends(guards.require_admin)):
        with ctx.session_factory() as s:
            put_setting(s, DROP_KEY, body.model_dump())
            ctx.audit(s, found[0].username, "settings.finding_drop",
                      f"{'on' if body.enabled else 'off'}, {body.percent} % from {body.min_findings} findings")
            s.commit()
        return {"ok": True}

    return router
