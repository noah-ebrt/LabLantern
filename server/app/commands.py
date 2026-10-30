"""Befehle an Agenten: nur eine feste Liste, keine Shell, keine freien Argumente. Der Agent holt sie per
Long-Poll ab (kein offener Port auf den Hosts) und prüft die Liste selbst noch einmal. Gefährliche Befehle
(Neustart, Update) kommen erst mit Passkey-Bestätigung dazu."""
import asyncio
import json
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from .agent_api import COMMAND_TTL, SENT_TIMEOUT, _version, agent_system
from .context import Context
from .guards import Guards
from .models import AgentCommand, System
from .scanrun import agent_should_report, remove_system_files


def trust_for_agents(s):
    from .passkeys import trust_for_agents as t   # spät importiert: passkeys importiert agent_api
    return t(s)

QUERIES = ("disk_usage", "failed_units", "listening_ports", "uptime")
MAX_QUEUED = 5
MAX_WAIT = 45           # Long-Poll; unter dem 60-s-Timeout des Agenten
ONLINE_WINDOW = 120.0
MAX_OUTPUT = 64 * 1024


class CommandIn(BaseModel):
    type: Literal["report_now", "query"]
    query: Literal["disk_usage", "failed_units", "listening_ports", "uptime"] | None = None


class ResultIn(BaseModel):
    status: Literal["done", "failed", "rejected"]
    output: str = Field(default="", max_length=MAX_OUTPUT)


def is_online(ctx: Context, system: System) -> bool:
    return system.last_contact is not None and ctx.clock() - system.last_contact < ONLINE_WINDOW


def _expire(ctx: Context, s) -> None:
    s.execute(update(AgentCommand)
              .where(AgentCommand.status == "queued", AgentCommand.created_at < ctx.clock() - COMMAND_TTL)
              .values(status="expired", finished_at=ctx.clock()))
    s.execute(update(AgentCommand)
              .where(AgentCommand.status == "sent", AgentCommand.sent_at < ctx.clock() - SENT_TIMEOUT)
              .values(status="failed", finished_at=ctx.clock(),
                      output="No answer from the agent within 15 minutes"))


def command_dict(c: AgentCommand) -> dict:
    # Umschlag und Signatur gehören dem Agenten, nicht der Anzeige
    params = {k: v for k, v in json.loads(c.params_json or "{}").items() if k not in ("envelope", "assertion")}
    return {"id": c.id, "type": c.type, "params": params, "status": c.status,
            "created_by": c.created_by, "created_at": c.created_at, "sent_at": c.sent_at,
            "finished_at": c.finished_at, "output": c.output}


def build_commands_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    # --- Oberfläche ---

    @router.post("/systems/{system_id}/commands")
    def create_command(system_id: int, body: CommandIn, found=Depends(guards.require_admin)):
        if body.type == "query" and body.query is None:
            raise HTTPException(422, "Query name required")
        params = {"name": body.query} if body.type == "query" else {}
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if system is None:
                raise HTTPException(404, "System not found")
            if system.status != "active":
                raise HTTPException(409, "System is not active")
            _expire(ctx, s)
            queued = s.scalars(select(AgentCommand).where(AgentCommand.system_id == system_id,
                                                          AgentCommand.status.in_(("queued", "sent")))).all()
            if len(queued) >= MAX_QUEUED:
                raise HTTPException(429, "Too many open commands for this system")
            cmd = AgentCommand(system_id=system_id, type=body.type, params_json=json.dumps(params),
                               created_by=found[0].username, created_at=ctx.clock())
            s.add(cmd)
            ctx.audit(s, found[0].username, "command.create",
                      f"{body.type}{' ' + body.query if body.query else ''} on {system.name}")
            s.commit()
            return command_dict(cmd)

    @router.get("/systems/{system_id}/commands")
    def list_commands(system_id: int, _found=Depends(guards.require_session)):
        with ctx.session_factory() as s:
            _expire(ctx, s)
            s.commit()
            rows = s.scalars(select(AgentCommand).where(AgentCommand.system_id == system_id)
                             .order_by(AgentCommand.id.desc()).limit(20)).all()
            return [command_dict(c) for c in rows]

    # --- Agent ---

    def _claim(authorization: str | None) -> dict | None:
        with ctx.session_factory() as s:
            system = agent_system(s, authorization)
            system.last_contact = ctx.clock()
            _expire(ctx, s)
            rows = s.scalars(select(AgentCommand).where(AgentCommand.system_id == system.id,
                                                        AgentCommand.status == "queued")
                             .order_by(AgentCommand.id).limit(MAX_QUEUED)).all()
            for c in rows:
                c.status, c.sent_at = "sent", ctx.clock()
            s.commit()
            # Ein Update startet den Agenten neu, bevor er antworten kann: erledigt, sobald er die Version meldet
            for c in s.scalars(select(AgentCommand).where(AgentCommand.system_id == system.id,
                                                          AgentCommand.type == "update_agent",
                                                          AgentCommand.status == "sent")):
                target = json.loads(c.params_json or "{}").get("version", "")
                if target and _version(system.agent_version) >= _version(target):
                    c.status, c.finished_at, c.output = "done", ctx.clock(), f"Agent now runs {system.agent_version}"
            s.commit()
            cmds = [{"id": c.id, "type": c.type, "params": json.loads(c.params_json or "{}")} for c in rows]
            report = agent_should_report(ctx, system)
            trust = trust_for_agents(s)
        if report or cmds:
            return {"report": report, "commands": cmds, "passkeys": trust}
        return None

    @router.post("/agent/commands/next")
    async def next_commands(wait: int = 0, authorization: str | None = Header(None)):
        """Long-Poll: antwortet sofort, wenn ein Report fällig ist oder Befehle warten, sonst nach `wait` s."""
        wait = max(0, min(wait, MAX_WAIT))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait
        while True:
            found = await asyncio.to_thread(_claim, authorization)
            if found is not None or loop.time() >= deadline:
                if found is None:
                    with ctx.session_factory() as s:
                        return {"report": False, "commands": [], "passkeys": trust_for_agents(s)}
                return found
            await asyncio.sleep(1)

    @router.post("/agent/commands/{command_id}/result")
    def command_result(command_id: int, body: ResultIn, authorization: str | None = Header(None)):
        with ctx.session_factory() as s:
            system = agent_system(s, authorization)
            cmd = s.get(AgentCommand, command_id)
            if cmd is None or cmd.system_id != system.id or cmd.status != "sent":
                raise HTTPException(404, "No open command with this ID")
            cmd.status, cmd.output, cmd.finished_at = body.status, body.output, ctx.clock()
            if cmd.type == "uninstall" and body.status == "done":
                # Agent entfernt sich selbst: dann verschwindet der Host samt Funden und Verlauf auch hier
                ctx.audit(s, cmd.created_by, "system.deleted", f"System {system.name} (agent uninstalled itself)")
                s.delete(system)
            s.commit()
            if cmd.type == "uninstall" and body.status == "done":
                remove_system_files(ctx, system.id)
        return {"ok": True}

    return router
