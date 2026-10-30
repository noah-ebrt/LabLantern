"""Collector-API v1 (PLAN-extensions C): Geräte ohne Agent (Unraid, Synology, OpenWrt …) melden per Skript Pakete
und Container. Rein passiv: Die Antwort ist immer nur {"ok": true}, nie ein Befehl oder ein Update. Das Token gilt
für genau ein System (Hash in `agent_token_hash`, wie beim Agenten); `host_type="collector"` trennt die beiden, ein
Collector-Token öffnet keinen Agenten-Endpunkt und umgekehrt. Die Felder beschreibt docs/collector-schema.json."""
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from . import auth
from .containers import learn_baseline
from .context import Context
from .guards import Guards, client_ip
from .models import ImageSbom, System
from .sbom import packages_to_sbom
from .scanrun import advance_collecting_runs, image_sbom_path, sbom_path
from .trust import ca_fingerprint

MAX_BODY = 5 * 1024 * 1024
MIN_INTERVAL = 300   # höchstens ein Report je 5 min und System
HOST_TYPE = "collector"


class CollectorOsIn(BaseModel):
    id: str = Field(default="", max_length=40, pattern=r"^[a-z0-9._-]*$")
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=100)


class CollectorPackageIn(BaseModel):
    ecosystem: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$")
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=200)
    purl: str | None = Field(default=None, max_length=500, pattern=r"^pkg:[a-z0-9.+-]+/")


class CollectorContainerIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    image: str = Field(min_length=1, max_length=500)
    image_id: str = Field(default="", pattern=r"^(sha256:[0-9a-f]{64})?$")
    repo_digests: list[str] = Field(default_factory=list, max_length=50)
    sbom: dict[str, Any] | None = None

    @field_validator("sbom")
    @classmethod
    def _cyclonedx(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and v.get("bomFormat") != "CycloneDX":
            raise ValueError("sbom must be CycloneDX JSON (syft <image> -o cyclonedx-json)")
        return v


class CollectorReport(BaseModel):
    schema_: Literal["v1"] = Field(alias="schema")
    os: CollectorOsIn
    packages: list[CollectorPackageIn] = Field(max_length=20_000)
    containers: list[CollectorContainerIn] = Field(default_factory=list, max_length=50)


class CollectorIn(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _image_id(c: CollectorContainerIn) -> str:
    """Ohne gemeldete Image-ID: eine feste aus der Referenz, damit Funde und SBOM je Image zusammenbleiben."""
    return c.image_id or "sha256:" + hashlib.sha256(c.image.encode()).hexdigest()


def _write(path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def build_collector_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter()

    def authorize(authorization: str | None) -> int:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Authorization header with bearer token required")
        token_hash = auth.sha256_hex(authorization.removeprefix("Bearer ").strip())
        with ctx.session_factory() as s:
            system = s.scalar(select(System).where(System.agent_token_hash == token_hash,
                                                   System.host_type == HOST_TYPE))
            if system is None:
                raise HTTPException(401, "Invalid collector token")
            if system.status != "active":
                raise HTTPException(403, "Collector access for this device was revoked")
            if system.last_seen is not None:
                wait = MIN_INTERVAL - (datetime.now(timezone.utc) - system.last_seen).total_seconds()
                if wait > 0:
                    raise HTTPException(429, "At most one report every 5 minutes",
                                        headers={"Retry-After": str(int(wait) + 1)})
            return system.id

    def store(system_id: int, report: CollectorReport, ip: str) -> None:
        now = datetime.now(timezone.utc)
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            sbom, ecosystems = packages_to_sbom(system.name, report.os.id, report.os.name, report.os.version,
                                                [p.model_dump() for p in report.packages])
            _write(sbom_path(ctx, system.id), sbom)
            containers = []
            for c in report.containers:
                iid = _image_id(c)
                if c.sbom is not None:
                    _write(image_sbom_path(ctx, system.id, iid), c.sbom)
                    s.merge(ImageSbom(system_id=system.id, image_id=iid, error="", created_at=now))
                containers.append({"name": c.name, "image": c.image, "image_id": iid, "repo_digests": c.repo_digests,
                                   "state": "running", "runtime": "docker", "labels": {}, "ports": []})
            system.last_seen = system.sbom_updated_at = now
            system.awaiting_report_since = None
            system.ip = ip
            system.container_count = len(containers)
            system.collection_errors = "{}"
            system.inventory_json = json.dumps({
                "os_name": f"{report.os.name} {report.os.version}", "os_id": report.os.id,
                "os_version_id": report.os.version, "containers": containers,
                "packages_count": len(report.packages), "has_sbom": True,
                "collector": {"schema": "v1", "ecosystems": ecosystems},
            })
            if containers:
                learn_baseline(system)
            s.commit()
        advance_collecting_runs(ctx)

    @router.post("/collector/v1/report")
    async def report(request: Request, authorization: str | None = Header(None)):
        # Erst das Token, dann der Body: Ohne gültiges Token liest der Server nichts ein.
        system_id = await run_in_threadpool(authorize, authorization)
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY:
            raise HTTPException(413, "Report larger than 5 MB")
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > MAX_BODY:
                raise HTTPException(413, "Report larger than 5 MB")
        try:
            data = CollectorReport.model_validate_json(bytes(body))
        except ValidationError as e:
            first = e.errors()[0]
            where = ".".join(str(p) for p in first["loc"])
            raise HTTPException(422, f"{where}: {first['msg']}"[:300]) from None
        await run_in_threadpool(store, system_id, data, client_ip(request))
        return {"ok": True}

    def setup(system: System, token: str, request: Request) -> dict:
        from .agent_api import _agent_endpoint
        base = _agent_endpoint(ctx, request.headers.get("host", ""))
        fp = ca_fingerprint(ctx.settings)
        sha = fp.replace(":", "").lower() if fp else ""
        # Wurzelzertifikat einmal holen und am Fingerabdruck prüfen (geht auch mit BusyBox); danach nur noch --cacert
        cmd = (f'D=${{VW_DIR:-/etc/vulnwatch-collector}} && mkdir -p "$D" && '
               f'curl -fsSk {base}/ca.crt -o "$D/ca.crt" && '
               f'[ "$(sed \'/-----/d\' "$D/ca.crt" | base64 -d | sha256sum | cut -c1-64)" = "{sha}" ] && '
               f'echo {base} > "$D/url" && (umask 077 && echo {token} > "$D/token") && echo ok') if sha else None
        return {"id": system.id, "name": system.name, "token": token, "server_url": base,
                "ca_fingerprint": fp, "setup_cmd": cmd}

    @router.post("/collector/systems")
    def create(body: CollectorIn, request: Request, found=Depends(guards.require_admin)):
        token = auth.new_token(24)
        with ctx.session_factory() as s:
            if s.scalar(select(System.id).where(System.name == body.name)):
                raise HTTPException(409, "A system with this name exists already")
            system = System(name=body.name, host_type=HOST_TYPE, status="active", agent_version="",
                            agent_token_hash=auth.sha256_hex(token), awaiting_report_since=ctx.clock())
            s.add(system)
            ctx.audit(s, found[0].username, "collector.created", f"Collector device {body.name} added")
            s.commit()
            return setup(system, token, request)

    @router.post("/collector/systems/{system_id}/token")
    def new_token(system_id: int, request: Request, found=Depends(guards.require_admin)):
        token = auth.new_token(24)
        with ctx.session_factory() as s:
            system = s.get(System, system_id)
            if system is None or system.host_type != HOST_TYPE:
                raise HTTPException(404, "Collector device not found")
            system.agent_token_hash = auth.sha256_hex(token)
            ctx.audit(s, found[0].username, "collector.token", f"New token for collector device {system.name}")
            s.commit()
            return setup(system, token, request)

    return router
