"""Schnittstelle für den Worker. Der Worker hat weder Master key noch Datenbank noch Daten-Volume:
Er holt Aufträge und SBOMs über diese API und liefert Rohdaten. Authentifizierung nur per Worker-Token."""
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .context import Context
from .models import ScanJob, put_setting, setting
from .scanrun import (
    IMAGE_ID, JobStateError, WorkerResultIn, claim_job, fail_job, image_sbom_path, process_scan_result, sbom_path,
)

WORKER_SEEN_KEY = "worker.last_seen"


def ensure_worker_token(path: Path) -> str:
    path = Path(path)
    if path.exists():
        token = path.read_text().strip()
        if len(token) >= 32:
            return token
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    return token


class FailIn(BaseModel):
    error: str = Field(min_length=1, max_length=500)


class ProgressIn(BaseModel):
    # host/image: älterer Worker (der Reihe nach); download/scan: paralleler Worker; osv: zweite Quelle
    step: Literal["database", "canary", "download", "host", "image", "scan", "osv", "saving"]
    text: str = Field(default="", max_length=200)
    host: str = Field(default="", max_length=100)
    host_index: int = Field(default=0, ge=0, le=10_000)
    hosts_total: int = Field(default=0, ge=0, le=10_000)
    image_index: int = Field(default=0, ge=0, le=100_000)
    images_total: int = Field(default=0, ge=0, le=100_000)
    done: int = Field(default=0, ge=0, le=100_000)       # paralleler Scan: fertige SBOMs von `total`
    total: int = Field(default=0, ge=0, le=100_000)
    reused: int = Field(default=0, ge=0, le=100_000)     # davon unverändert, Ergebnis wiederverwendet


def build_worker_router(ctx: Context) -> APIRouter:
    def require_worker(authorization: str | None = Header(None)):
        sent = (authorization or "").removeprefix("Bearer ").strip()
        if not ctx.worker_token or not hmac.compare_digest(sent.encode(), ctx.worker_token.encode()):
            raise HTTPException(401, "Invalid worker token")

    router = APIRouter(prefix="/worker", dependencies=[Depends(require_worker)])

    def mark_seen() -> None:
        with ctx.session_factory() as s:
            put_setting(s, WORKER_SEEN_KEY, str(ctx.clock()), raw=True)
            s.commit()

    @router.post("/claim")
    def claim():
        mark_seen()
        return {"job": claim_job(ctx)}

    @router.get("/jobs/{job_id}/sbom/{system_id}")
    def sbom(job_id: int, system_id: int):
        with ctx.session_factory() as s:
            job = s.get(ScanJob, job_id)
        if job is None or job.status != "running":
            raise HTTPException(409, "Job is not running")
        entry = next((x for x in json.loads(job.payload)["systems"] if x["id"] == system_id), None)
        path = sbom_path(ctx, system_id)
        if entry is None or not entry["sbom"] or not path.is_file():
            raise HTTPException(404, "no SBOM for this system in this job")
        return FileResponse(path, media_type="application/json")

    @router.get("/jobs/{job_id}/image-sbom/{system_id}/{image_id}")
    def image_sbom(job_id: int, system_id: int, image_id: str):
        with ctx.session_factory() as s:
            job = s.get(ScanJob, job_id)
        if job is None or job.status != "running":
            raise HTTPException(409, "Job is not running")
        listed = any(x["id"] == system_id and img["id"] == image_id and img["sbom"]
                     for x in json.loads(job.payload)["systems"] for img in x.get("images", []))
        if not listed or not IMAGE_ID.match(image_id):
            raise HTTPException(404, "no SBOM for this image in this job")
        path = image_sbom_path(ctx, system_id, image_id)
        if not listed or not IMAGE_ID.match(image_id) or not path.is_file():
            raise HTTPException(404, "no SBOM for this image in this job")
        return FileResponse(path, media_type="application/json")

    @router.post("/jobs/{job_id}/result")
    def result(job_id: int, body: WorkerResultIn):
        try:
            run = process_scan_result(ctx, job_id, body)
        except JobStateError as e:
            raise HTTPException(409, str(e)) from None
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        return {"ok": True, "run_status": run.status}

    @router.post("/jobs/{job_id}/progress")
    def progress(job_id: int, body: ProgressIn):
        """Zwischenstand für die Fortschrittsanzeige; nur für einen laufenden Job."""
        with ctx.session_factory() as s:
            job = s.get(ScanJob, job_id)
            if job is None or job.status != "running":
                raise HTTPException(409, "job is not running")
            job.progress = json.dumps({**body.model_dump(), "at": ctx.clock()})
            s.commit()
        return {"ok": True}

    @router.post("/jobs/{job_id}/fail")
    def fail(job_id: int, body: FailIn):
        try:
            fail_job(ctx, job_id, body.error)
        except JobStateError as e:
            raise HTTPException(409, str(e)) from None
        return {"ok": True}

    return router


def worker_last_seen(ctx: Context) -> dict:
    with ctx.session_factory() as s:
        raw = setting(s, WORKER_SEEN_KEY, raw=True)
    if raw is None:
        return {"last_seen": None, "age_seconds": None}
    ts = float(raw)
    return {"last_seen": ts, "age_seconds": max(0, int(ctx.clock() - ts))}
