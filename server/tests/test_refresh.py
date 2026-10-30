from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models import ScanJob, ScanRun, System
from app.scanrun import advance_collecting_runs, request_scan_run, ScanAlreadyActive
from tests.test_agent_api import activate, report
from tests.test_scan_flow import Notes

import pytest


def setup(env, client, h, names=("a", "b")):
    env.app.state.ctx.notifier = Notes()
    out = []
    for n in names:
        sid, bearer = activate(env, client, h, hostname=n)
        env.new_client().post("/api/agent/report", headers=bearer, json=report(containers=[]))
        out.append((sid, bearer))
    return out


def poll(env, bearer):
    return env.new_client().post("/api/agent/poll", headers=bearer).json()


def run_and_job(env):
    with env.app.state.ctx.session_factory() as s:
        return s.scalar(select(ScanRun).order_by(ScanRun.id.desc())), s.scalar(select(ScanJob))


def test_agent_poll_says_report_only_when_due_or_requested(admin):
    env, client, h = admin
    [(sid, bearer)] = setup(env, client, h, ["a"])
    assert poll(env, bearer) == {"report": False}               # gerade gemeldet
    request_scan_run(env.app.state.ctx, "manual")
    assert poll(env, bearer) == {"report": True}                # frische Daten angefordert
    with env.app.state.ctx.session_factory() as s:
        s.get(System, sid).last_seen = datetime.now(timezone.utc) - timedelta(minutes=56)
        s.commit()
    advance_collecting_runs(env.app.state.ctx)
    assert poll(env, bearer)["report"] is True                  # stündlich fällig


def test_poll_requires_a_valid_agent_token(admin):
    env, client, h = admin
    assert env.new_client().post("/api/agent/poll").status_code == 401


def test_scan_now_first_collects_fresh_data_then_queues_the_scan(admin):
    env, client, h = admin
    systems = setup(env, client, h)
    r = client.post("/api/runs/trigger", headers=h)
    assert r.json()["status"] == "collecting"
    run, job = run_and_job(env)
    assert run.status == "collecting" and job is None
    prog = client.get("/api/overview").json()["active_run"]
    assert prog["phase"] == "collecting" and prog["systems_total"] == 2 and prog["systems_reported"] == 0
    env.new_client().post("/api/agent/report", headers=systems[0][1], json=report(containers=[]))
    prog = client.get("/api/overview").json()["active_run"]
    assert prog["systems_reported"] == 1 and prog["ready_ids"] == [systems[0][0]]   # welcher Host bereit ist
    env.new_client().post("/api/agent/report", headers=systems[1][1], json=report(containers=[]))
    run, job = run_and_job(env)
    assert run.status == "queued" and job is not None and job.status == "pending"
    assert client.get("/api/overview").json()["active_run"]["phase"] == "scanning"


def test_collection_waits_for_requested_image_sboms(admin):
    env, client, h = admin
    [(sid, bearer)] = setup(env, client, h, ["a"])
    img = "sha256:" + "e" * 64
    request_scan_run(env.app.state.ctx, "manual")
    env.new_client().post("/api/agent/report", headers=bearer,
                          json=report(containers=[{"id": "c", "name": "x", "image": "nginx:1", "image_id": img}]))
    assert run_and_job(env)[0].status == "collecting"           # Image-SBOM fehlt noch
    env.new_client().post("/api/agent/image-sbom", headers=bearer, json={"image_id": img, "sbom": {"bomFormat": "CycloneDX"}})
    assert run_and_job(env)[0].status == "queued"


def test_collection_gives_up_after_the_timeout_and_scans_anyway(admin):
    env, client, h = admin
    setup(env, client, h)
    request_scan_run(env.app.state.ctx, "manual")
    env.clock.advance(11 * 60)
    advance_collecting_runs(env.app.state.ctx)
    run, job = run_and_job(env)
    assert run.status == "queued" and job is not None


def test_no_second_request_while_collecting(admin):
    env, client, h = admin
    setup(env, client, h)
    request_scan_run(env.app.state.ctx, "manual")
    with pytest.raises(ScanAlreadyActive):
        request_scan_run(env.app.state.ctx, "manual")


def test_without_active_systems_the_scan_is_queued_immediately(admin):
    env, client, h = admin
    run = request_scan_run(env.app.state.ctx, "manual")
    assert run.status == "queued"
