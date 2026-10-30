import os
import stat

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.test_scan_flow import Notes, make_system, raw


@pytest.fixture
def wenv(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    token = ctx.worker_token
    env.wh = {"Authorization": f"Bearer {token}"}
    env.wclient = env.new_client()
    return env


def ctx_of(env):
    return env.app.state.ctx


def body(sid, findings=None, ok=True, canary_ok=True):
    return {"canary": {"ok": canary_ok, "message": "ok"},
            "grype_db": {"ok": True, "age_hours": 2.0, "built": "x", "reason": ""},
            "systems": [{"system_id": sid, "ok": ok, "error": "" if ok else "kaputt",
                         "findings": findings or []}]}


def test_worker_token_file_is_created_private_and_reused(tmp_path, caplog):
    token_file = tmp_path / "auth" / "worker.token"
    s = Settings(data_dir=tmp_path / "data", worker_token_file=token_file)
    first = create_app(s).state.ctx.worker_token
    assert len(first) >= 32 and token_file.read_text().strip() == first
    assert stat.S_IMODE(os.stat(token_file).st_mode) == 0o600
    assert create_app(s).state.ctx.worker_token == first


def test_worker_endpoints_reject_missing_or_wrong_token(wenv):
    c = wenv.wclient
    for method, url in [("post", "/api/worker/claim"), ("get", "/api/worker/jobs/1/sbom/1"),
                        ("post", "/api/worker/jobs/1/result"), ("post", "/api/worker/jobs/1/fail")]:
        assert getattr(c, method)(url).status_code == 401
        assert getattr(c, method)(url, headers={"Authorization": "Bearer falsch"}).status_code == 401


def test_a_logged_in_admin_session_is_not_a_worker(admin):
    env, client, h = admin
    assert client.post("/api/worker/claim", headers=h).status_code == 401


def test_agent_token_is_not_a_worker_token(wenv):
    assert wenv.wclient.post("/api/worker/claim", headers={"Authorization": "Bearer " + "a" * 43}).status_code == 401


def test_claim_without_job_returns_null_and_marks_worker_seen(admin):
    env, client, h = admin
    ctx = ctx_of(env)
    assert client.get("/api/overview").json()["worker"] == {"last_seen": None, "age_seconds": None}
    w = env.new_client()
    r = w.post("/api/worker/claim", headers={"Authorization": f"Bearer {ctx.worker_token}"})
    assert r.status_code == 200 and r.json() == {"job": None}
    seen = client.get("/api/overview").json()["worker"]
    assert seen["last_seen"] is not None and seen["age_seconds"] == 0


def test_claim_returns_the_queued_job(wenv):
    ctx = ctx_of(wenv)
    sid = make_system(ctx, "host-c")
    wenv.app.state.ctx  # noqa
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    job = wenv.wclient.post("/api/worker/claim", headers=wenv.wh).json()["job"]
    assert job["systems"] == [{"id": sid, "name": "host-c", "sbom": True, "images": []}]
    assert wenv.wclient.post("/api/worker/claim", headers=wenv.wh).json() == {"job": None}


def claimed(wenv, sbom=True):
    ctx = ctx_of(wenv)
    sid = make_system(ctx, "host-c", sbom=sbom)
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    job = wenv.wclient.post("/api/worker/claim", headers=wenv.wh).json()["job"]
    return sid, job


def test_sbom_download_serves_the_agents_sbom_for_a_claimed_job(wenv):
    sid, job = claimed(wenv)
    (ctx_of(wenv).settings.data_dir / "sboms" / f"{sid}.json").write_text('{"bomFormat":"CycloneDX"}')
    r = wenv.wclient.get(f"/api/worker/jobs/{job['id']}/sbom/{sid}", headers=wenv.wh)
    assert r.status_code == 200 and r.json() == {"bomFormat": "CycloneDX"}


def test_sbom_download_refuses_systems_outside_the_job_and_unclaimed_jobs(wenv):
    sid, job = claimed(wenv)
    other = make_system(ctx_of(wenv), "anderes")
    assert wenv.wclient.get(f"/api/worker/jobs/{job['id']}/sbom/{other}", headers=wenv.wh).status_code == 404
    assert wenv.wclient.get(f"/api/worker/jobs/999/sbom/{sid}", headers=wenv.wh).status_code == 409


def test_sbom_download_404_when_the_agent_never_sent_one(wenv):
    sid, job = claimed(wenv, sbom=False)
    assert wenv.wclient.get(f"/api/worker/jobs/{job['id']}/sbom/{sid}", headers=wenv.wh).status_code == 404


def test_result_flows_into_findings_and_run(admin):
    env, client, h = admin
    ctx = ctx_of(env)
    ctx.notifier = Notes()
    sid = make_system(ctx, "host-c")
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    wh = {"Authorization": f"Bearer {ctx.worker_token}"}
    w = env.new_client()
    job = w.post("/api/worker/claim", headers=wh).json()["job"]
    r = w.post(f"/api/worker/jobs/{job['id']}/result", headers=wh,
               json=body(sid, [raw(cve="CVE-2021-44228", kev=True, cvss=10.0)]))
    assert r.status_code == 200 and r.json()["run_status"] == "success"
    f = client.get("/api/findings").json()
    assert f[0]["cve_id"] == "CVE-2021-44228" and f[0]["severity"] == "kritisch"
    assert client.get("/api/runs").json()[0]["status"] == "success"


def test_result_validation_rejects_bad_values_unknown_systems_and_replays(wenv):
    sid, job = claimed(wenv)
    url = f"/api/worker/jobs/{job['id']}/result"
    bad = body(sid, [{**raw(), "cvss_score": 11.0}])
    assert wenv.wclient.post(url, headers=wenv.wh, json=bad).status_code == 422
    assert wenv.wclient.post(url, headers=wenv.wh, json=body(4242)).status_code == 422
    assert wenv.wclient.post(url, headers=wenv.wh, json=body(sid)).status_code == 200
    assert wenv.wclient.post(url, headers=wenv.wh, json=body(sid)).status_code == 409


def test_worker_can_report_a_fatal_failure(admin):
    env, client, h = admin
    ctx = ctx_of(env)
    ctx.notifier = Notes()
    make_system(ctx)
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    wh = {"Authorization": f"Bearer {ctx.worker_token}"}
    w = env.new_client()
    job = w.post("/api/worker/claim", headers=wh).json()["job"]
    assert w.post(f"/api/worker/jobs/{job['id']}/fail", headers=wh, json={"error": "database update broken"}).status_code == 200
    run = client.get("/api/runs").json()[0]
    assert run["status"] == "failed" and "database update" in run["error"].lower()
    assert ctx.notifier.sent[-1][0].startswith("[IMMEDIATE ALERT]")


def test_progress_is_shown_for_the_running_job_only(admin):
    env, client, h = admin
    ctx = ctx_of(env)
    ctx.notifier = Notes()
    sid = make_system(ctx, "host-c")
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    wh = {"Authorization": f"Bearer {ctx.worker_token}"}
    w = env.new_client()
    assert w.post("/api/worker/jobs/1/progress", headers=wh, json={"step": "host"}).status_code == 409   # noch nicht abgeholt
    job = w.post("/api/worker/claim", headers=wh).json()["job"]
    step = {"step": "image", "text": "Scanning image nginx:1.27", "host": "host-c", "host_index": 1, "hosts_total": 1,
            "image_index": 3, "images_total": 14}
    assert w.post(f"/api/worker/jobs/{job['id']}/progress", headers=wh, json=step).status_code == 200
    run = client.get("/api/overview").json()["active_run"]
    assert run["phase"] == "scanning" and run["progress"]["image_index"] == 3 and run["progress"]["host"] == "host-c"
    assert w.post(f"/api/worker/jobs/{job['id']}/progress", headers=wh, json={"step": "rm -rf"}).status_code == 422
    assert w.post(f"/api/worker/jobs/{job['id']}/progress", json=step).status_code == 401
    w.post(f"/api/worker/jobs/{job['id']}/result", headers=wh, json=body(sid))
    assert w.post(f"/api/worker/jobs/{job['id']}/progress", headers=wh, json=step).status_code == 409
