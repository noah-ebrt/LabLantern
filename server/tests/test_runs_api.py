import json
from datetime import datetime, timezone

from sqlalchemy import select

from app.models import Finding, ScanRun, System
from app.scanrun import claim_job, process_scan_result
from tests.test_scan_flow import Notes, make_system, raw, result


def setup_system(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    return ctx, make_system(ctx, "host-c")


def test_runs_endpoints_require_login(env):
    assert env.client.get("/api/runs").status_code == 401
    assert env.client.post("/api/runs/trigger").status_code == 401
    assert env.client.get("/api/findings").status_code == 401


def test_trigger_queues_a_run_and_does_not_scan_in_the_server(admin):
    env, client, h = admin
    setup_system(env)
    r = client.post("/api/runs/trigger", headers=h)
    assert r.status_code == 200 and r.json()["status"] in ("collecting", "queued")
    runs = client.get("/api/runs").json()
    assert runs[0]["status"] in ("collecting", "queued") and runs[0]["trigger"] == "manual"


def test_second_trigger_while_active_is_409(admin):
    env, client, h = admin
    setup_system(env)
    client.post("/api/runs/trigger", headers=h)
    r = client.post("/api/runs/trigger", headers=h)
    assert r.status_code == 409 and "already running" in r.json()["detail"]


def test_trigger_requires_admin_and_csrf(admin):
    env, client, h = admin
    assert client.post("/api/runs/trigger").status_code == 403


def test_trigger_is_audited(admin):
    from app.models import AuditLog
    env, client, h = admin
    setup_system(env)
    client.post("/api/runs/trigger", headers=h)
    with env.app.state.ctx.session_factory() as s:
        actions = [a.action for a in s.scalars(select(AuditLog))]
    assert "run.queued" in actions


def finished_run(env, findings=None, **kw):
    ctx, sid = setup_system(env)
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    process_scan_result(ctx, job["id"], result([(sid, findings if findings is not None else [raw()], None)], **kw))
    return ctx, sid


def test_findings_list_and_filters(admin):
    env, client, h = admin
    finished_run(env, [raw(), raw(cve="CVE-2021-44228", kev=True, cvss=10.0)])
    all_ = client.get("/api/findings").json()
    assert [f["cve_id"] for f in all_] == ["CVE-2021-44228", "CVE-2024-1234"]    # nach CVSS absteigend
    assert all_[0]["system_name"] == "host-c" and all_[0]["kev"] is True
    assert [f["cve_id"] for f in client.get("/api/findings?severity=kritisch").json()] == ["CVE-2021-44228"]


def test_snooze_requires_reason_and_limits_days(admin):
    from datetime import date, timedelta
    env, client, h = admin
    finished_run(env)
    fid = client.get("/api/findings").json()[0]["id"]
    day = lambda n: (date.today() + timedelta(days=n)).isoformat()   # noqa: E731
    assert client.post(f"/api/findings/{fid}/snooze", headers=h, json={"reason": "x", "until": day(30)}).status_code == 422
    assert client.post(f"/api/findings/{fid}/snooze", headers=h,
                       json={"reason": "Wartungsfenster", "until": day(182)}).status_code == 422
    r = client.post(f"/api/findings/{fid}/snooze", headers=h, json={"reason": "Wartungsfenster", "until": day(14)})
    assert r.status_code == 200
    acc = client.get("/api/findings?status=accepted").json()
    assert len(acc) == 1 and acc[0]["accepted_until"] and "Wartungsfenster" in acc[0]["accepted_reason"]
    assert client.get("/api/findings").json() == []


def test_run_detail_shows_per_system_results(admin):
    env, client, h = admin
    finished_run(env)
    runs = client.get("/api/runs").json()
    assert runs[0]["status"] == "success" and runs[0]["notify_status"] == "sent"
    detail = client.get(f"/api/runs/{runs[0]['id']}").json()
    assert detail["systems"][0]["system_name"] == "host-c" and detail["systems"][0]["status"] == "ok"
    assert client.get("/api/runs/9999").status_code == 404


def test_overview_ampel_reflects_run_health(admin):
    env, client, h = admin
    assert client.get("/api/overview").json()["ampel"] == "unbekannt"
    finished_run(env, [])
    assert client.get("/api/overview").json()["ampel"] == "gruen"


def test_overview_ampel_is_red_after_failed_canary(admin):
    env, client, h = admin
    finished_run(env, [], canary_ok=False)
    ov = client.get("/api/overview").json()
    assert ov["ampel"] == "rot" and ov["canary_status"] == "fehler"


def test_overview_ampel_is_red_for_a_critical_finding(admin):
    env, client, h = admin
    finished_run(env, [raw(cve="CVE-2021-44228", kev=True, cvss=10.0)])
    assert client.get("/api/overview").json()["ampel"] == "rot"


def test_overview_ampel_is_not_green_when_the_last_run_is_older_than_36h(admin):
    env, client, h = admin
    finished_run(env, [])
    with env.app.state.ctx.session_factory() as s:
        run = s.scalar(select(ScanRun))
        from datetime import timedelta
        run.finished_at = datetime.now(timezone.utc) - timedelta(hours=40)
        s.commit()
    assert client.get("/api/overview").json()["ampel"] == "rot"


def test_overview_ampel_is_red_when_a_system_could_not_be_scanned(admin):
    env, client, h = admin
    ctx, sid = setup_system(env)
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    process_scan_result(ctx, job["id"], result([(sid, [], "grype kaputt")]))
    ov = client.get("/api/overview").json()
    assert ov["ampel"] == "rot"      # nicht geprüft = nie grün
    assert ov["coverage"][0]["checks"]["paket_cve"]["status"] == "fehler"


def test_findings_are_paginated_with_a_total_count(admin):
    env, client, h = admin
    finished_run(env, [raw(cve=f"CVE-2024-{i:04d}", cvss=float(i)) for i in range(1, 6)])
    r = client.get("/api/findings?limit=2&offset=1")
    assert [f["cve_id"] for f in r.json()] == ["CVE-2024-0004", "CVE-2024-0003"]    # nach CVSS absteigend
    assert r.headers["x-total-count"] == "5"
    assert len(client.get("/api/findings").json()) == 5               # Standard-Limit reicht hier
    assert client.get("/api/findings?limit=5000").status_code == 422
    assert client.get("/api/findings?limit=0").status_code == 422
    assert client.get("/api/findings?offset=-1").status_code == 422


def test_total_count_respects_filters(admin):
    env, client, h = admin
    finished_run(env, [raw(cve="CVE-2021-44228", kev=True, cvss=10.0), raw(cve="CVE-2024-1", cvss=5.0)])
    r = client.get("/api/findings?severity=kritisch&limit=10")
    assert r.headers["x-total-count"] == "1" and len(r.json()) == 1


def test_new_sbom_after_a_failed_scan_shows_pending_not_the_old_error(admin):
    env, client, h = admin
    ctx, sid = setup_system(env)
    from app.scanrun import enqueue_scan_run
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    process_scan_result(ctx, job["id"], result([(sid, [], "keine SBOM")]))
    with ctx.session_factory() as s:
        s.get(System, sid).sbom_updated_at = datetime.now(timezone.utc)
        s.commit()
    check = client.get("/api/overview").json()["coverage"][0]["checks"]["paket_cve"]
    assert check["status"] == "offen" and "next run" in check["detail"]


def test_sbom_from_the_old_agent_is_flagged_not_ok(admin):
    env, client, h = admin
    ctx, _ = finished_run(env, [])
    with ctx.session_factory() as s:          # SBOM ohne Zeitstempel = vom alten Agenten
        for x in s.scalars(select(System)):
            x.sbom_updated_at = None
        s.commit()
    check = client.get("/api/overview").json()["coverage"][0]["checks"]["paket_cve"]
    assert check["status"] == "fehler" and "set the system up again" in check["detail"]


def test_history_has_runs_with_coverage_and_time_to_fix(admin):
    from app.models import Finding, System
    from tests.test_scan_flow import Notes, make_system, raw, run_once

    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw(cvss=9.5)], None)])
    run_once(ctx, [(sid, [], None)])   # behoben
    data = client.get("/api/history").json()
    assert [r["counts"].get("hoch") for r in data["runs"]] == [1, 0]
    assert all(r["coverage_percent"] is not None and r["duration_min"] >= 0 for r in data["runs"])
    assert data["time_to_fix"][0]["fixed"] == 1


def test_metrics_need_a_token_and_expose_state(admin):
    from tests.test_scan_flow import Notes, make_system, raw, run_once

    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw(cvss=9.5)], None)])
    assert client.get("/metrics").status_code == 404                 # aus, bis ein Token erzeugt wurde
    token = client.post("/api/settings/metrics/token", headers=h).json()["token"]
    anon = env.new_client()
    assert anon.get("/metrics").status_code == 401
    assert anon.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = anon.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert 'lablantern_findings_open{severity="hoch"} 1' in body
    assert 'lablantern_check_status{system="host-c",check="paket_cve"} 1' in body
    assert "lablantern_coverage_percent" in body and "lablantern_last_run_success 1" in body
    assert token not in client.get("/api/settings/metrics").text   # nur der Hash liegt in der Datenbank
    new = client.post("/api/settings/metrics/token", headers=h).json()["token"]
    assert anon.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert anon.get("/metrics", headers={"Authorization": f"Bearer {new}"}).status_code == 200
    client.delete("/api/settings/metrics", headers=h)
    assert anon.get("/metrics", headers={"Authorization": f"Bearer {new}"}).status_code == 404


def test_fixable_counts_host_fixes_and_images_with_a_newer_build(admin):
    env, client, h = admin
    ctx, sid = finished_run(env, [raw(), raw(cve="CVE-2024-2", fixed="", has_fix=False)])
    with ctx.session_factory() as s:
        def add(target, cve, fixed="1.2.1-r0", source="grype"):
            s.add(Finding(system_id=sid, cve_id=cve, severity="hoch", component="brotli", fixed_version=fixed,
                          source=source, target=target))
        add("image:caddy:2-alpine", "CVE-2026-1")           # Fix nur in der Paketquelle: wartet auf Upstream
        add("image:waha", "CVE-2026-2")                     # neueres Image da: behebbar
        add("image:waha", "LL-IMAGE-OUTDATED", fixed="newer image", source="registry")
        s.commit()
    ov = client.get("/api/overview").json()
    assert sum(ov["fixable"].values()) == 2 and sum(ov["findings"].values()) == 5
    ids = {f["cve_id"] for f in client.get("/api/findings?fixable=true").json()}
    assert ids == {"CVE-2024-1234", "CVE-2026-2"}
