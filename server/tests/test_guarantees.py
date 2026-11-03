"""Garantien gegen stille Lücken (PLAN Abschnitt 6) und Kurzlauf (Abschnitt 7): Soll/Ist der Container,
Exposition in der Bewertung, zweimal ohne Daten, Rohdaten-Archiv, Konfigurationsversion."""
import json
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import archive
from app.containers import container_check, set_expected
from app.coverage import calculate_coverage_matrix
from app.models import Finding, ScanRun, System, SystemScanResult, put_setting
from app.report import format_run_report
from app.scanrun import claim_job, enqueue_scan_run, process_scan_result, short_run_notable
from tests.test_agent_api import activate, report
from tests.test_scan_flow import Notes, ctx, make_system, raw, result, run_once  # noqa: F401 (Fixture)


def containers(*names, state="running"):
    return [{"id": f"id{i}", "name": n, "image": f"img/{n}:1", "image_id": "sha256:" + f"{i:x}" * 64,
             "state": state} for i, n in enumerate(names, 1)]


def test_first_report_sets_the_expected_containers_and_changes_are_findings(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    agent = env.new_client()
    agent.post("/api/agent/report", headers=bearer, json=report(containers=containers("web", "db")))
    with env.app.state.ctx.session_factory() as s:
        sysrow = s.get(System, sid)
        assert container_check(sysrow) == ("ok", "2 containers")
    # db fehlt, ein unbekannter läuft; gestoppte, nie erwartete Container zählen nicht
    agent.post("/api/agent/report", headers=bearer,
               json=report(containers=containers("web", "miner") + containers("oneshot", state="exited")))
    with env.app.state.ctx.session_factory() as s:
        status, detail = container_check(s.get(System, sid))
    assert status == "fund" and "1 missing: db" in detail and "1 unexpected: miner" in detail
    detail_api = client.get(f"/api/systems/{sid}").json()["containers_expected"]
    assert detail_api["missing"] == ["db"] and detail_api["unknown"] == ["miner"]
    # Admin übernimmt den Ist-Zustand
    assert client.post(f"/api/systems/{sid}/containers/expected", headers=h).json()["expected"] == ["miner", "web"]
    with env.app.state.ctx.session_factory() as s:
        assert container_check(s.get(System, sid))[0] == "ok"


def test_accepting_containers_needs_admin_csrf(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    assert client.post(f"/api/systems/{sid}/containers/expected").status_code in (401, 403)


def test_an_exposed_container_raises_the_severity(ctx):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        sysrow = s.get(System, sid)
        sysrow.inventory_json = json.dumps({"containers": containers("vaultwarden")})
        sysrow.exposed_containers = json.dumps(["vaultwarden"])
        s.commit()
    target = "image:img/vaultwarden:1"
    run_once(ctx, [(sid, [{**raw(cve="CVE-1", cvss=9.5), "target": target},
                          {**raw(cve="CVE-2", cvss=9.5), "target": "host"}], None)])
    with ctx.session_factory() as s:
        got = {f.cve_id: (f.severity, f.internet_exposed) for f in s.scalars(select(Finding))}
    assert got == {"CVE-1": ("kritisch", True), "CVE-2": ("hoch", False)}


def test_exposure_api_stores_names_and_audits(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    r = client.put(f"/api/systems/{sid}/exposed", headers=h, json={"containers": [" web ", "(host)", ""]})
    assert r.json()["exposed"] == ["(host)", "web"]
    assert client.get(f"/api/systems/{sid}").json()["exposed_containers"] == ["(host)", "web"]


def test_system_detail_shows_exposure_found_by_connectors(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    with env.app.state.ctx.session_factory() as s:
        put_setting(s, "npm.state", {"exposed": {str(sid): ["web"]}})
        put_setting(s, "fritz.state", {"exposed": {str(sid): ["web", "(host)"]}})
        s.commit()
    assert client.get(f"/api/systems/{sid}").json()["exposed_auto"] == {"web": ["NPM", "router"], "(host)": ["router"]}


def test_no_data_twice_in_a_row_is_an_immediate_alert(ctx):
    sid = make_system(ctx)
    _, run1 = run_once(ctx, [(sid, [], "grype kaputt")])
    assert "IMMEDIATE" not in ctx.notifier.sent[-1][0]
    _, run2 = run_once(ctx, [(sid, [], "grype kaputt")])
    subject, body = ctx.notifier.sent[-1]
    assert subject.startswith("[IMMEDIATE ALERT]") and "host-c" in subject and "two consecutive runs" in body
    with ctx.session_factory() as s:
        assert [r.no_data for r in s.scalars(select(SystemScanResult).order_by(SystemScanResult.id))] == [True, True]


def test_a_silent_agent_counts_as_no_data_even_when_its_old_sbom_scans_fine(ctx):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        s.get(System, sid).last_seen = datetime.now(timezone.utc) - timedelta(hours=5)
        s.commit()
    run_once(ctx, [(sid, [], None)])
    run_once(ctx, [(sid, [], None)])
    assert ctx.notifier.sent[-1][0].startswith("[IMMEDIATE ALERT]")


def test_every_run_archives_raw_data_and_records_the_config_version(ctx):
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [raw()], None)])
    root = ctx.settings.data_dir / "archive"
    manifest = json.loads((root / "runs" / f"{run.id}.json").read_text())
    assert manifest["sboms"] == {str(sid): manifest["sboms"][str(sid)]} and manifest["result"]
    assert run.archive_status == "ok" and len(run.config_version) == 12
    assert "Config version: " + run.config_version in ctx.notifier.sent[-1][1]
    # unveränderte SBOM: ein zweiter Lauf legt keinen neuen Inhalt dafür an
    blobs = len(list(root.glob("blobs/*/*.gz")))
    run_once(ctx, [(sid, [raw()], None)])
    assert len(list(root.glob("blobs/*/*.gz"))) == blobs


def test_archive_prunes_after_90_days(ctx):
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [raw()], None)])
    root = ctx.settings.data_dir / "archive"
    assert archive.prune(ctx, now=time.time() + 91 * 86400) >= 2
    assert not list(root.glob("runs/*.json")) and not list(root.glob("blobs/*/*.gz"))


def test_config_version_changes_with_exposure(ctx):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        before = archive.config_version(s)
        s.get(System, sid).exposed_containers = json.dumps(["web"])
        s.commit()
        assert archive.config_version(s) != before


def test_short_run_reports_only_news(ctx):
    sid = make_system(ctx)
    enqueue_scan_run(ctx, "short")
    job = claim_job(ctx)
    run = process_scan_result(ctx, job["id"], result([(sid, [raw(cvss=5.0)], None)]))
    assert ctx.notifier.sent == [] and run.notify_status.startswith("skipped")
    enqueue_scan_run(ctx, "short")
    job = claim_job(ctx)
    process_scan_result(ctx, job["id"], result([(sid, [raw(cve="CVE-9", cvss=9.8)], None)]))
    assert len(ctx.notifier.sent) == 1   # neuer hoher Fund: wird gemeldet


def test_short_run_notable_rules():
    base = {"status": "success", "canary_ok": True, "db_ok": True, "system_errors": [], "new_findings": []}
    assert not short_run_notable(base)
    assert short_run_notable({**base, "status": "partial"})
    assert short_run_notable({**base, "new_findings": [{"severity": "hoch"}]})
    assert not short_run_notable({**base, "new_findings": [{"severity": "mittel"}]})


def test_short_run_skips_right_after_another_run(ctx):
    from app.schedule import run_short_job

    sid = make_system(ctx)
    run_once(ctx, [(sid, [], None)])
    run_short_job(ctx)
    with ctx.session_factory() as s:
        assert s.scalar(select(ScanRun).where(ScanRun.trigger == "short")) is None


def test_short_schedule_api(admin):
    env, client, h = admin
    assert client.get("/api/settings/short-schedule").json()["enabled"] is True
    assert client.put("/api/settings/short-schedule", headers=h, json={"enabled": False, "hours": 5}).status_code == 422
    assert client.put("/api/settings/short-schedule", headers=h, json={"enabled": False, "hours": 4}).status_code == 200
    got = client.get("/api/settings/short-schedule").json()
    assert (got["enabled"], got["hours"], got["choices"], got["next_run"]) == (False, 4, [2, 3, 4, 6, 8, 12], None)
    assert got["hours_of_day"] == [7, 11, 15, 19, 23]   # täglicher Lauf 03:00


def test_short_runs_ping_their_own_watchdog_check(ctx, monkeypatch):
    from app import watchdog

    sent = []
    monkeypatch.setattr(watchdog, "ping", lambda url, suffix="", body="", timeout=10: sent.append(url + suffix))
    ctx.secrets.set("watchdog.run_url", "https://hc.example/ping/daily1")
    ctx.secrets.set("watchdog.short_url", "https://hc.example/ping/short1")
    watchdog.run_started(ctx, 1, "short")
    watchdog.run_finished(ctx, 1, "success", True, "", "short")
    watchdog.run_started(ctx, 2, "scheduled")
    assert sent == ["https://hc.example/ping/short1/start", "https://hc.example/ping/short1",
                    "https://hc.example/ping/daily1/start"]


def test_report_subject_for_repeat_no_data():
    subject, _ = format_run_report({"run_id": 1, "status": "partial", "canary_ok": True, "db_ok": True,
                                    "summary": {}, "repeat_no_data": ["host-c"]})
    assert subject.startswith("[IMMEDIATE ALERT]")


def test_coverage_counts_expected_container_check(ctx):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        sysrow = s.get(System, sid)
        sysrow.inventory_json = json.dumps({"containers": containers("web")})
        set_expected(sysrow, {"web", "db"})
        s.commit()
        assert calculate_coverage_matrix(s)["systems"][0]["checks"]["container"]["status"] == "fund"


def test_short_runs_sit_at_fixed_hours_after_the_daily_run(ctx):
    from app.schedule import set_schedule, set_short_schedule, short_hours_of_day

    set_schedule(ctx, True, "03:00")
    set_short_schedule(ctx, True, 12)
    assert short_hours_of_day(ctx) == [15]
    set_short_schedule(ctx, True, 6)
    assert short_hours_of_day(ctx) == [9, 15, 21]


def test_manual_trigger_modes(admin, monkeypatch):
    from app import schedule

    env, client, h = admin
    started = []
    monkeypatch.setattr(schedule, "start_side_passes", lambda ctx: started.append(True))
    r = client.post("/api/runs/trigger", headers=h, json={"mode": "latest"}).json()
    with env.app.state.ctx.session_factory() as s:
        run = s.get(ScanRun, r["run_id"])
        assert (run.trigger, run.status, started) == ("short", "queued", [])
        run.status = "success"
        s.commit()
    r = client.post("/api/runs/trigger", headers=h, json={}).json()
    with env.app.state.ctx.session_factory() as s:
        assert s.get(ScanRun, r["run_id"]).trigger == "manual" and started == [True]


def test_watchdog_providers_translate_the_pings(ctx, monkeypatch):
    from app import watchdog
    from app.models import put_setting

    sent = []
    monkeypatch.setattr(watchdog, "ping", lambda url, suffix="", body="", timeout=10, method="POST": sent.append((method, url + suffix)))
    ctx.secrets.set("watchdog.run_url", "https://kuma.example.org/api/push/abc123")
    with ctx.session_factory() as s:
        put_setting(s, "watchdog.config", {"provider": "uptimekuma", "heartbeat_minutes": 5})
        s.commit()
    watchdog.run_started(ctx, 1, "scheduled")                       # Kuma kennt keinen Start
    watchdog.run_finished(ctx, 1, "failed", False, "boom", "scheduled")
    watchdog.run_finished(ctx, 2, "success", True, "", "scheduled")
    assert [m for m, _ in sent] == ["GET", "GET"]
    assert "status=down" in sent[0][1] and "boom" in sent[0][1] and "status=up" in sent[1][1]
    sent.clear()
    with ctx.session_factory() as s:
        put_setting(s, "watchdog.config", {"provider": "custom", "heartbeat_minutes": 5})
        s.commit()
    watchdog.run_started(ctx, 3, "scheduled")
    watchdog.run_finished(ctx, 3, "failed", False, "boom", "scheduled")  # nur Erfolge; das Ausbleiben ist der Alarm
    watchdog.run_finished(ctx, 4, "success", True, "", "scheduled")
    assert sent == [("POST", "https://kuma.example.org/api/push/abc123")]


def test_watchdog_config_api_validates_per_provider(admin):
    env, client, h = admin
    bad = client.put("/api/settings/watchdog", headers=h, json={"provider": "uptimekuma", "run_url": "https://hc.example.org/ping/abcdef12"})
    assert bad.status_code == 422 and "/api/push/" in bad.json()["detail"]
    ok = client.put("/api/settings/watchdog", headers=h, json={"provider": "custom", "heartbeat_minutes": 15,
                                                                "heartbeat_url": "http://monitor.lan:8080/beat/lablantern"})
    assert ok.status_code == 200
    data = client.get("/api/settings/watchdog").json()
    assert data["config"] == {"provider": "custom", "heartbeat_minutes": 15} and data["heartbeat"]["set"] is True
    assert client.put("/api/settings/watchdog", headers=h, json={"heartbeat_minutes": 7}).status_code == 422
    assert client.get("/api/settings/short-schedule").json()["agent_report_minutes"] == 55
