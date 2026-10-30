from datetime import datetime, timedelta, timezone

import pytest

from app import notify as notify_mod
from app.models import ScanRun
from app.reportpolicy import get_report_policy, report_decision, set_report_policy
from app.report import run_level
from app.scanrun import claim_job, enqueue_scan_run, process_scan_result
from test_scan_flow import Notes, make_system, raw, result

MONDAY = datetime(2026, 11, 2, 3, 5, tzinfo=timezone.utc)
TUESDAY = MONDAY + timedelta(days=1)


def ok_info(**kw):
    return {"run_id": 1, "status": "success", "canary_ok": True, "db_ok": True, "summary": {}, **kw}


ALERTS = {
    "IMMEDIATE ALERT": ok_info(canary_ok=False),
    "ALERT": ok_info(summary={"kritisch": 1}),
    "ERROR": ok_info(system_errors=[("host-a", "no SBOM")]),
}


def test_run_level_matches_subject():
    assert run_level(ok_info()) == "OK"
    assert run_level(ok_info(summary={"hoch": 2})) == "WARNING"
    for level, info in ALERTS.items():
        assert run_level(info) == level


@pytest.mark.parametrize("level", list(ALERTS))
def test_alert_levels_always_send(level):
    weekly = {"frequency": "weekly", "weekday": 0, "last_regular_sent": MONDAY.isoformat()}
    paused = {"frequency": "daily", "paused_until": (TUESDAY + timedelta(days=1)).date().isoformat()}
    assert report_decision(weekly, ALERTS[level], TUESDAY) == "send"
    assert report_decision(paused, ALERTS[level], TUESDAY) == "send"


def test_weekly_sends_only_on_weekday():
    policy = {"frequency": "weekly", "weekday": 0, "last_regular_sent": (MONDAY - timedelta(days=7)).isoformat()}
    assert report_decision(policy, ok_info(), MONDAY) == "send"
    policy["last_regular_sent"] = MONDAY.isoformat()
    assert report_decision(policy, ok_info(), TUESDAY) == "skip: weekly"


def test_weekly_catches_up_once():
    policy = {"frequency": "weekly", "weekday": 0, "last_regular_sent": (MONDAY - timedelta(days=7)).isoformat()}
    assert report_decision(policy, ok_info(), TUESDAY) == "send"


def test_on_change():
    policy = {"frequency": "on_change"}
    assert report_decision(policy, ok_info(summary={"hoch": 3}), TUESDAY) == "skip: no change"
    for change in ({"new_findings": [{"severity": "mittel"}]}, {"resolved_count": 1}, {"reopened_count": 1},
                   {"changed_count": 2}):
        assert report_decision(policy, ok_info(**change), TUESDAY) == "send"


def test_pause_and_expiry():
    policy = {"frequency": "daily", "paused_until": TUESDAY.date().isoformat()}
    assert report_decision(policy, ok_info(), TUESDAY) == f"skip: paused until {TUESDAY.date().isoformat()}"
    policy["paused_until"] = MONDAY.date().isoformat()
    assert report_decision(policy, ok_info(), TUESDAY) == "send"


def test_policy_defaults_and_validation(env):
    ctx = env.app.state.ctx
    assert get_report_policy(ctx)["frequency"] == "daily"
    with pytest.raises(ValueError):
        set_report_policy(ctx, {"frequency": "hourly"})
    with pytest.raises(ValueError):
        set_report_policy(ctx, {"frequency": "weekly", "weekday": 7})


def test_channel_routing(env, monkeypatch):
    ctx = env.app.state.ctx
    notify_mod.save_channels(ctx, [{"name": "mail", "url": "mailto://a@b.c", "gets": "report"},
                                   {"name": "ntfy", "url": "ntfy://x", "gets": "alerts"},
                                   {"name": "old", "url": "json://y"}])
    calls = []
    monkeypatch.setattr(notify_mod, "send_notification", lambda urls, *a, **k: calls.append(urls) or (True, None))
    notify_mod.notify_via_apprise(ctx, "t", "b", kind="report")
    notify_mod.notify_via_apprise(ctx, "t", "b", kind="alert")
    assert calls == [["mailto://a@b.c", "json://y"], ["ntfy://x", "json://y"]]


def test_channel_gets_endpoint(admin):
    env, client, csrf = admin
    assert client.post("/api/integrations/notifications", json={"name": "push", "url": "json://x"},
                       headers=csrf).status_code == 200
    assert client.get("/api/integrations/notifications").json()["channels"][0]["gets"] == "both"
    assert client.put("/api/integrations/notifications/0", json={"gets": "alerts"}, headers=csrf).status_code == 200
    assert client.get("/api/integrations/notifications").json()["channels"][0]["gets"] == "alerts"
    assert client.put("/api/integrations/notifications/0", json={"gets": "x"}, headers=csrf).status_code == 422


def test_policy_endpoint_and_overview(admin):
    env, client, csrf = admin
    until = (datetime.now(timezone.utc) + timedelta(days=3)).date().isoformat()
    r = client.put("/api/settings/report-policy", json={"frequency": "weekly", "weekday": 4, "paused_until": until},
                   headers=csrf)
    assert r.status_code == 200, r.text
    assert client.get("/api/settings/report-policy").json()["weekday"] == 4
    assert client.get("/api/overview").json()["reports_paused_until"] == until


def scheduled_run(ctx, systems):
    enqueue_scan_run(ctx, "scheduled")
    job = claim_job(ctx)
    return process_scan_result(ctx, job["id"], result(systems))


def test_paused_scheduled_report_skipped_but_alert_sent(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    until = (datetime.fromtimestamp(ctx.clock(), timezone.utc) + timedelta(days=5)).date().isoformat()
    set_report_policy(ctx, {"frequency": "daily", "paused_until": until})
    sid = make_system(ctx)
    run = scheduled_run(ctx, [(sid, [], None)])
    assert run.notify_status == f"skip: paused until {until}" and not ctx.notifier.sent
    run = scheduled_run(ctx, [(sid, [raw(kev=True, cvss=10, cve="CVE-2021-44228")], None)])
    assert run.notify_status == "sent" and ctx.notifier.kinds == ["alert"]


def test_manual_run_ignores_policy(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    set_report_policy(ctx, {"frequency": "on_change"})
    sid = make_system(ctx)
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    run = process_scan_result(ctx, job["id"], result([(sid, [], None)]))
    assert run.notify_status == "sent" and ctx.notifier.kinds == ["report"]


def test_weekly_records_last_sent_and_names_the_period(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    now = datetime.fromtimestamp(ctx.clock(), timezone.utc)
    set_report_policy(ctx, {"frequency": "weekly", "weekday": now.weekday()})
    sid = make_system(ctx)
    scheduled_run(ctx, [(sid, [], None)])
    assert "weekly report" in ctx.notifier.sent[-1][0]
    assert get_report_policy(ctx)["last_regular_sent"]
    with ctx.session_factory() as s:
        assert s.query(ScanRun).count() == 1


def test_changed_findings_are_counted(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    set_report_policy(ctx, {"frequency": "on_change"})
    sid = make_system(ctx)
    scheduled_run(ctx, [(sid, [raw(cvss=5.0, label="Medium", fixed="", has_fix=False)], None)])
    run = scheduled_run(ctx, [(sid, [raw(cvss=5.0, label="Medium", fixed="", has_fix=False)], None)])
    assert run.notify_status == "skip: no change"
    run = scheduled_run(ctx, [(sid, [raw(cvss=5.0, label="Medium", fixed="1.1")], None)])
    assert run.notify_status == "sent"


def test_config_document_carries_policy_and_channel_gets(admin):
    env, client, h = admin
    assert client.post("/api/integrations/notifications", headers=h,
                       json={"name": "Push", "url": "json://x"}).status_code == 200
    doc = client.get("/api/settings/config").json()
    assert doc["report_policy"] == {"frequency": "daily", "weekday": 0, "paused_until": None}
    doc["report_policy"] = {"frequency": "on_change", "weekday": 0, "paused_until": None}
    doc["notifications"][0]["gets"] = "alerts"
    r = client.put("/api/settings/config", headers=h, json=doc).json()
    assert r["ok"], r
    assert client.get("/api/settings/report-policy").json()["frequency"] == "on_change"
    assert client.get("/api/integrations/notifications").json()["channels"][0]["gets"] == "alerts"
