import pytest
from sqlalchemy import select

from app.models import AuditLog, ScanRun
from app.schedule import (apply_schedule, build_scheduler, get_schedule, get_timezone, next_run_iso, run_daily_job,
                          set_schedule, set_timezone)
from tests.test_scan_flow import make_system


def ctx_of(env):
    return env.app.state.ctx


def test_default_schedule_is_enabled_at_0300_utc(env):
    assert get_schedule(ctx_of(env)) == {"enabled": True, "time": "03:00"}


def test_schedule_roundtrip(env):
    set_schedule(ctx_of(env), False, "21:45")
    assert get_schedule(ctx_of(env)) == {"enabled": False, "time": "21:45"}


@pytest.mark.parametrize("bad", ["25:00", "3:00", "03:60", "abc", "", "03:00:00"])
def test_invalid_time_is_rejected(env, bad):
    with pytest.raises(ValueError):
        set_schedule(ctx_of(env), True, bad)


def test_next_run_is_later_today_or_tomorrow(env):
    # FakeClock startet bei 2027-01-15 08:00:00 UTC
    set_schedule(ctx_of(env), True, "03:00")
    assert next_run_iso(ctx_of(env)) == "2027-01-16T03:00:00+00:00"
    set_schedule(ctx_of(env), True, "09:30")
    assert next_run_iso(ctx_of(env)) == "2027-01-15T09:30:00+00:00"


def test_timezone_defaults_to_utc_and_shifts_the_daily_run(env):
    assert get_timezone(ctx_of(env)) == "UTC"
    set_timezone(ctx_of(env), "Europe/Berlin")   # Januar: UTC+1
    set_schedule(ctx_of(env), True, "03:00")
    assert next_run_iso(ctx_of(env)) == "2027-01-16T02:00:00+00:00"
    with pytest.raises(ValueError):
        set_timezone(ctx_of(env), "Mars/Olympus")


def test_next_run_is_none_when_disabled(env):
    set_schedule(ctx_of(env), False, "03:00")
    assert next_run_iso(ctx_of(env)) is None


def test_scheduler_registers_daily_and_maintenance_jobs(env):
    set_schedule(ctx_of(env), True, "04:15")
    sched = build_scheduler(ctx_of(env))
    daily = sched.get_job("daily-scan")
    assert daily is not None
    fields = {f.name: str(f) for f in daily.trigger.fields}
    assert fields["hour"] == "4" and fields["minute"] == "15"
    assert sched.get_job("maintenance") is not None


def test_apply_schedule_changes_and_removes_the_daily_job(env):
    ctx = ctx_of(env)
    sched = build_scheduler(ctx)
    set_schedule(ctx, True, "05:05")
    apply_schedule(sched, ctx)
    assert {f.name: str(f) for f in sched.get_job("daily-scan").trigger.fields}["hour"] == "5"
    set_schedule(ctx, False, "05:05")
    apply_schedule(sched, ctx)
    assert sched.get_job("daily-scan") is None
    assert sched.get_job("maintenance") is not None


def test_daily_job_queues_a_scheduled_run_and_tolerates_an_active_one(env):
    ctx = ctx_of(env)
    make_system(ctx)
    run_daily_job(ctx)
    run_daily_job(ctx)    # läuft schon: kein Fehler, kein zweiter Lauf
    with ctx.session_factory() as s:
        runs = list(s.scalars(select(ScanRun)))
    assert len(runs) == 1 and runs[0].trigger == "scheduled"


def test_schedule_api_requires_login_and_admin(env, admin):
    e, client, h = admin
    anon = e.new_client()
    assert anon.get("/api/settings/schedule").status_code == 401
    assert client.put("/api/settings/schedule", json={"enabled": True, "time": "02:00"}).status_code == 403


def test_schedule_api_roundtrip_validation_and_audit(admin):
    env, client, h = admin
    assert client.get("/api/settings/schedule").json() == {"enabled": True, "time": "03:00", "timezone": "UTC",
                                                           "next_run": "2027-01-16T03:00:00+00:00"}
    r = client.put("/api/settings/schedule", json={"enabled": True, "time": "02:30"}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/settings/schedule").json()["time"] == "02:30"
    assert client.put("/api/settings/schedule", json={"enabled": True, "time": "99:99"}, headers=h).status_code == 422
    with ctx_of(env).session_factory() as s:
        assert "settings.schedule" in [a.action for a in s.scalars(select(AuditLog))]


def test_schedule_change_reaches_the_running_scheduler(admin):
    env, client, h = admin
    sched = build_scheduler(ctx_of(env))
    ctx_of(env).on_schedule_change = lambda: apply_schedule(sched, ctx_of(env))
    client.put("/api/settings/schedule", json={"enabled": True, "time": "06:10"}, headers=h)
    assert {f.name: str(f) for f in sched.get_job("daily-scan").trigger.fields}["minute"] == "10"


def test_timezone_api_validation_audit_and_scheduler(admin):
    env, client, h = admin
    sched = build_scheduler(ctx_of(env))
    ctx_of(env).on_schedule_change = lambda: apply_schedule(sched, ctx_of(env))
    assert client.get("/api/settings/timezone").json() == {"timezone": "UTC"}
    assert client.put("/api/settings/timezone", json={"timezone": "Nowhere/City"}, headers=h).status_code == 422
    assert client.put("/api/settings/timezone", json={"timezone": "Europe/Berlin"}, headers=h).status_code == 200
    assert client.get("/api/settings/schedule").json()["timezone"] == "Europe/Berlin"
    assert str(sched.get_job("daily-scan").trigger.timezone) == "Europe/Berlin"
    with ctx_of(env).session_factory() as s:
        assert "settings.timezone" in [a.action for a in s.scalars(select(AuditLog))]


def test_the_running_server_starts_the_scheduler_and_applies_changes(tmp_path, caplog):
    from fastapi.testclient import TestClient
    from tests.conftest import Env
    env = Env(tmp_path, caplog)
    sched = env.app.state.scheduler
    assert not sched.running
    with TestClient(env.app):   # Lebenszyklus wie im echten Server
        assert sched.running
        assert {j.id for j in sched.get_jobs()} >= {"maintenance", "release-sync", "daily-scan"}
        env.app.state.ctx.on_schedule_change()   # z. B. nach einer Zeitplan-Änderung
        assert sched.get_job("daily-scan") is not None
    assert not sched.running
