import json
import urllib.error

import pytest

from app import watchdog
from app.models import Setting

HB = "https://watch.example.org/ping/911f7b7a-4644-4bfa-aa48-987388bac60d"
RUN = "https://watch.example.org/ping/0a1b2c3d-4644-4bfa-aa48-987388bac60d"


class Pings:
    """Fängt die Pings ab, statt ins Netz zu gehen."""

    def __init__(self, monkeypatch, fail=None):
        self.sent = []
        self.fail = fail

        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(req, timeout):
            self.sent.append((req.full_url, req.data.decode()))
            if self.fail:
                raise self.fail
            return Resp()
        monkeypatch.setattr(watchdog.urllib.request, "urlopen", urlopen)


@pytest.fixture
def wd(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    return env, client, h, ctx


def test_urls_are_validated_stored_secretly_and_shown_masked(wd):
    env, client, h, ctx = wd
    assert client.put("/api/settings/watchdog", headers=h, json={"heartbeat_url": "http://evil/ping/x"}).status_code == 422
    assert client.put("/api/settings/watchdog", headers=h, json={"run_url": "https://x.org/api/v3/checks/"}).status_code == 422
    assert client.put("/api/settings/watchdog", headers=h, json={"heartbeat_url": HB, "run_url": RUN}).status_code == 200
    got = client.get("/api/settings/watchdog")
    assert "911f7b7a-4644" not in got.text   # nie die volle URL zurückgeben
    assert got.json()["heartbeat"]["set"] is True and got.json()["heartbeat"]["target"] == "watch.example.org/ping/911f…c60d"
    assert client.put("/api/settings/watchdog", json={"heartbeat_url": HB}).status_code in (401, 403)
    client.put("/api/settings/watchdog", headers=h, json={"clear": ["run"]})
    assert client.get("/api/settings/watchdog").json()["run"]["set"] is False


def test_heartbeat_reports_a_silent_worker_as_failure(wd, monkeypatch):
    env, client, h, ctx = wd
    ctx.secrets.set(watchdog.SECRETS["heartbeat"], HB)
    p = Pings(monkeypatch)
    watchdog.heartbeat(ctx)   # Worker nie gesehen
    assert p.sent[-1][0] == HB + "/fail" and "worker was last seen never" in p.sent[-1][1]
    with ctx.session_factory() as s:
        s.add(Setting(key="worker.last_seen", value=str(ctx.clock() - 30)))
        s.commit()
    watchdog.heartbeat(ctx)
    assert p.sent[-1][0] == HB and "worker seen 30 s ago" in p.sent[-1][1]
    last = client.get("/api/settings/watchdog").json()["heartbeat"]["last"]
    assert last["ok"] is True and last["sent"] == "success"


def test_runs_ping_start_then_success_or_fail_with_reason(wd, monkeypatch):
    env, client, h, ctx = wd
    ctx.secrets.set(watchdog.SECRETS["run"], RUN)
    p = Pings(monkeypatch)
    watchdog.run_started(ctx, 7, "scheduled")
    watchdog.run_finished(ctx, 7, "success", canary_ok=True)
    watchdog.run_finished(ctx, 8, "partial", canary_ok=False, error="1 system(s) not checked")
    assert [u for u, _ in p.sent] == [RUN + "/start", RUN, RUN + "/fail"]
    assert "canary test failed" in p.sent[2][1] and "not checked" in p.sent[2][1]


def test_unreachable_healthchecks_never_breaks_anything(wd, monkeypatch):
    env, client, h, ctx = wd
    ctx.secrets.set(watchdog.SECRETS["heartbeat"], HB)
    Pings(monkeypatch, fail=urllib.error.URLError("timed out"))
    watchdog.heartbeat(ctx)   # wirft nicht
    last = client.get("/api/settings/watchdog").json()["heartbeat"]["last"]
    assert last["ok"] is False and "unreachable" in last["error"]


def test_nothing_is_sent_without_configuration_and_test_needs_a_url(wd, monkeypatch):
    env, client, h, ctx = wd
    p = Pings(monkeypatch)
    watchdog.heartbeat(ctx)
    watchdog.run_started(ctx, 1, "manual")
    assert p.sent == []
    assert client.post("/api/settings/watchdog/test", headers=h).status_code == 409
    ctx.secrets.set(watchdog.SECRETS["heartbeat"], HB)
    r = client.post("/api/settings/watchdog/test", headers=h)
    assert r.json() == {"heartbeat": {"ok": True, "error": None}} and p.sent[-1][0] == HB
    assert json.loads(json.dumps(r.json()))   # serialisierbar


def test_runs_ping_the_watchdog_on_start_and_on_every_finish(admin, monkeypatch):
    from tests.test_scan_flow import Notes, make_system
    from app.scanrun import claim_job, enqueue_scan_run, fail_job
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    ctx.secrets.set(watchdog.SECRETS["run"], RUN)
    p = Pings(monkeypatch)
    make_system(ctx, "host-c")
    run = enqueue_scan_run(ctx, "scheduled")
    job = claim_job(ctx)
    fail_job(ctx, job["id"], "Worker returned no result within 30 min")
    assert [u for u, _ in p.sent] == [RUN + "/start", RUN + "/fail"]
    assert f"Run #{run.id}" in p.sent[1][1] and "no result" in p.sent[1][1]


def test_scheduler_has_the_heartbeat_job(env):
    assert env.app.state.scheduler.get_job("watchdog-heartbeat") is not None
