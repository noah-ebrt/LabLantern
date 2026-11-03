import asyncio
import json
import socket
import threading
import time
from contextlib import contextmanager

import httpx
import uvicorn

from app.models import AgentCommand, System
from tests.test_agent_api import activate, report
from tests.test_pairing import pair, status


def collect(env, action):
    """Führt `action` (synchron, mit DB-Zugriffen) aus und liefert die dabei veröffentlichten Themen."""
    hub = env.app.state.events

    async def run():
        q = hub.subscribe()
        try:
            await asyncio.to_thread(action)
            await asyncio.sleep(0.05)
            got = set()
            while not q.empty():
                got |= set(q.get_nowait())
            return got
        finally:
            hub.unsubscribe(q)

    return asyncio.run(run())


def test_commits_publish_the_touched_topics(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    agent = env.new_client()
    assert "systems" in collect(env, lambda: agent.post("/api/agent/report", headers=bearer, json=report()))
    assert collect(env, lambda: client.post(f"/api/systems/{sid}/commands", headers=h,
                                            json={"type": "report_now"})) == {"commands"}


def test_long_poll_heartbeats_and_reads_publish_nothing(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    agent = env.new_client()
    assert collect(env, lambda: agent.post("/api/agent/commands/next", headers=bearer)) == set()
    assert collect(env, lambda: client.get("/api/systems")) == set()
    assert collect(env, lambda: client.get(f"/api/systems/{sid}/commands")) == set()


def test_bulk_expiry_publishes_and_rollback_does_not(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    client.post(f"/api/systems/{sid}/commands", headers=h, json={"type": "report_now"})
    env.clock.advance(301)
    assert collect(env, lambda: client.get(f"/api/systems/{sid}/commands")) == {"commands"}

    def rolled_back():
        with env.app.state.ctx.session_factory() as s:
            s.get(System, sid).name = "other"
            s.flush()
            s.rollback()
    assert collect(env, rolled_back) == set()


def test_fresh_agent_initializes_then_reports_or_times_out(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    state = lambda: client.get(f"/api/systems/{sid}").json()["state"]   # noqa: E731
    assert state() == "initializing"
    env.clock.advance(170)
    assert state() == "initializing"
    env.clock.advance(20)
    assert state() == "error"
    env.new_client().post("/api/agent/report", headers=bearer, json=report())
    assert state() == "online"


def test_paired_agent_starts_initializing(admin):
    env, client, h = admin
    pid = pair(env)
    client.post(f"/api/pairings/{pid}/approve", headers=h, json={})
    assert status(env, pid).json()["status"] == "approved"
    assert client.get("/api/systems").json()[0]["state"] == "initializing"


def test_watcher_snapshot_sees_time_based_changes(admin):
    env, client, h = admin
    activate(env, client, h)
    hub = env.app.state.events
    before = hub.snapshot()
    env.clock.advance(181)
    assert hub.snapshot() != before   # initializing -> error, ohne dass jemand schreibt


def test_event_stream_needs_a_session(env):
    assert env.client.get("/api/events").status_code == 401


@contextmanager
def served(env):
    """Echter Server im Thread: Der TestClient wartet auf das Ende einer Antwort, ein Live-Strom endet nie."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(env.app, host="127.0.0.1", port=port, log_level="error",
                                           timeout_graceful_shutdown=1))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        t.join(timeout=5)


def stream_lines(base, client):
    cookie = {"Cookie": f"ll_session={client.cookies.get('ll_session')}"}
    return httpx.stream("GET", f"{base}/api/events", headers=cookie, timeout=5)


def test_event_stream_delivers_changes(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    env.app.state.events.heartbeat = 0.05
    with served(env) as base, stream_lines(base, client) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        lines = r.iter_lines()
        assert "event: hello" in [next(lines) for _ in range(3)]
        with env.app.state.ctx.session_factory() as s:
            s.add(AgentCommand(system_id=sid, type="report_now", created_at=env.clock()))
            s.commit()
        for line in lines:
            if line.startswith("data:") and "topics" in line:
                assert "commands" in json.loads(line[5:])["topics"]
                break


def test_event_stream_ends_on_logout(admin):
    env, client, h = admin
    env.app.state.events.heartbeat = 0.05
    with served(env) as base, stream_lines(base, client) as r:
        lines = r.iter_lines()
        next(lines)
        assert client.post("/api/logout", headers=h).status_code == 200
        assert "event: logout" in list(lines)   # der Strom endet danach von selbst
