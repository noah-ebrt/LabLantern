from tests.test_agent_api import activate, report


def test_command_roundtrip_report_now_and_query(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    agent = env.new_client()
    agent.post("/api/agent/report", headers=bearer, json=report())   # nichts fällig
    assert agent.post("/api/agent/commands/next", headers=bearer).json() == {"report": False, "commands": [], "passkeys": None}

    c1 = client.post(f"/api/systems/{sid}/commands", headers=h, json={"type": "query", "query": "uptime"}).json()
    assert c1["status"] == "queued" and c1["params"] == {"name": "uptime"}
    nxt = agent.post("/api/agent/commands/next", headers=bearer).json()
    assert nxt["commands"] == [{"id": c1["id"], "type": "query", "params": {"name": "uptime"}}]
    assert agent.post("/api/agent/commands/next", headers=bearer).json()["commands"] == []   # nur einmal ausgeliefert

    r = agent.post(f"/api/agent/commands/{c1['id']}/result", headers=bearer, json={"status": "done", "output": "up 3 days"})
    assert r.status_code == 200
    hist = client.get(f"/api/systems/{sid}/commands").json()
    assert hist[0]["status"] == "done" and hist[0]["output"] == "up 3 days"
    assert client.get("/api/systems").json()[0]["online"] is True


def test_only_allowlisted_commands_and_queries_are_accepted(admin):
    env, client, h = admin
    sid, _ = activate(env, client, h)
    for body in ({"type": "shell", "cmd": "id"}, {"type": "query", "query": "cat /etc/shadow"},
                 {"type": "query"}, {"type": "reboot"}):
        assert client.post(f"/api/systems/{sid}/commands", headers=h, json=body).status_code == 422
    assert client.post(f"/api/systems/{sid}/commands", json={"type": "report_now"}).status_code in (401, 403)


def test_results_only_from_the_agent_that_received_the_command(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h, hostname="a")
    _, other = activate(env, client, h, hostname="b")
    c = client.post(f"/api/systems/{sid}/commands", headers=h, json={"type": "report_now"}).json()
    agent = env.new_client()
    url = f"/api/agent/commands/{c['id']}/result"
    assert agent.post(url, headers=bearer, json={"status": "done"}).status_code == 404   # noch nicht abgeholt
    agent.post("/api/agent/commands/next", headers=bearer)
    assert agent.post(url, headers=other, json={"status": "done"}).status_code == 404
    assert agent.post(url, headers=bearer, json={"status": "done"}).status_code == 200
    assert agent.post(url, headers=bearer, json={"status": "failed"}).status_code == 404   # nur einmal


def test_stale_commands_expire_and_the_queue_is_bounded(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    for _ in range(5):
        assert client.post(f"/api/systems/{sid}/commands", headers=h, json={"type": "report_now"}).status_code == 200
    assert client.post(f"/api/systems/{sid}/commands", headers=h, json={"type": "report_now"}).status_code == 429
    env.clock.advance(301)
    assert {c["status"] for c in client.get(f"/api/systems/{sid}/commands").json()} == {"expired"}
    assert env.new_client().post("/api/agent/commands/next", headers=bearer).json()["commands"] == []


def test_long_poll_requires_a_valid_agent_token(env):
    c = env.new_client()
    assert c.post("/api/agent/commands/next").status_code == 401
    assert c.post("/api/agent/commands/next", headers={"Authorization": "Bearer nope"}).status_code == 401
