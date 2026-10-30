from app.models import System


def test_overview_requires_login(env):
    assert env.client.get("/api/overview").status_code == 401


def test_overview_is_empty_but_well_formed(admin):
    env, client, _ = admin
    body = client.get("/api/overview").json()
    assert body["findings"] == {"kritisch": 0, "hoch": 0, "mittel": 0, "info": 0}
    assert body["coverage"] == []
    assert body["last_run"] is None and body["active_run"] is None
    assert body["next_run"] == "2027-01-16T03:00:00+00:00"       # täglicher Lauf ist standardmäßig an
    assert body["ampel"] == "unbekannt"
    assert body["watchdog"] == {"configured": False}
    assert body["setup_hints"] == [{"id": "notifications", "done": False}]


def test_overview_marks_notification_hint_done_once_a_channel_is_saved(admin):
    env, client, h = admin
    client.post("/api/integrations/notifications", json={"name": "Test", "url": "json://localhost:9/"}, headers=h)
    assert client.get("/api/overview").json()["setup_hints"] == [{"id": "notifications", "done": True}]


def test_smtp_alone_does_not_count_as_a_delivery_channel(admin, smtp_server):
    """Reports und Alarme laufen über Apprise, nicht über das SMTP-Feld."""
    from tests.test_smtp import smtp_body
    env, client, h = admin
    client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers=h)
    assert client.get("/api/overview").json()["setup_hints"] == [{"id": "notifications", "done": False}]


def test_api_responses_carry_security_headers(env):
    r = env.client.get("/api/state")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_a_new_host_waits_for_its_first_scan_instead_of_showing_an_error(admin):
    from datetime import datetime, timedelta, timezone

    from app.coverage import calculate_coverage_matrix
    from tests.test_agent_api import activate, report
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report())
    row = client.get("/api/overview").json()["coverage"][0]
    assert row["checks"]["paket_cve"] == {"status": "offen", "detail": "new host: checked in the next scan run"}
    assert row["last_scan"] is None and row["image_problems"] == [] and "collection_errors" in row
    later = datetime.now(timezone.utc) + timedelta(hours=37)
    with env.app.state.ctx.session_factory() as s:
        cve = calculate_coverage_matrix(s, later)["systems"][0]["checks"]["paket_cve"]
    assert cve["status"] == "fehler"   # nach 36 h ohne Scan doch ein Fehler


def test_a_finding_counts_as_checked_for_coverage(admin):
    from app.coverage import calculate_coverage_matrix
    from tests.test_agent_api import activate, report
    env, client, h = admin
    _, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report())   # 2 Updates offen, Neustart nötig
    with env.app.state.ctx.session_factory() as s:
        cov = calculate_coverage_matrix(s)
    checks = cov["systems"][0]["checks"]
    assert checks["sicherheitsupdates"]["status"] == checks["reboot"]["status"] == "fund"
    assert checks["paket_cve"]["status"] == checks["versionen"]["status"] == "offen"   # noch nicht geprüft
    assert cov["ok_checks"] == cov["total_checks"] - 2


def test_system_coverage_row_for_the_host_view(admin):
    env, client, h = admin
    with env.app.state.ctx.session_factory() as s:
        sys = System(name="h1", status="active", host_type="linux")
        s.add(sys)
        s.commit()
        sid = sys.id
    row = client.get(f"/api/systems/{sid}/coverage").json()
    assert row["system_id"] == sid and set(row["checks"]) >= {"paket_cve", "versionen"}
    assert client.get("/api/systems/999999/coverage").status_code == 404
