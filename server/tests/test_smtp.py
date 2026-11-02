import pytest

from tests.conftest import SMTP_PASS, SMTP_USER


def smtp_body(_port, **over):
    body = {"host": "127.0.0.1", "port": _port, "security": "none", "username": SMTP_USER,
            "from_addr": "vulnwatch@example.org", "to_addr": "noah@example.org",
            "password": SMTP_PASS}
    body.update(over)
    return body


def test_smtp_endpoints_require_login(env):
    assert env.client.get("/api/integrations/smtp").status_code == 401
    assert env.client.put("/api/integrations/smtp", json={}).status_code == 401
    assert env.client.post("/api/integrations/smtp/test").status_code == 401


def test_unconfigured_smtp_reports_password_not_set(admin):
    env, client, _ = admin
    body = client.get("/api/integrations/smtp").json()
    assert body["configured"] is False
    assert body["password"] == {"set": False, "updated_at": None}


def test_save_requires_csrf(admin, smtp_server):
    env, client, _ = admin
    r = client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port))
    assert r.status_code == 403


def test_save_then_get_shows_settings_but_never_the_password(admin, smtp_server):
    env, client, h = admin
    r = client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers=h)
    assert r.status_code == 200
    got = client.get("/api/integrations/smtp").json()
    assert got["configured"] is True
    assert got["host"] == "127.0.0.1" and got["username"] == SMTP_USER
    assert got["password"]["set"] is True and got["password"]["updated_at"]
    assert SMTP_PASS not in r.text and SMTP_PASS not in str(got)


def test_omitting_password_keeps_the_stored_one(admin, smtp_server):
    env, client, h = admin
    client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers=h)
    body = smtp_body(smtp_server.port, to_addr="ops@example.org")   # gleicher Server (anderer: test_secret_retarget)
    del body["password"]
    assert client.put("/api/integrations/smtp", json=body, headers=h).status_code == 200
    assert env.app.state.ctx.secrets.get("smtp.password") == SMTP_PASS
    assert client.get("/api/integrations/smtp").json()["to_addr"] == "ops@example.org"


def test_invalid_settings_are_rejected(admin, smtp_server):
    env, client, h = admin
    for bad in ({"port": 0}, {"port": 70000}, {"security": "magic"}, {"host": ""},
                {"from_addr": "kein-mail"}, {"to_addr": "a@b.de\r\nBcc: x@y.de"}):
        r = client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port, **bad), headers=h)
        assert r.status_code == 422, bad


def test_connection_test_sends_a_real_mail(admin, smtp_server):
    env, client, h = admin
    client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers=h)
    r = client.post("/api/integrations/smtp/test", headers=h)
    assert r.json() == {"ok": True}
    sender, rcpts, msg = smtp_server.messages[0]
    assert sender == "vulnwatch@example.org" and rcpts == ["noah@example.org"]
    assert "vulnwatch" in msg["Subject"].lower()
    assert SMTP_PASS not in msg.as_string()


def test_connection_test_with_wrong_password_fails_without_leaking_it(admin, smtp_server):
    env, client, h = admin
    client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port, password="falsch-falsch-1"), headers=h)
    r = client.post("/api/integrations/smtp/test", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and body["error"]
    assert "falsch-falsch-1" not in r.text
    assert smtp_server.messages == []


def test_connection_test_without_server_reports_error(admin):
    env, client, h = admin
    client.put("/api/integrations/smtp", json=smtp_body(1, password="x"), headers=h)
    body = client.post("/api/integrations/smtp/test", headers=h).json()
    assert body["ok"] is False and body["error"]


def test_connection_test_without_config_is_409(admin):
    env, client, h = admin
    assert client.post("/api/integrations/smtp/test", headers=h).status_code == 409


def test_reader_may_view_but_not_change(admin, smtp_server):
    from app.auth import new_token, sha256_hex
    from app.models import AdminUser, SessionRow
    env, client, h = admin
    csrf = new_token()
    raw = new_token()
    ctx = env.app.state.ctx
    with ctx.session_factory() as s:
        u = AdminUser(username="leser", password_hash="x", role="reader")
        s.add(u)
        s.flush()
        s.add(SessionRow(token_hash=sha256_hex(raw), user_id=u.id, csrf_token=csrf,
                         expires_at=ctx.clock() + 3600))
        s.commit()
    reader = env.new_client()
    reader.cookies.set("vw_session", raw)
    assert reader.get("/api/integrations/smtp").status_code == 200
    r = reader.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403
    r = reader.post("/api/integrations/smtp/test", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403


def test_change_is_audited_without_values(admin, smtp_server):
    from sqlalchemy import select
    from app.models import AuditLog
    env, client, h = admin
    client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers=h)
    with env.app.state.ctx.session_factory() as s:
        rows = [(r.actor, r.action, r.detail) for r in s.scalars(select(AuditLog).order_by(AuditLog.id))]
    entry = [r for r in rows if r[1] == "integration.smtp.saved"]
    assert entry and entry[0][0] == "noah"
    assert "password" in entry[0][2].lower()
    assert SMTP_PASS not in repr(rows)
