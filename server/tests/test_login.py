import pyotp
import pytest

from tests.conftest import PASSWORD


@pytest.fixture
def ready(env):
    secret = env.complete_setup()
    return env, secret


def test_login_success_sets_hardened_session_cookie(ready):
    env, secret = ready
    r = env.login(env.client, secret)
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "noah" and body["role"] == "admin" and body["csrf_token"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie
    state = env.client.get("/api/state").json()
    assert state["authenticated"] is True and state["csrf_token"] == body["csrf_token"]


def test_login_wrong_password_is_rejected(ready):
    env, secret = ready
    r = env.login(env.client, secret, password="falsches-passwort-xyz")
    assert r.status_code == 401


def test_login_wrong_totp_is_rejected(ready):
    env, secret = ready
    r = env.client.post("/api/login", json={"username": "noah", "password": PASSWORD,
                                            "totp_code": "000000"})
    assert r.status_code == 401


def test_login_unknown_user_gets_same_answer_as_wrong_password(ready):
    env, secret = ready
    a = env.login(env.client, secret, username="gibtsnicht")
    b = env.login(env.client, secret, password="falsches-passwort-xyz")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_totp_code_cannot_be_replayed(ready):
    env, secret = ready
    code = env.totp_code(secret)
    body = {"username": "noah", "password": PASSWORD, "totp_code": code}
    assert env.client.post("/api/login", json=body).status_code == 200
    assert env.new_client().post("/api/login", json=body).status_code == 401


def test_login_without_second_factor_field_is_rejected(ready):
    env, _ = ready
    r = env.client.post("/api/login", json={"username": "noah", "password": PASSWORD})
    assert r.status_code == 422


def test_five_failures_lock_the_account_even_for_correct_credentials(ready):
    env, secret = ready
    for _ in range(5):
        assert env.login(env.client, secret, password="falsches-passwort-xyz").status_code == 401
    r = env.login(env.client, secret)
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0


def test_failures_from_another_address_do_not_lock_the_admin_out(ready):
    from fastapi.testclient import TestClient
    env, secret = ready
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.168.1.66", 40000))
    for _ in range(6):
        attacker.post("/api/login", json={"username": "noah", "password": "falsches-passwort-xyz", "totp_code": "000000"})
    assert env.login(env.client, secret).status_code == 200


def test_lock_expires_after_window(ready):
    env, secret = ready
    for _ in range(5):
        env.login(env.client, secret, password="falsches-passwort-xyz")
    env.clock.advance(901)
    assert env.login(env.client, secret).status_code == 200


def test_session_expires(ready):
    env, secret = ready
    env.login(env.client, secret)
    env.clock.advance(12 * 3600 + 1)
    assert env.client.get("/api/state").json()["authenticated"] is False


def test_logout_requires_csrf_header(ready):
    env, secret = ready
    csrf = env.login(env.client, secret).json()["csrf_token"]
    assert env.client.post("/api/logout").status_code == 403
    assert env.client.post("/api/logout", headers={"X-CSRF-Token": "falsch"}).status_code == 403
    assert env.client.get("/api/state").json()["authenticated"] is True
    assert env.client.post("/api/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert env.client.get("/api/state").json()["authenticated"] is False


def test_logout_without_session_is_401(ready):
    env, _ = ready
    assert env.client.post("/api/logout").status_code == 401


def test_session_token_is_stored_only_as_hash(ready):
    env, secret = ready
    env.login(env.client, secret)
    raw = env.client.cookies.get("ll_session")
    db_bytes = b"".join(p.read_bytes() for p in env.data_dir.glob("lablantern.db*"))
    assert raw.encode() not in db_bytes


def test_audit_log_records_login_events_without_secrets(ready):
    env, secret = ready
    env.login(env.client, secret, password="falsches-passwort-xyz")
    env.login(env.client, secret)
    from sqlalchemy import select
    from app.models import AuditLog
    with env.app.state.ctx.session_factory() as s:
        rows = [(r.action, r.detail) for r in s.scalars(select(AuditLog).order_by(AuditLog.id))]
    actions = [a for a, _ in rows]
    assert actions == ["setup.completed", "login.failed", "login"]
    text = repr(rows)
    assert PASSWORD not in text and "falsches-passwort-xyz" not in text
