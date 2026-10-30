import hashlib
import pyotp


def test_state_before_setup(env):
    r = env.client.get("/api/state")
    assert r.status_code == 200
    assert r.json() == {"setup_complete": False, "authenticated": False}


def test_setup_token_is_logged_at_first_start_but_stored_only_as_hash(env):
    assert env.setup_token and len(env.setup_token) >= 24
    db_bytes = b"".join(p.read_bytes() for p in env.data_dir.glob("vulnwatch.db*"))
    assert env.setup_token.encode() not in db_bytes
    assert hashlib.sha256(env.setup_token.encode()).hexdigest().encode() in db_bytes


def test_totp_step_without_token_is_rejected(env):
    assert env.client.post("/api/setup/totp", json={}).status_code == 422


def test_totp_step_with_wrong_token_is_forbidden(env):
    r = env.client.post("/api/setup/totp", json={"setup_token": "falsch"})
    assert r.status_code == 403


def test_complete_with_wrong_token_creates_no_admin(env):
    secret = pyotp.random_base32()
    r = env.client.post(
        "/api/setup/complete",
        json={"setup_token": "falsch", "username": "noah",
              "password": "korrekt-pferd-batterie", "totp_code": pyotp.TOTP(secret).now()},
    )
    assert r.status_code == 403
    assert env.client.get("/api/state").json()["setup_complete"] is False


def test_complete_with_wrong_totp_code_is_rejected(env):
    env.client.post("/api/setup/totp", json={"setup_token": env.setup_token})
    r = env.client.post(
        "/api/setup/complete",
        json={"setup_token": env.setup_token, "username": "noah",
              "password": "korrekt-pferd-batterie", "totp_code": "000000"},
    )
    assert r.status_code == 400
    assert env.client.get("/api/state").json()["setup_complete"] is False


def test_complete_without_totp_step_is_rejected(env):
    r = env.client.post(
        "/api/setup/complete",
        json={"setup_token": env.setup_token, "username": "noah",
              "password": "korrekt-pferd-batterie", "totp_code": "123456"},
    )
    assert r.status_code == 400


def test_short_password_is_rejected(env):
    env.client.post("/api/setup/totp", json={"setup_token": env.setup_token})
    r = env.client.post(
        "/api/setup/complete",
        json={"setup_token": env.setup_token, "username": "noah",
              "password": "kurz", "totp_code": "123456"},
    )
    assert r.status_code == 422


def test_totp_step_returns_secret_and_otpauth_uri(env):
    r = env.client.post("/api/setup/totp", json={"setup_token": env.setup_token})
    body = r.json()
    assert r.status_code == 200
    assert pyotp.TOTP(body["totp_secret"]).now()
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert body["totp_secret"] in body["otpauth_uri"]


def test_setup_completes_once_and_token_is_burned(env):
    env.complete_setup()
    assert env.client.get("/api/state").json()["setup_complete"] is True
    r = env.client.post("/api/setup/totp", json={"setup_token": env.setup_token})
    assert r.status_code == 409
    r = env.client.post(
        "/api/setup/complete",
        json={"setup_token": env.setup_token, "username": "zweiter",
              "password": "korrekt-pferd-batterie", "totp_code": "123456"},
    )
    assert r.status_code == 409


def test_failed_token_guesses_are_rate_limited(env):
    codes = [env.client.post("/api/setup/totp", json={"setup_token": f"raten{i}"}).status_code
             for i in range(8)]
    assert codes[:5] == [403] * 5
    assert 429 in codes[5:]
    # auch das richtige Token wird in der Sperre abgewiesen
    assert env.client.post("/api/setup/totp", json={"setup_token": env.setup_token}).status_code == 429


def test_new_token_is_issued_on_restart_while_setup_incomplete(tmp_path, caplog):
    from tests.conftest import Env
    first = Env(tmp_path, caplog)
    caplog.clear()
    second = Env(tmp_path, caplog)
    assert second.setup_token and second.setup_token != first.setup_token
    r = second.client.post("/api/setup/totp", json={"setup_token": first.setup_token})
    assert r.status_code == 403


def test_no_token_is_logged_once_setup_is_done(tmp_path, caplog):
    from tests.conftest import Env
    first = Env(tmp_path, caplog)
    first.complete_setup()
    caplog.clear()
    second = Env(tmp_path, caplog)
    assert second.setup_token is None
    assert second.client.get("/api/state").json()["setup_complete"] is True


def test_totp_step_includes_scannable_qr_as_svg(env):
    body = env.client.post("/api/setup/totp", json={"setup_token": env.setup_token}).json()
    assert body["qr_svg"].lstrip().startswith(("<?xml", "<svg"))
    assert "<script" not in body["qr_svg"].lower()
