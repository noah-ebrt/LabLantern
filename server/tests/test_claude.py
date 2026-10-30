import http.server
import json
import logging
import threading

import pytest
from sqlalchemy import select, text

from app.aibase import short_error
from app.models import AuditLog
from tests.conftest import Env

KEY = "sk-ant-api03-GEHEIMER-TESTSCHLUESSEL-0123456789abcdef"


class FakeAnthropic:
    """Kleiner Server, der die Anthropic-API nachbildet: prüft den Schlüssel im Header."""

    def __init__(self, status=200, valid_key=KEY):
        self.requests = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                ok = self.headers.get("x-api-key") == valid_key
                code = status if ok else 401
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"data": []} if code == 200 else {"error": {"message": "nope " + (self.headers.get("x-api-key") or "")}}).encode())

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def anthropic():
    f = FakeAnthropic()
    yield f
    f.stop()


@pytest.fixture
def cadmin(tmp_path, caplog, anthropic):
    env = Env(tmp_path, caplog, anthropic_base_url=anthropic.url)
    secret = env.complete_setup()
    csrf = env.login(env.client, secret).json()["csrf_token"]
    return env, env.client, {"X-CSRF-Token": csrf}


def test_endpoints_require_login_and_admin(cadmin):
    env, client, h = cadmin
    anon = env.new_client()
    assert anon.get("/api/integrations/claude").status_code == 401
    assert client.put("/api/integrations/claude", json={"api_key": KEY}).status_code == 403
    assert client.post("/api/integrations/claude/test").status_code == 403
    assert client.delete("/api/integrations/claude").status_code == 403


def test_unconfigured_state(cadmin):
    env, client, h = cadmin
    assert client.get("/api/integrations/claude").json() == {
        "configured": False, "api_key": {"set": False, "updated_at": None}, "model": "claude-haiku-5-5",
        "selected": None, "auto_model": "claude-haiku-5-5", "last_used": None}


def test_save_stores_the_key_encrypted_and_never_returns_it(cadmin):
    env, client, h = cadmin
    r = client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h)
    assert r.status_code == 200 and KEY not in r.text
    got = client.get("/api/integrations/claude")
    assert got.json()["configured"] is True and got.json()["api_key"]["set"] is True
    assert KEY not in got.text
    assert env.app.state.ctx.secrets.get("claude.api_key") == KEY


@pytest.mark.parametrize("bad", ["", "kurz", "mit leerzeichen " + "x" * 30, "x" * 500, "zeilen\numbruch" + "x" * 30])
def test_malformed_keys_are_rejected(cadmin, bad):
    env, client, h = cadmin
    assert client.put("/api/integrations/claude", json={"api_key": bad}, headers=h).status_code == 422


def test_test_button_succeeds_with_a_valid_key_and_sends_it_as_header_only(cadmin, anthropic):
    env, client, h = cadmin
    client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h)
    r = client.post("/api/integrations/claude/test", headers=h)
    assert r.json() == {"ok": True}
    path, headers = anthropic.requests[0]
    assert headers["x-api-key"] == KEY and headers["anthropic-version"] == "2023-06-01"
    assert KEY not in path


def test_test_button_reports_a_wrong_key_without_echoing_it(cadmin):
    env, client, h = cadmin
    wrong = "sk-ant-api03-FALSCH-" + "y" * 30
    client.put("/api/integrations/claude", json={"api_key": wrong}, headers=h)
    body = client.post("/api/integrations/claude/test", headers=h).json()
    assert body["ok"] is False and "invalid" in body["error"] and "401" in body["error"]
    assert wrong not in json.dumps(body)


def test_test_button_reports_server_errors_and_unreachable_api(tmp_path, caplog):
    srv = FakeAnthropic(status=500)
    try:
        env = Env(tmp_path / "a", caplog, anthropic_base_url=srv.url)
        secret = env.complete_setup()
        h = {"X-CSRF-Token": env.login(env.client, secret).json()["csrf_token"]}
        env.client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h)
        assert "500" in env.client.post("/api/integrations/claude/test", headers=h).json()["error"]
    finally:
        srv.stop()
    caplog.clear()
    env2 = Env(tmp_path / "b", caplog, anthropic_base_url="http://127.0.0.1:9")
    secret = env2.complete_setup()
    h2 = {"X-CSRF-Token": env2.login(env2.client, secret).json()["csrf_token"]}
    env2.client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h2)
    body = env2.client.post("/api/integrations/claude/test", headers=h2).json()
    assert body["ok"] is False and "unreachable" in body["error"]


def test_test_without_key_is_409(cadmin):
    env, client, h = cadmin
    assert client.post("/api/integrations/claude/test", headers=h).status_code == 409


def test_delete_removes_the_key(cadmin):
    env, client, h = cadmin
    client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h)
    assert client.delete("/api/integrations/claude", headers=h).status_code == 200
    assert client.get("/api/integrations/claude").json()["configured"] is False
    assert env.app.state.ctx.secrets.get("claude.api_key") is None


def test_key_is_nowhere_readable_after_all_operations(cadmin, caplog):
    """Abnahme-Kriterium wie beim SMTP-Passwort: nicht in API, Datenbank, Dateien, Logs, Audit-Log."""
    env, client, h = cadmin
    with caplog.at_level(logging.DEBUG):
        client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h)
        client.post("/api/integrations/claude/test", headers=h)
        client.put("/api/integrations/claude", json={"api_key": "sk-ant-api03-ZWEITER-" + "z" * 30}, headers=h)
        client.post("/api/integrations/claude/test", headers=h)
        client.put("/api/integrations/claude", json={"api_key": KEY}, headers=h)
        seen = [client.get(p).text for p in ("/api/state", "/api/overview", "/api/integrations/claude")]
        ctx = env.app.state.ctx
        with ctx.session_factory() as s:
            s.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
            seen.append("\n".join(s.connection().connection.iterdump()))
            seen.append(repr([(a.actor, a.action, a.detail) for a in s.scalars(select(AuditLog))]))
        for f in env.data_dir.rglob("*"):
            if f.is_file() and f.name != "master.key":
                seen.append(f.read_bytes().decode("latin-1"))
        seen.append(caplog.text)
    blob = "\n".join(seen)
    assert KEY not in blob and "ZWEITER" not in blob
    assert "claude" in repr([a.action for a in ctx.session_factory().__enter__().scalars(select(AuditLog))])


def test_validation_errors_never_echo_the_submitted_secret(cadmin):
    env, client, h = admin = cadmin
    r = client.put("/api/integrations/claude", json={"api_key": "mit leerzeichen GEHEIMER-SCHLUESSEL-TEIL " + "x" * 30}, headers=h)
    assert r.status_code == 422
    assert "GEHEIMER-SCHLUESSEL-TEIL" not in r.text
    assert r.json()["detail"][0]["loc"][-1] == "api_key"          # Feldname und Grund bleiben sichtbar


def test_models_come_from_anthropic_and_auto_picks_the_newest_haiku(admin, monkeypatch):
    from app import integrations

    env, client, h = admin
    env.app.state.ctx.secrets.set("claude.api_key", KEY)
    models = [{"id": "claude-haiku-5-5", "display_name": "Claude Haiku 5.5", "created_at": "2026-06-01T00:00:00Z"},
              {"id": "claude-opus-5-5", "display_name": "Claude Opus 5.5", "created_at": "2026-07-01T00:00:00Z"},
              {"id": "claude-haiku-6", "display_name": "Claude Haiku 6", "created_at": "2026-10-20T00:00:00Z"},
              {"id": "not a model", "created_at": "2026-10-21T00:00:00Z"}]
    calls = []

    def fake(base, key, opener=None):
        calls.append(key)
        return sorted([{"id": m["id"], "name": m.get("display_name", m["id"]), "created_at": m["created_at"]}
                       for m in models if integrations._MODEL_ID.match(m["id"])], key=lambda m: m["created_at"], reverse=True)

    monkeypatch.setattr(integrations, "fetch_models", fake)
    data = client.get("/api/integrations/claude/models").json()
    assert [m["id"] for m in data["items"]] == ["claude-haiku-6", "claude-opus-5-5", "claude-haiku-5-5"]
    assert data["auto"] == "claude-haiku-6"
    client.get("/api/integrations/claude/models")
    assert len(calls) == 1   # 24 h zwischengespeichert
    assert client.get("/api/integrations/claude").json()["model"] == "claude-haiku-6"
    assert client.put("/api/integrations/claude/model", headers=h, json={"model": "rm -rf"}).status_code == 422
    assert client.put("/api/integrations/claude/model", headers=h, json={"model": "claude-opus-5-5"}).json()["model"] == "claude-opus-5-5"
    assert integrations.resolve_model(env.app.state.ctx) == "claude-opus-5-5"
    client.put("/api/integrations/claude/model", headers=h, json={"model": None})
    assert integrations.resolve_model(env.app.state.ctx) == "claude-haiku-6"


def test_usage_limit_message_is_passed_through():
    body = {"error": {"type": "invalid_request_error", "message": "You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC."}}
    msg = short_error("Anthropic", 400, body, secret=None)
    assert msg == "Anthropic: You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC. (HTTP 400)"


def test_error_text_is_truncated_and_scrubbed():
    key = "sk-ant-api03-SECRET-0123456789abcdef"
    msg = short_error("OpenAI", 401, {"error": {"message": f"bad key {key} " + "x" * 600}}, secret=key)
    assert key not in msg and len(msg) <= 340 and msg.endswith("(HTTP 401)")
