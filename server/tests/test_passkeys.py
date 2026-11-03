import hashlib
import json

from tests.conftest import PASSWORD
from tests.softauthn import SoftAuthenticator, b64u
from tests.test_agent_api import activate


def register(client, h, auth, name="YubiKey"):
    opts = client.post("/api/passkeys/register/options", headers=h).json()
    r = client.post("/api/passkeys/register", headers=h, json={"name": name, "credential": auth.register(opts)})
    assert r.status_code == 200, r.text


def test_first_passkey_becomes_the_unsigned_initial_trust_list(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    key = SoftAuthenticator()
    register(client, h, key)
    info = client.get("/api/passkeys").json()
    assert info["rp_id"] == "lablantern.lan" and info["keys"][0]["name"] == "YubiKey"
    assert info["trust"] == {"rev": 1, "signed": False, "outdated": False}
    trust = env.new_client().post("/api/agent/commands/next", headers=bearer).json()["passkeys"]
    env_ = json.loads(trust["envelope"])
    assert trust["assertion"] == "" and env_["rp_id"] == "lablantern.lan" and [k["id"] for k in env_["keys"]] == [key.id]


def test_login_with_password_and_passkey(env):
    secret = env.complete_setup()
    c = env.new_client()
    csrf = env.login(c, secret).json()["csrf_token"]
    key = SoftAuthenticator()
    register(c, {"X-CSRF-Token": csrf}, key)

    fresh = env.new_client()
    assert fresh.post("/api/login/passkey/options", json={"username": "noah", "password": "wrong"}).status_code == 401
    o = fresh.post("/api/login/passkey/options", json={"username": "noah", "password": PASSWORD}).json()
    bad = fresh.post("/api/login/passkey", json={"token": o["token"], "credential": key.assertion(b64u(b"x" * 32))})
    assert bad.status_code == 400   # falsche Challenge; das Token ist danach verbraucht
    o = fresh.post("/api/login/passkey/options", json={"username": "noah", "password": PASSWORD}).json()
    r = fresh.post("/api/login/passkey", json={"token": o["token"], "credential": key.assertion(o["options"]["challenge"])})
    assert r.status_code == 200 and r.json()["username"] == "noah"
    assert fresh.get("/api/systems").status_code == 200


def test_reboot_needs_a_passkey_assertion_over_exactly_this_envelope(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    key = SoftAuthenticator()
    register(client, h, key)

    p = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"}).json()
    challenge = p["options"]["challenge"]
    assert challenge == b64u(hashlib.sha256(p["envelope"].encode()).digest())
    url = f"/api/systems/{sid}/commands/confirm"
    assert client.post(url, headers=h, json={"credential": key.assertion(b64u(b"other" * 7))}).status_code == 400
    p = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"}).json()
    assert client.post(url, headers=h, json={"credential": key.assertion(p["options"]["challenge"], flags=0x01)}).status_code == 400  # ohne UV
    p = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"}).json()
    r = client.post(url, headers=h, json={"credential": key.assertion(p["options"]["challenge"])})
    assert r.status_code == 200, r.text

    cmd = env.new_client().post("/api/agent/commands/next", headers=bearer).json()["commands"][0]
    assert cmd["type"] == "reboot" and cmd["params"]["envelope"] == p["envelope"]
    a = json.loads(cmd["params"]["assertion"])
    assert a["credential_id"] == key.id and a["signature"]
    shown = client.get(f"/api/systems/{sid}/commands").json()[0]
    assert "envelope" not in shown["params"] and shown["params"]["delay"] == "30"
    assert client.post(f"/api/systems/{sid}/commands", headers=h, json={"type": "reboot"}).status_code == 422


def test_new_keys_reach_agents_only_when_signed_by_an_already_trusted_key(admin):
    env, client, h = admin
    activate(env, client, h)
    first, second = SoftAuthenticator(), SoftAuthenticator()
    register(client, h, first)
    register(client, h, second, "Phone")
    assert client.get("/api/passkeys").json()["trust"]["outdated"] is True

    t = client.post("/api/passkeys/trust/options", headers=h).json()
    assert [c["id"] for c in t["options"]["allowCredentials"]] == [first.id]   # nur der bisher vertraute Schlüssel
    assert client.post("/api/passkeys/trust", headers=h,
                       json={"credential": second.assertion(t["options"]["challenge"])}).status_code == 400
    t = client.post("/api/passkeys/trust/options", headers=h).json()
    assert client.post("/api/passkeys/trust", headers=h,
                       json={"credential": first.assertion(t["options"]["challenge"])}).status_code == 200
    assert client.get("/api/passkeys").json()["trust"] == {"rev": 2, "signed": True, "outdated": False}


def test_update_is_refused_when_the_agent_is_current_and_without_a_passkey(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    assert client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"}).status_code == 409
    register(client, h, SoftAuthenticator())
    env.new_client().post("/api/agent/report", headers=bearer, json={"agent_version": "9.9.9", "hostname": "host-a",
                                                                       "os_id": "ubuntu", "packages": []})
    r = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "update_agent"})
    assert r.status_code == 409 and "already" in r.json()["detail"]


def test_uninstall_with_passkey_removes_the_system_once_the_agent_confirms(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    key = SoftAuthenticator()
    register(client, h, key)
    p = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "uninstall"}).json()
    assert client.post(f"/api/systems/{sid}/commands/confirm", headers=h,
                       json={"credential": key.assertion(p["options"]["challenge"])}).status_code == 200
    agent = env.new_client()
    cmd = agent.post("/api/agent/commands/next", headers=bearer).json()["commands"][0]
    assert cmd["type"] == "uninstall"
    assert client.get("/api/systems").json()   # noch da, bis der Agent bestätigt
    agent.post(f"/api/agent/commands/{cmd['id']}/result", headers=bearer, json={"status": "done", "output": "bye"})
    assert client.get("/api/systems").json() == []
    assert agent.post("/api/agent/commands/next", headers=bearer).status_code == 401


def test_a_running_action_blocks_further_ones_until_it_ends_or_times_out(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    key = SoftAuthenticator()
    register(client, h, key)
    p = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"}).json()
    client.post(f"/api/systems/{sid}/commands/confirm", headers=h, json={"credential": key.assertion(p["options"]["challenge"])})
    assert client.get("/api/systems").json()[0]["pending_action"] == "reboot"
    r = client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"})
    assert r.status_code == 409 and "still running" in r.json()["detail"]

    env.new_client().post("/api/agent/commands/next", headers=bearer)   # abgeholt, aber keine Antwort
    env.clock.advance(901)
    assert client.get("/api/systems").json()[0]["pending_action"] is None
    assert client.get(f"/api/systems/{sid}/commands").json()[0]["status"] == "failed"
    assert client.post(f"/api/systems/{sid}/commands/prepare", headers=h, json={"type": "reboot"}).status_code == 200


def test_update_all_signs_once_for_new_agents_and_lists_old_ones(admin, monkeypatch):
    from app.models import AgentCommand, System

    env, client, h = admin
    ids = [activate(env, client, h, hostname=n, ip=f"192.168.178.{i}")[0] for i, n in enumerate(("a", "b", "c"), 10)]
    key = SoftAuthenticator()
    register(client, h, key)
    ctx = env.app.state.ctx
    monkeypatch.setattr(type(ctx), "settings_agent_version", lambda self: "0.14.0")
    with ctx.session_factory() as s:
        for sid, v in zip(ids, ("0.13.0", "0.13.2", "0.12.0")):
            s.get(System, sid).agent_version = v
        s.commit()
    p = client.post("/api/systems/commands/update-all/prepare", headers=h).json()
    assert p["batch_ids"] == ids[:2] and p["single_ids"] == [ids[2]]
    signed = json.loads(p["envelope"])
    assert (signed["system_id"], signed["system_ids"], signed["type"]) == (0, ids[:2], "update_agent")
    assert p["options"]["challenge"] == b64u(hashlib.sha256(p["envelope"].encode()).digest())
    url = "/api/systems/commands/update-all/confirm"
    assert client.post(url, headers=h, json={"credential": key.assertion(b64u(b"x" * 32))}).status_code == 400
    p = client.post("/api/systems/commands/update-all/prepare", headers=h).json()
    r = client.post(url, headers=h, json={"credential": key.assertion(p["options"]["challenge"])}).json()
    assert r == {"created": ["a", "b"], "skipped": []}
    with ctx.session_factory() as s:
        cmds = s.query(AgentCommand).filter(AgentCommand.type == "update_agent").all()
        assert sorted(c.system_id for c in cmds) == ids[:2]
        assert all(json.loads(c.params_json)["envelope"] == p["envelope"] for c in cmds)
    # laufende Updates: nur noch der alte Agent bleibt übrig, einzeln
    p = client.post("/api/systems/commands/update-all/prepare", headers=h).json()
    assert p == {"batch_ids": [], "single_ids": [ids[2]], "options": None}


def test_update_all_without_outdated_agents(admin):
    env, client, h = admin
    activate(env, client, h)
    register(client, h, SoftAuthenticator())
    with env.app.state.ctx.session_factory() as s:
        from app.models import System
        for x in s.query(System):
            x.agent_version = "99.0.0"
        s.commit()
    r = client.post("/api/systems/commands/update-all/prepare", headers=h)
    assert r.status_code == 409 and "newest" in r.json()["detail"]
    assert client.get("/api/systems/agent-update").json()["last_check"] is None
