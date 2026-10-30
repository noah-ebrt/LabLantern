import hashlib
import os

from app.pairing import pairing_code
from tests.softauthn import SoftAuthenticator
from tests.test_agent_api import activate
from tests.test_passkeys import register

SECRET = "ab" * 32


NONCES: dict[int, str] = {}


def commit(env, hostname="newhost", secret=SECRET):
    """Schritt 1: nur das Commitment; der Master antwortet mit seiner Zufallszahl."""
    r = env.new_client().post("/api/agent/pair", json={"hostname": hostname, "agent_version": "0.12.0",
                                                       "commitment": hashlib.sha256(secret.encode()).hexdigest()})
    assert r.status_code == 200, r.text
    NONCES[r.json()["pairing_id"]] = r.json()["nonce"]
    return r.json()["pairing_id"]


def pair(env, hostname="newhost", secret=SECRET):
    pid = commit(env, hostname, secret)
    r = env.new_client().post(f"/api/agent/pair/{pid}/reveal", json={"secret": secret})
    assert r.status_code == 200, r.text
    return pid


def status(env, pid, secret=SECRET):
    return env.new_client().post(f"/api/agent/pair/{pid}/status", json={"secret": secret})


def test_code_matches_the_agent_algorithm():
    # Gegenstück: agent/internal/pairing (gleiche Eingabe, gleicher Code)
    assert pairing_code("AA:BB", "00" * 32, "11" * 16) == pairing_code("aabb", "00" * 32, "11" * 16)
    assert len(pairing_code("AABB", "00" * 32, "11" * 16)) == 7
    assert pairing_code("AA:BB", "ab" * 32, "cd" * 16) == "VQK-IC7"   # gleicher Wert im Go-Test


def test_pairing_without_passkey_then_token_exactly_once(admin):
    env, client, h = admin
    pid = pair(env)
    listed = client.get("/api/pairings").json()
    assert listed[0]["code"] == pairing_code(os.environ["VW_TEST_CA_FP"], SECRET, NONCES[pid])
    assert listed[0]["replaces_existing"] is False
    assert status(env, pid).json() == {"status": "pending"}
    assert status(env, pid, secret="cd" * 32).status_code == 404   # ohne Geheimnis nichts zu holen

    assert client.post(f"/api/pairings/{pid}/approve/options", headers=h).json() == {"passkey": False}
    assert client.post(f"/api/pairings/{pid}/approve", headers=h, json={}).status_code == 200
    got = status(env, pid).json()
    assert got["status"] == "approved" and got["agent_token"]
    assert status(env, pid).json() == {"status": "collected"}   # nur einmal
    bearer = {"Authorization": f"Bearer {got['agent_token']}"}
    assert env.new_client().post("/api/agent/commands/next", headers=bearer).status_code == 200
    assert client.get("/api/systems").json()[0]["status"] == "active"


def test_with_a_passkey_approval_needs_a_touch_and_repairing_keeps_the_system(admin):
    env, client, h = admin
    sid, old_bearer = activate(env, client, h, hostname="host-a")
    key = SoftAuthenticator()
    register(client, h, key)
    pid = pair(env, hostname="host-a")
    assert client.get("/api/pairings").json()[0]["replaces_existing"] is True
    assert client.post(f"/api/pairings/{pid}/approve", headers=h, json={}).status_code == 400
    o = client.post(f"/api/pairings/{pid}/approve/options", headers=h).json()
    r = client.post(f"/api/pairings/{pid}/approve", headers=h, json={"credential": key.assertion(o["options"]["challenge"])})
    assert r.status_code == 200 and r.json()["system_id"] == sid
    assert env.new_client().post("/api/agent/commands/next", headers=old_bearer).status_code == 401   # altes Token ungültig


def test_rejected_and_expired_pairings_yield_nothing(admin):
    env, client, h = admin
    pid = pair(env)
    assert client.post(f"/api/pairings/{pid}/reject", headers=h).status_code == 200
    assert status(env, pid).json() == {"status": "rejected"}
    pid2 = pair(env, secret="ef" * 32)
    env.clock.advance(16 * 60)
    assert status(env, pid2, secret="ef" * 32).json() == {"status": "expired"}
    assert client.get("/api/pairings").json() == []
    bad = env.new_client().post("/api/agent/pair", json={"hostname": "../x", "commitment": "ab" * 32})
    assert bad.status_code == 422


def test_the_old_one_step_protocol_is_refused(admin):
    # Ohne Commitment könnte ein Mann in der Mitte ein passendes Geheimnis für den Master suchen
    env, _, _ = admin
    r = env.new_client().post("/api/agent/pair", json={"hostname": "newhost", "secret": SECRET})
    assert r.status_code == 422


def test_no_code_before_the_reveal_and_the_reveal_must_match_the_commitment(admin):
    env, client, h = admin
    pid = commit(env)
    assert client.get("/api/pairings").json() == []                    # nichts zum Vergleichen, nichts freizugeben
    assert client.post(f"/api/pairings/{pid}/approve", headers=h, json={}).status_code == 404
    assert status(env, pid).json() == {"status": "committed"}
    wrong = env.new_client().post(f"/api/agent/pair/{pid}/reveal", json={"secret": "cd" * 32})
    assert wrong.status_code == 404
    assert env.new_client().post(f"/api/agent/pair/{pid}/reveal", json={"secret": SECRET}).status_code == 200
    assert env.new_client().post(f"/api/agent/pair/{pid}/reveal", json={"secret": SECRET}).status_code == 409
    assert len(client.get("/api/pairings").json()) == 1


def test_each_request_gets_a_fresh_nonce_so_the_code_cannot_be_precomputed(admin):
    env, _, _ = admin
    a, b = commit(env, secret="01" * 32), commit(env, secret="02" * 32)
    assert NONCES[a] != NONCES[b] and len(NONCES[a]) == 32


def test_one_address_cannot_fill_the_pairing_queue(admin):
    env, _, _ = admin
    commit(env, secret="01" * 32)
    commit(env, secret="02" * 32)
    r = env.new_client().post("/api/agent/pair", json={"hostname": "x", "commitment": "03" * 32})
    assert r.status_code == 429
