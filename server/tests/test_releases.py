import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.releases import ReleaseError, check_releases, current_release, sync_latest_release
from tests.conftest import Env

KEY = Ed25519PrivateKey.generate()


def pub_of(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def publish(root, version, key=KEY, tamper=False, signed_by=None):
    """Legt ein Release so ab, wie agent-sign es tut (ll-release publish)."""
    bins = {f"lablantern-agent-linux-{a}": f"{a}-{version}".encode() for a in ("amd64", "arm64")}
    manifest = json.dumps({"version": version, "created": "2026-10-29T00:00:00Z",
                           "files": {n: hashlib.sha256(b).hexdigest() for n, b in bins.items()}}, indent=2).encode()
    if tamper:
        bins["lablantern-agent-linux-amd64"] = b"evil"
    rel = root / version
    rel.mkdir(parents=True)
    for name, data in {**bins, "manifest.json": manifest,
                       "manifest.json.sig": base64.b64encode((signed_by or key).sign(manifest))}.items():
        (rel / name).write_bytes(data)
    (root / "release.pub").write_text(pub_of(key) + "\n")
    (root / "latest.json").write_text(json.dumps({"version": version, "source": "x", "public_key": pub_of(key),
                                                  "built": "2026-10-29T00:00:00Z"}))


@pytest.fixture
def renv(tmp_path, caplog):
    root = tmp_path / "agent-releases"
    root.mkdir()
    env = Env(tmp_path / "master", caplog, agent_releases_dir=root)
    return env, env.app.state.ctx, root


def test_newest_signed_release_is_verified_and_served(renv):
    env, ctx, root = renv
    publish(root, "0.16.0")
    assert sync_latest_release(ctx) == "0.16.0"
    assert ctx.settings_agent_version() == "0.16.0"
    r = env.new_client().get("/api/agent/download/amd64")
    assert r.status_code == 200 and r.content == b"amd64-0.16.0"


def test_release_with_bad_signature_is_refused_and_nothing_changes(renv):
    env, ctx, root = renv
    publish(root, "0.16.0", signed_by=Ed25519PrivateKey.generate())
    with pytest.raises(ReleaseError, match="signature"):
        sync_latest_release(ctx)
    assert ctx.settings_agent_version() != "0.16.0"


def test_binary_that_does_not_match_the_signed_checksum_is_refused(renv):
    env, ctx, root = renv
    publish(root, "0.16.0", tamper=True)
    with pytest.raises(ReleaseError, match="checksum"):
        sync_latest_release(ctx)
    assert env.new_client().get("/api/agent/download/amd64").content != b"evil"


def test_older_release_never_replaces_a_newer_one(renv):
    env, ctx, root = renv
    publish(root, "0.16.1")
    sync_latest_release(ctx)
    publish(root, "0.16.0")
    assert sync_latest_release(ctx) == "0.16.1"


def test_a_new_signing_key_replaces_the_served_release(renv):
    """Neu aufgesetztes Schlüssel-Volume: Agenten mit dem neuen Schlüssel brauchen das neue Release."""
    env, ctx, root = renv
    publish(root, "0.16.1")
    sync_latest_release(ctx)
    other = Ed25519PrivateKey.generate()
    publish(root, "0.16.0", key=other)
    assert sync_latest_release(ctx) == "0.16.0"
    assert current_release(ctx)["public_key"] == pub_of(other)


def test_without_a_build_the_status_says_how_to_build(renv):
    env, ctx, root = renv
    status = check_releases(ctx)
    assert status["ok"] is False and "no agent built" in status["error"] and "docker compose up" in status["hint"]


def test_release_settings_api_shows_version_and_key(renv):
    env, ctx, root = renv
    publish(root, "0.16.0")
    secret = env.complete_setup()
    h = {"X-CSRF-Token": env.login(env.client, secret).json()["csrf_token"]}
    r = env.client.post("/api/settings/releases/sync", headers=h).json()
    assert (r["ok"], r["version"], r["error"], r["hint"]) == (True, "0.16.0", None, None)
    got = env.client.get("/api/settings/releases").json()
    assert got["current_version"] == "0.16.0" and got["public_key"] == pub_of(KEY) and got["built"]
    assert env.client.put("/api/settings/releases", json={}, headers=h).status_code == 405


def test_signed_manifest_is_served_for_agent_self_update(renv):
    env, ctx, root = renv
    publish(root, "0.16.0")
    sync_latest_release(ctx)
    c = env.new_client()
    assert b'"version"' in c.get("/api/agent/release/manifest.json").content
    assert c.get("/api/agent/release/manifest.json.sig").status_code == 200
    assert c.get("/api/agent/release/..%2Fmaster.key").status_code == 404
