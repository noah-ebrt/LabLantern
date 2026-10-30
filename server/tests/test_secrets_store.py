import os
import stat

import pytest
from sqlalchemy import text

from app.secrets_store import SecretStore, SecretTampered, load_or_create_master_key


def test_master_key_is_created_with_mode_0600_and_reused(tmp_path):
    path = tmp_path / "master.key"
    key = load_or_create_master_key(path)
    assert len(key) == 32
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_or_create_master_key(path) == key


def test_master_key_with_wrong_length_is_rejected(tmp_path):
    path = tmp_path / "master.key"
    path.write_bytes(b"short")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_or_create_master_key(path)


def test_secret_roundtrip(session_factory):
    store = SecretStore(session_factory, os.urandom(32))
    store.set("smtp.password", "hunter2-geheim")
    assert store.get("smtp.password") == "hunter2-geheim"


def test_secret_is_not_stored_in_plaintext(session_factory):
    store = SecretStore(session_factory, os.urandom(32))
    store.set("smtp.password", "hunter2-geheim")
    with session_factory() as s:
        rows = s.execute(text("SELECT wrapped_dek, ciphertext FROM secrets")).all()
    blob = b"".join(bytes(c) for r in rows for c in r)
    assert b"hunter2-geheim" not in blob


def test_meta_reports_set_state_without_value(session_factory):
    store = SecretStore(session_factory, os.urandom(32))
    assert store.meta("smtp.password") == {"set": False, "updated_at": None}
    store.set("smtp.password", "x")
    meta = store.meta("smtp.password")
    assert meta["set"] is True
    assert meta["updated_at"] is not None
    assert "x" not in repr(meta).replace("updated_at", "").replace("set", "")


def test_set_overwrites_and_get_missing_returns_none(session_factory):
    store = SecretStore(session_factory, os.urandom(32))
    assert store.get("nope") is None
    store.set("a", "1")
    store.set("a", "2")
    assert store.get("a") == "2"


def test_wrong_master_key_cannot_decrypt(session_factory):
    SecretStore(session_factory, os.urandom(32)).set("a", "1")
    with pytest.raises(SecretTampered):
        SecretStore(session_factory, os.urandom(32)).get("a")


def test_ciphertext_swapped_between_names_is_detected(session_factory):
    store = SecretStore(session_factory, os.urandom(32))
    store.set("a", "wert-a")
    store.set("b", "wert-b")
    with session_factory() as s:
        s.execute(text(
            "UPDATE secrets SET wrapped_dek = (SELECT wrapped_dek FROM secrets WHERE name='b'),"
            " ciphertext = (SELECT ciphertext FROM secrets WHERE name='b') WHERE name='a'"
        ))
        s.commit()
    with pytest.raises(SecretTampered):
        store.get("a")


def test_delete_removes_secret(session_factory):
    store = SecretStore(session_factory, os.urandom(32))
    store.set("a", "1")
    store.delete("a")
    assert store.meta("a")["set"] is False


def test_migration_moves_legacy_key_out_of_the_data_volume(tmp_path):
    from app.secrets_store import migrate_master_key
    legacy = tmp_path / "data" / "master.key"
    target = tmp_path / "keys" / "master.key"
    legacy.parent.mkdir()
    target.parent.mkdir()
    key = load_or_create_master_key(legacy)
    migrate_master_key(legacy, target)
    assert not legacy.exists()
    assert target.read_bytes() == key
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def test_migration_is_a_noop_when_target_exists_and_legacy_is_gone(tmp_path):
    from app.secrets_store import migrate_master_key
    target = tmp_path / "master.key"
    key = load_or_create_master_key(target)
    migrate_master_key(tmp_path / "gibtsnicht.key", target)
    assert target.read_bytes() == key


def test_migration_removes_identical_legacy_copy(tmp_path):
    from app.secrets_store import migrate_master_key
    legacy = tmp_path / "legacy.key"
    target = tmp_path / "target.key"
    key = load_or_create_master_key(legacy)
    target.write_bytes(key)
    target.chmod(0o600)
    migrate_master_key(legacy, target)
    assert not legacy.exists() and target.read_bytes() == key


def test_migration_refuses_when_two_different_keys_exist(tmp_path):
    from app.secrets_store import migrate_master_key
    legacy = tmp_path / "legacy.key"
    target = tmp_path / "target.key"
    load_or_create_master_key(legacy)
    load_or_create_master_key(target)
    with pytest.raises(ValueError, match="two different"):
        migrate_master_key(legacy, target)
    assert legacy.exists() and target.exists()
