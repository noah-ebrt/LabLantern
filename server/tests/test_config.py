from app.config import Settings


def test_certificate_names_always_include_localhost_for_the_healthcheck(monkeypatch):
    monkeypatch.setenv("LABLANTERN_HOSTNAMES", "lablantern.lan,192.0.2.10")
    hostnames = Settings.from_env().hostnames
    assert hostnames[:2] == ["lablantern.lan", "192.0.2.10"]
    assert "localhost" in hostnames


def test_localhost_is_not_duplicated(monkeypatch):
    monkeypatch.setenv("LABLANTERN_HOSTNAMES", "localhost,lablantern.lan")
    assert Settings.from_env().hostnames == ["localhost", "lablantern.lan"]


def test_master_key_path_defaults_to_data_dir(tmp_path):
    assert Settings(data_dir=tmp_path).master_key_path == tmp_path / "master.key"


def test_master_key_file_can_live_outside_the_data_volume(monkeypatch, tmp_path):
    monkeypatch.setenv("LABLANTERN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("LABLANTERN_MASTER_KEY_FILE", str(tmp_path / "keys" / "master.key"))
    assert Settings.from_env().master_key_path == tmp_path / "keys" / "master.key"
