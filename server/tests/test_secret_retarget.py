"""Gespeicherte Geheimnisse gehen nie ohne neue Eingabe an eine andere Gegenstelle; Image-SBOMs je Host begrenzt."""
from app import agent_api
from app.secrets_store import same_target

SMTP = {"host": "mail.example.org", "port": 587, "security": "starttls", "username": "u",
        "from_addr": "vw@example.org", "to_addr": "admin@example.org"}


def test_same_target_compares_scheme_host_and_port():
    assert same_target("http://npm.lan:81", "http://NPM.lan:81/")
    assert same_target("https://pve.lan", "https://pve.lan:443")
    assert not same_target("http://npm.lan:81", "http://evil.example:81")
    assert not same_target("https://pve.lan", "http://pve.lan")      # ohne TLS: mitlesbar
    assert not same_target("http://npm.lan:81", "http://npm.lan:82")
    assert not same_target(None, "http://npm.lan:81")
    assert not same_target("http://npm.lan:99999", "http://npm.lan:99999")


def test_npm_password_is_not_sent_to_a_new_address(admin):
    _env, client, h = admin
    body = {"url": "http://npm.lan:81", "email": "a@example.org"}
    assert client.put("/api/settings/npm", headers=h, json=body).json()["detail"] == "Password required"
    assert client.put("/api/settings/npm", headers=h, json={**body, "password": "pw"}).status_code == 200
    assert client.put("/api/settings/npm", headers=h, json=body).status_code == 200   # gleiche Adresse: bleibt
    r = client.put("/api/settings/npm", headers=h, json={**body, "url": "http://evil.example:81"})
    assert r.status_code == 422 and "enter the password again" in r.json()["detail"]
    assert client.get("/api/settings/npm").json()["config"]["url"] == "http://npm.lan:81"
    r = client.put("/api/settings/npm", headers=h, json={**body, "url": "http://npm2.lan:81", "password": "pw2"})
    assert r.status_code == 200


def test_smtp_password_is_not_sent_to_a_new_server(admin):
    _env, client, h = admin
    assert client.put("/api/integrations/smtp", headers=h, json={**SMTP, "password": "pw"}).status_code == 200
    assert client.put("/api/integrations/smtp", headers=h, json={**SMTP, "to_addr": "x@example.org"}).status_code == 200
    for change in ({"host": "evil.example"}, {"port": 25}, {"security": "none"}):
        r = client.put("/api/integrations/smtp", headers=h, json={**SMTP, **change})
        assert r.status_code == 422 and "enter the password again" in r.json()["detail"], change
    assert client.put("/api/integrations/smtp", headers=h,
                      json={**SMTP, "host": "mail2.example.org", "password": "pw2"}).status_code == 200


def test_image_sboms_per_host_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_api, "MAX_HOST_SBOM_BYTES", 100)
    d = tmp_path / "images" / "7"
    d.mkdir(parents=True)
    old, running = "a" * 64, "b" * 64
    (d / f"{old}.json").write_text("x" * 60)       # Image läuft nicht mehr
    (d / f"{running}.json").write_text("x" * 30)
    new = d / f"{'c' * 64}.json"
    ids = {f"sha256:{running}", f"sha256:{'c' * 64}"}
    assert agent_api.sbom_room(new, 10, ids)                     # 90 + 10 passt
    assert agent_api.sbom_room(new, 50, ids)                     # erst nach dem Aufräumen: 30 + 50
    assert not (d / f"{old}.json").exists() and (d / f"{running}.json").exists()
    assert not agent_api.sbom_room(new, 80, ids)                 # 30 + 80 passt auch dann nicht
