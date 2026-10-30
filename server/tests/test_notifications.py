import json

import pytest
from sqlalchemy import select, text

from app.models import AuditLog
from app.notify import NOTIFY_SECRET_KEY, load_notification_urls

# Echte URL-Formen, bei denen das Geheimnis NICHT im Benutzerinfo-Teil steht (Telegram, Slack, Discord …)
SECRET_URLS = {
    "Telegram": "tgram://123456789:AAF-GEHEIMER-BOT-TOKEN/987654",  # gitleaks:allow (Test-Fake)
    "Slack": "slack://T1JJ3T3L2/A1BRTD4JD/TIiajkdnlazkcOXrIdevi7FQ",  # gitleaks:allow (Beispiel aus der Apprise-Doku)
    "Discord": "discord://1234567890/GEHEIMER-WEBHOOK-TOKEN",
    "Mail": "mailto://user:GEHEIMES_PASSWORT_123@smtp.example.org:587?to=noah@example.org",
    "ntfy": "ntfy://user:NTFYPASS@ntfy.example.org/topic",
}
SECRET_PARTS = ["AAF-GEHEIMER-BOT-TOKEN", "TIiajkdnlazkcOXrIdevi7FQ", "GEHEIMER-WEBHOOK-TOKEN", "GEHEIMES_PASSWORT_123", "NTFYPASS"]  # gitleaks:allow (Test-Fakes)


def add(client, h, name, url):
    return client.post("/api/integrations/notifications", json={"name": name, "url": url}, headers=h)


def test_endpoints_require_login_and_admin(admin):
    env, client, h = admin
    anon = env.new_client()
    assert anon.get("/api/integrations/notifications").status_code == 401
    assert anon.post("/api/integrations/notifications", json={}).status_code == 401
    assert anon.delete("/api/integrations/notifications/0").status_code == 401
    assert anon.post("/api/integrations/notifications/test").status_code == 401
    assert add(client, {}, "x", "json://localhost:9/").status_code == 403           # ohne CSRF
    assert client.delete("/api/integrations/notifications/0").status_code == 403


def test_unconfigured_notifications_reports_empty(admin):
    env, client, _ = admin
    assert client.get("/api/integrations/notifications").json() == {"configured": False, "channels": []}


def test_no_part_of_any_channel_url_is_ever_shown(admin):
    env, client, h = admin
    for name, url in SECRET_URLS.items():
        assert add(client, h, name, url).status_code == 200, name
    body = client.get("/api/integrations/notifications")
    assert [c["name"] for c in body.json()["channels"]] == list(SECRET_URLS)
    assert [c["scheme"] for c in body.json()["channels"]] == ["tgram", "slack", "discord", "mailto", "ntfy"]
    for part in SECRET_PARTS + ["smtp.example.org", "ntfy.example.org", "987654", "noah@example.org"]:
        assert part not in body.text, part
    assert all(set(c) == {"index", "name", "scheme", "gets"} for c in body.json()["channels"])


def test_urls_are_stored_encrypted_and_not_in_the_audit_log(admin):
    env, client, h = admin
    for name, url in SECRET_URLS.items():
        add(client, h, name, url)
    ctx = env.app.state.ctx
    with ctx.session_factory() as s:
        s.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
        dump = "\n".join(s.connection().connection.iterdump()) + repr([(a.action, a.detail) for a in s.scalars(select(AuditLog))])
    blob = dump + "".join(f.read_bytes().decode("latin-1") for f in env.data_dir.rglob("*") if f.is_file() and f.name != "master.key")
    for part in SECRET_PARTS:
        assert part not in blob, part
    assert "GEHEIMES_PASSWORT_123" in ctx.secrets.get(NOTIFY_SECRET_KEY)        # mit dem Master key lesbar
    assert load_notification_urls(ctx) == list(SECRET_URLS.values())


def test_invalid_urls_and_names_are_rejected(admin):
    env, client, h = admin
    assert add(client, h, "Kaputt", "das-ist-keine-url").status_code == 422
    assert add(client, h, "Unbekannt", "nixschema://x").status_code == 422
    assert add(client, h, "", "json://localhost:9/").status_code == 422
    assert add(client, h, "x" * 61, "json://localhost:9/").status_code == 422
    assert add(client, h, "Zeilen\numbruch", "json://localhost:9/").status_code == 422
    assert client.get("/api/integrations/notifications").json()["channels"] == []


def test_error_message_for_a_bad_url_does_not_echo_it(admin):
    env, client, h = admin
    r = add(client, h, "Kaputt", "tgram://GEHEIMER-TEIL-DER-FALSCHEN-URL")
    assert r.status_code == 422 and "GEHEIMER-TEIL" not in r.text


def test_duplicate_url_is_refused(admin):
    env, client, h = admin
    add(client, h, "Eins", "json://localhost:9/hook")
    assert add(client, h, "Zwei", "json://localhost:9/hook").status_code == 409


def test_remove_channel_by_index(admin):
    env, client, h = admin
    add(client, h, "Eins", "json://localhost:9/a")
    add(client, h, "Zwei", "json://localhost:9/b")
    assert client.delete("/api/integrations/notifications/0", headers=h).status_code == 200
    assert [c["name"] for c in client.get("/api/integrations/notifications").json()["channels"]] == ["Zwei"]
    assert client.get("/api/integrations/notifications").json()["channels"][0]["index"] == 0
    assert client.delete("/api/integrations/notifications/5", headers=h).status_code == 404
    client.delete("/api/integrations/notifications/0", headers=h)
    assert client.get("/api/integrations/notifications").json() == {"configured": False, "channels": []}


def test_changes_are_audited_with_name_and_scheme_only(admin):
    env, client, h = admin
    add(client, h, "Handy", SECRET_URLS["Telegram"])
    client.delete("/api/integrations/notifications/0", headers=h)
    with env.app.state.ctx.session_factory() as s:
        rows = [(a.action, a.detail) for a in s.scalars(select(AuditLog)) if a.action.startswith("integration.notifications")]
    assert ("integration.notifications.added", "Handy (tgram)") in rows
    assert any(a == "integration.notifications.removed" and "Handy" in d for a, d in rows)
    assert "123456789" not in repr(rows)


def test_legacy_stored_format_without_names_still_works(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.secrets.set(NOTIFY_SECRET_KEY, json.dumps(["json://localhost:9/alt", "ntfy://topic"]))
    body = client.get("/api/integrations/notifications").json()
    assert [(c["name"], c["scheme"]) for c in body["channels"]] == [("Channel 1", "json"), ("Channel 2", "ntfy")]
    assert load_notification_urls(ctx) == ["json://localhost:9/alt", "ntfy://topic"]


def test_test_endpoint_sends_to_every_channel_and_names_the_failing_ones(admin, monkeypatch):
    env, client, h = admin
    add(client, h, "Gut", "json://localhost:9/gut")
    add(client, h, "Schlecht", "json://localhost:9/schlecht")
    import app.notify as notify_mod
    calls = []

    def fake_send(urls, title, body):
        calls.append(urls)
        return ("schlecht" not in urls[0], None if "schlecht" not in urls[0] else "kaputt")

    monkeypatch.setattr(notify_mod, "send_notification", fake_send)
    r = client.post("/api/integrations/notifications/test", headers=h)
    assert r.status_code == 200 and len(calls) == 2
    body = r.json()
    assert body["ok"] is False and "Schlecht" in body["error"] and "Gut" not in body["error"]
    assert "schlecht" not in r.text


def test_test_endpoint_ok_when_all_channels_work(admin, monkeypatch):
    env, client, h = admin
    add(client, h, "Gut", "json://localhost:9/gut")
    import app.notify as notify_mod
    monkeypatch.setattr(notify_mod, "send_notification", lambda u, t, b: (True, None))
    assert client.post("/api/integrations/notifications/test", headers=h).json() == {"ok": True, "error": None}


def test_test_without_channels_is_409(admin):
    env, client, h = admin
    assert client.post("/api/integrations/notifications/test", headers=h).status_code == 409


def smtp_channel(_port, **over):
    body = {"name": "Mail", "host": "127.0.0.1", "port": _port, "security": "none", "username": "mailer",
            "password": "SMTP-GEHEIM-12345", "from_addr": "vw@example.org", "to_addr": "noah@example.org"}
    body.update(over)
    return body


def test_smtp_form_creates_the_first_channel_and_delivers_a_real_mail(admin, smtp_server):
    env, client, h = admin
    client.post("/api/integrations/notifications", json={"name": "Handy", "url": "json://localhost:9/x"}, headers=h)
    r = client.post("/api/integrations/notifications/smtp", json=smtp_channel(smtp_server.port), headers=h)
    assert r.status_code == 200 and "SMTP-GEHEIM" not in r.text
    chans = client.get("/api/integrations/notifications").json()["channels"]
    assert [(c["name"], c["scheme"]) for c in chans][0] == ("Mail", "mailto")      # Mail ist der erste Kanal
    from app.notify import load_notification_urls, send_notification
    ok, err = send_notification([load_notification_urls(env.app.state.ctx)[0]], "Betreff", "Text")
    assert ok, err
    sender, rcpts, msg = smtp_server.messages[0]
    assert rcpts == ["noah@example.org"] and "SMTP-GEHEIM" not in msg.as_string()


def test_mail_gets_the_html_template_and_plain_text_keeps_its_line_breaks(admin, smtp_server):
    env, client, h = admin
    client.post("/api/integrations/notifications/smtp", json=smtp_channel(smtp_server.port), headers=h)
    from app.notify import load_notification_urls, send_notification
    url = load_notification_urls(env.app.state.ctx)[0]
    ok, err = send_notification([url], "Betreff", "Zeile 1\nZeile 2", "<p>Vorlage</p>")
    assert ok, err
    parts = {p.get_content_type(): p.get_payload(decode=True).decode() for p in smtp_server.messages[0][2].walk() if not p.is_multipart()}
    assert "<p>Vorlage</p>" in parts["text/html"]
    ok, err = send_notification([url], "Test", "Zeile 1\nZeile 2")   # ohne Vorlage: Klartext mit Umbruch
    assert ok, err
    msg = smtp_server.messages[1][2]
    body = "".join(p.get_payload(decode=True).decode() for p in msg.walk() if not p.is_multipart())
    assert "Zeile 1" in body and "Zeile 1 Zeile 2" not in body


def test_mail_template_escapes_feed_content_and_links_only_http():
    from app.mailtpl import early_warning_html
    item = {"title": "<script>x</script>", "link": "javascript:alert(1)", "status": "unklar", "exploited": False,
            "severity": "hoch", "detail": "a on b: <b>c</b>", "actions": [], "mitigations": []}
    html = early_warning_html("[EARLY WARNING] x", [item], ["b"], 0)
    assert "<script>" not in html and "&lt;script&gt;" in html and "javascript:" not in html


def test_smtp_password_with_special_characters_survives(admin, smtp_server):
    from tests.conftest import SMTP_USER
    env, client, h = admin
    import tests.conftest as c
    r = client.post("/api/integrations/notifications/smtp",
                    json=smtp_channel(smtp_server.port, username="mailer"), headers=h)
    assert r.status_code == 200
    url = __import__("app.notify", fromlist=["x"]).load_notification_urls(env.app.state.ctx)[0]
    assert "SMTP-GEHEIM-12345" in url
    r = client.post("/api/integrations/notifications/smtp",
                    json=smtp_channel(smtp_server.port, name="Mail2", password="p@ss/w#rd?&=x"), headers=h)
    assert r.status_code == 200
    from urllib.parse import unquote
    url2 = __import__("app.notify", fromlist=["x"]).load_notification_urls(env.app.state.ctx)[0]
    assert "p%40ss%2Fw%23rd%3F%26%3Dx" in url2 and unquote("p%40ss%2Fw%23rd%3F%26%3Dx") == "p@ss/w#rd?&=x"


def test_smtp_form_validates_input(admin):
    env, client, h = admin
    for bad in ({"port": 0}, {"security": "magic"}, {"host": "a b"}, {"to_addr": "kein-mail"}, {"from_addr": "x@y.de\r\nBcc: z@q.de"}):
        r = client.post("/api/integrations/notifications/smtp", json=smtp_channel(587, **bad), headers=h)
        assert r.status_code == 422, bad
