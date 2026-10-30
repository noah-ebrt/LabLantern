"""Abnahme Phase 1 (PLAN Abschnitt 13):
1. Einrichtung ohne Token unmöglich
2. gespeichertes SMTP-Passwort nirgends lesbar: UI/API, Datenbank im Klartext, Logs
"""
import logging

from sqlalchemy import text

from tests.conftest import SMTP_PASS
from tests.test_smtp import smtp_body

WRONG = "falsches-smtp-passwort-77"


def test_setup_is_impossible_without_the_token(env):
    attempts = [
        env.client.post("/api/setup/complete", json={
            "setup_token": t, "username": "angreifer",
            "password": "korrekt-pferd-batterie", "totp_code": "123456"})
        for t in ("", "x", "admin", "0" * 32)
    ]
    assert all(r.status_code in (403, 422, 429) for r in attempts)
    assert env.client.get("/api/state").json()["setup_complete"] is False


def _everything_readable(env, client, caplog):
    """Alles, was ein Angreifer oder Admin je zu sehen bekommt."""
    texts = []
    for path in ("/api/state", "/api/overview", "/api/integrations/smtp"):
        texts.append(client.get(path).text)
    ctx = env.app.state.ctx
    with ctx.session_factory() as s:
        s.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
        dump = "\n".join(s.connection().connection.iterdump())
    texts.append(dump)
    for f in env.data_dir.rglob("*"):
        if f.is_file() and f.name != "master.key":
            texts.append(f.read_bytes().decode("latin-1"))
    texts.append(caplog.text)
    return "\n".join(texts)


def test_stored_smtp_password_is_readable_nowhere(admin, smtp_server, caplog):
    env, client, h = admin
    with caplog.at_level(logging.DEBUG):
        assert client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port), headers=h).status_code == 200
        assert client.post("/api/integrations/smtp/test", headers=h).json() == {"ok": True}
        client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port, password=WRONG), headers=h)
        assert client.post("/api/integrations/smtp/test", headers=h).json()["ok"] is False
        client.put("/api/integrations/smtp", json=smtp_body(smtp_server.port, password=SMTP_PASS), headers=h)
        everything = _everything_readable(env, client, caplog)
    assert SMTP_PASS not in everything
    assert WRONG not in everything
    # Gegenprobe: die Suche würde ein Klartext-Passwort finden und das Geheimnis ist tatsächlich gesetzt
    assert env.app.state.ctx.secrets.get("smtp.password") == SMTP_PASS


def test_stored_notification_secret_is_readable_nowhere(admin, caplog):
    env, client, h = admin
    secrets_in_urls = {
        "ntfy": ("ntfy://SECRET_APPRISE_CREDENTIAL_98765@ntfy.sh/alerts", "SECRET_APPRISE_CREDENTIAL_98765"),
        # Telegram trägt das Geheimnis im Host-Teil, nicht im Benutzerinfo-Teil
        "Telegram": ("tgram://123456789:AAF-TELEGRAM-BOT-SECRET/987654", "AAF-TELEGRAM-BOT-SECRET"),
    }
    with caplog.at_level(logging.DEBUG):
        for name, (url, _) in secrets_in_urls.items():
            assert client.post("/api/integrations/notifications", json={"name": name, "url": url},
                               headers=h).status_code == 200
        everything = _everything_readable(env, client, caplog)
        everything += "\n" + client.get("/api/integrations/notifications").text

    stored = "\n".join(__import__("app.notify", fromlist=["x"]).load_notification_urls(env.app.state.ctx))
    for _, secret in secrets_in_urls.values():
        assert secret not in everything
        assert secret in stored                                     # tatsächlich gespeichert, nur nie lesbar
