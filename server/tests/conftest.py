import pytest
from sqlalchemy.orm import sessionmaker

from app.db import make_engine, init_db


@pytest.fixture
def session_factory(tmp_path):
    engine = make_engine(tmp_path / "vulnwatch.db")
    init_db(engine)
    return sessionmaker(engine, expire_on_commit=False)


import logging
import re

import pyotp
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


PASSWORD = "korrekt-pferd-batterie"


import http.server
import os
import threading

from app.pki import ensure_pki, fingerprint_sha256

@pytest.fixture(scope="session", autouse=True)
def ca_server(tmp_path_factory):
    """Stellt eine echte Test-CA über HTTP bereit, so wie Caddy intern /ca.crt ausliefert."""
    pki = ensure_pki(tmp_path_factory.mktemp("ca"), ["localhost"])
    pem = pki.ca_cert.read_bytes()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ok = self.path == "/ca.crt"
            self.send_response(200 if ok else 404)
            self.end_headers()
            self.wfile.write(pem if ok else b"")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # per Umgebungsvariable, weil einige Tests `tests.conftest` als zweites Modul importieren
    os.environ["VW_TEST_CA_URL"] = f"http://127.0.0.1:{srv.server_address[1]}/ca.crt"
    os.environ["VW_TEST_CA_FP"] = fingerprint_sha256(pki.ca_cert)
    os.environ["VW_TEST_CA_PEM"] = str(pki.ca_cert)
    yield
    srv.shutdown()
    srv.server_close()


class Env:
    """Eine frisch gestartete App samt Client, Uhr und dem Token aus dem Log."""

    def __init__(self, tmp_path, caplog, **settings_kw):
        self.data_dir = tmp_path / "data"
        self.clock = FakeClock()
        self.agent_dir = tmp_path / "agent-bin"
        self.agent_dir.mkdir(parents=True, exist_ok=True)
        for arch in ("amd64", "arm64"):
            (self.agent_dir / f"vulnwatch-agent-linux-{arch}").write_bytes(f"fake-agent-{arch}".encode())
            for pkg in ("deb", "rpm"):
                (self.agent_dir / f"vulnwatch-agent-linux-{arch}.{pkg}").write_bytes(f"fake-{arch}.{pkg}".encode())
        defaults = dict(data_dir=self.data_dir, hostnames=["vulnwatch.lan", "192.0.2.10", "localhost"],
                        ca_url=os.environ["VW_TEST_CA_URL"], agent_dir=self.agent_dir)
        with caplog.at_level(logging.INFO, logger="vulnwatch"):
            self.app = create_app(Settings(**{**defaults, **settings_kw}), clock=self.clock)
        self.log_text = caplog.text
        m = re.search(r"Setup token: (\S+)", self.log_text)
        self.setup_token = m.group(1) if m else None
        self.client = TestClient(self.app, base_url="https://testserver")

    def new_client(self) -> TestClient:
        return TestClient(self.app, base_url="https://testserver")

    def complete_setup(self, username="noah", password=PASSWORD) -> str:
        r = self.client.post("/api/setup/totp", json={"setup_token": self.setup_token})
        assert r.status_code == 200, r.text
        secret = r.json()["totp_secret"]
        code = pyotp.TOTP(secret).at(self.clock())
        r = self.client.post(
            "/api/setup/complete",
            json={"setup_token": self.setup_token, "username": username,
                  "password": password, "totp_code": code},
        )
        assert r.status_code == 200, r.text
        return secret

    def totp_code(self, secret: str, steps_ahead: int = 1) -> str:
        """Code für einen späteren Zeitschritt, damit der Setup-Code nicht als Replay zählt."""
        self.clock.advance(30 * steps_ahead)
        return pyotp.TOTP(secret).at(self.clock())

    def login(self, client, secret, username="noah", password=PASSWORD):
        r = client.post("/api/login", json={"username": username, "password": password,
                                            "totp_code": self.totp_code(secret)})
        return r


@pytest.fixture
def env(tmp_path, caplog):
    return Env(tmp_path, caplog)


import socket
from email import message_from_bytes

from aiosmtpd.controller import Controller

SMTP_USER = "mailer"
SMTP_PASS = "SMTP-GEHEIM-12345"


class _Inbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append((envelope.mail_from, envelope.rcpt_tos, message_from_bytes(envelope.content)))
        return "250 OK"


def _authenticator(server, session, envelope, mechanism, auth_data):
    from aiosmtpd.smtp import AuthResult
    ok = getattr(auth_data, "login", None) == SMTP_USER.encode() and \
        getattr(auth_data, "password", None) == SMTP_PASS.encode()
    return AuthResult(success=ok, handled=False)


@pytest.fixture
def smtp_server():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    inbox = _Inbox()
    controller = Controller(inbox, hostname="127.0.0.1", port=port, authenticator=_authenticator,
                            auth_required=True, auth_require_tls=False)
    controller.start()
    inbox.port = port
    yield inbox
    controller.stop()


@pytest.fixture
def admin(env):
    """Angemeldeter Admin: (env, client, csrf-Header)."""
    secret = env.complete_setup()
    csrf = env.login(env.client, secret).json()["csrf_token"]
    return env, env.client, {"X-CSRF-Token": csrf}


@pytest.fixture(autouse=True)
def no_extra_feeds(monkeypatch):
    """Die Frühwarnung holt in Tests weder den KEV-Katalog noch Release-Feeds, außer ein Test schaltet sie ein:
    die Feed-Attrappen der Tests antworten auf jede Adresse mit denselben Einträgen."""
    from app import earlywarning

    monkeypatch.setitem(earlywarning.SWITCH_DEFAULTS, "kev", False)
    monkeypatch.setitem(earlywarning.SWITCH_DEFAULTS, "release_feeds", False)


@pytest.fixture(autouse=True)
def no_public_dns(monkeypatch):
    """Tests fragen nie das öffentliche DNS: jeder Name gilt dann als "Prüfung fehlgeschlagen", also erreichbar."""
    def offline(name, rtype):
        raise OSError("public DNS disabled in tests")

    monkeypatch.setattr("app.publicdns.doh_query", offline)
