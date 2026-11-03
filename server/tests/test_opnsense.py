"""OPNsense als Gerät (Firmware): nachgebaute API mit TLS und Basic-Auth, Stand der letzten Update-Prüfung."""
import base64
import copy
import http.server
import json
import ssl
import threading

import pytest
from sqlalchemy import select

from app import appliances
from app.coverage import calculate_coverage_matrix
from app.eol import EolDb
from app.earlywarning import appliance_products
from app.models import Finding
from tests.test_appliances import make_cert

KEY, SECRET = "k" * 20, "s" * 40
STATUS = {"status": "update", "status_msg": "There are 3 updates available", "last_check": "Fri Oct 31 06:00:01 CET 2026",
          "product_version": "25.7.5", "product_abi": "25.7", "upgrade_major_version": "26.1", "upgrade_needs_reboot": "1",
          "upgrade_packages": [{"name": "opnsense", "current_version": "25.7.5", "new_version": "25.7.6"},
                               {"name": "curl", "current_version": "8.15.0", "new_version": "8.16.0"}]}
INFO = {"product": {"product_id": "opnsense", "product_version": "25.7.5", "product_series": "25.7"},
        "package": [{"name": "curl"}, {"name": "opnsense"}],
        "plugin": [{"name": "os-wireguard", "version": "2.6", "installed": "1"},
                   {"name": "os-haproxy", "version": "4.6", "installed": "0"}]}


class FakeOpn(http.server.BaseHTTPRequestHandler):
    status = STATUS

    def do_GET(self):
        auth = "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
        if self.headers.get("Authorization") != auth:
            return self._send(401, {"status": 401})
        routes = {"/api/core/firmware/status": self.status, "/api/core/firmware/info": INFO}
        self._send(200, routes[self.path]) if self.path in routes else self._send(404, {})

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


@pytest.fixture
def opn(tmp_path, monkeypatch):
    eol = EolDb([{"name": "opnsense", "label": "OPNsense", "releases": [
        {"name": "26.1", "isEol": False, "latest": {"name": "26.1.4"}},
        {"name": "25.7", "isEol": True, "eolFrom": "2026-07-31"}]}])
    monkeypatch.setattr(appliances.eol_mod, "load", lambda *a, **k: (eol, ""))
    cert, key = make_cert(tmp_path, "opn")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeOpn)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}"
    FakeOpn.status = STATUS
    srv.shutdown()
    srv.server_close()


def connect(admin, url, secret=SECRET):
    _, client, h = admin
    return client.post("/api/settings/appliances", headers=h, json={"kind": "opnsense", "name": "fw", "url": url,
                                                                      "account": KEY, "token": secret})


def state(env, sid):
    with env.app.state.ctx.session_factory() as s:
        found = {f.target: f for f in s.scalars(select(Finding).where(Finding.system_id == sid))}
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == sid)
        products = [p for p in appliance_products(s) if p["system_id"] == sid]
    return found, row["checks"]["versionen"], products


def test_core_update_major_and_plugins(admin, opn):
    env = admin[0]
    r = connect(admin, opn)
    assert r.status_code == 200 and r.json()["ok"], r.text
    found, versions, products = state(env, r.json()["system_id"])
    core = found["host"]
    assert (core.severity, core.installed_version, core.fixed_version, core.source) == ("hoch", "25.7.5", "25.7.6", "opnsense")
    assert "packages" not in found   # curl kommt mit dem Core-Update
    assert (found["eol"].cve_id, found["eol"].fixed_version) == ("LL-EOL", "26.1.4")
    assert found["major"].severity == "mittel" and found["major"].fixed_version == "26.1"
    assert versions["status"] == "fund" and "last check" in versions["detail"]
    assert {p["keyword"] for p in products} == {"opnsense", "wireguard"}   # nicht installiertes Plugin fehlt


def test_only_package_updates_is_one_finding(admin, opn):
    env = admin[0]
    FakeOpn.status = {**copy.deepcopy(STATUS), "upgrade_major_version": "",
                      "upgrade_packages": [{"name": "curl", "current_version": "8.15.0", "new_version": "8.16.0"}]}
    found, _, _ = state(env, connect(admin, opn).json()["system_id"])
    assert set(found) - {"eol"} == {"packages"} and found["packages"].severity == "mittel" and "curl" in found["packages"].title


def test_never_checked_is_na(admin, opn):
    """Die Firewall hat noch nicht nach Updates gesucht: LabLantern stößt keine Prüfung an, die Prüfung ist n/a."""
    env = admin[0]
    FakeOpn.status = {"status": "none", "status_msg": "Firmware status requires to check for update first"}
    r = connect(admin, opn).json()
    assert r["ok"] and r["version"] == "25.7.5"
    found, versions, _ = state(env, r["system_id"])
    assert set(found) - {"eol"} == set() and versions["status"] == "na" and "Check for updates" in versions["detail"]


def test_wrong_secret(admin, opn):
    r = connect(admin, opn, secret="x" * 40).json()
    assert r["ok"] is False and "rejected the API key" in r["error"]
