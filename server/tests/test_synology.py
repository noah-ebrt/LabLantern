"""Synology-DSM-Connector: nachgebautes DSM mit TLS, Anmeldung mit Konto und Passwort, Rechte eines Nicht-Admins."""
import http.server
import json
import ssl
import threading
from urllib.parse import parse_qs

import pytest
from sqlalchemy import select

from app.coverage import calculate_coverage_matrix
from app.earlywarning import appliance_products
from app.models import Finding
from tests.test_appliances import make_cert

PASSWORD = "correct horse battery staple"
UPDATE = {"update": {"available": True, "version": "DSM 7.2.2-72806 Update 4", "reboot": "now"}}
STORAGE = {"storagePools": [{"id": "reuse_1", "status": "degraded", "device_type": "shr_with_1_disk_protect",
                            "disks": ["sata1", "sata2"], "size": {"total": "2000", "used": "1000"}}],
           "volumes": [{"id": "volume_1", "vol_path": "/volume1", "status": "normal",
                        "size": {"total": "1000", "used": "960"}}],
           "disks": [{"id": "sata1", "longName": "Drive 1", "model": "WD40EFRX ", "status": "normal", "smart_status": "normal",
                      "temp": 31, "size_total": "4000787030016"},
                     {"id": "sata2", "longName": "Drive 2", "model": "WD40EFRX", "status": "crashed", "smart_status": "failing"}]}
PACKAGES = {"packages": [{"id": "ContainerManager", "name": "Container Manager", "version": "24.0.2-1535"},
                         {"id": "SynologyPhotos", "name": "Synology Photos", "version": "1.7.1-10015"}]}


class FakeDsm(http.server.BaseHTTPRequestHandler):
    admin = True
    seen: list[str] = []

    def do_POST(self):
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode()).items()}
        api, method = form.get("api"), form.get("method")
        FakeDsm.seen.append(f"{api}.{method}")
        if api == "SYNO.API.Auth" and method == "login":
            ok = form.get("account") == "vulnwatch" and form.get("passwd") == PASSWORD
            return self._send({"success": True, "data": {"sid": "s1"}} if ok else {"success": False, "error": {"code": 400}})
        if form.get("_sid") != "s1":
            return self._send({"success": False, "error": {"code": 119}})
        if api == "SYNO.API.Auth":
            return self._send({"success": True})
        if api == "SYNO.DSM.Info":
            return self._send({"success": True, "data": {"model": "DS920+", "version_string": "DSM 7.2.2-72806 Update 3"}})
        if not self.admin:
            return self._send({"success": False, "error": {"code": 105}})
        if api == "SYNO.Core.Upgrade.Server" and form["version"] == "2":
            return self._send({"success": False, "error": {"code": 104}})   # nur v1: Rückfall prüfen
        data = {"SYNO.Core.Upgrade.Server": UPDATE, "SYNO.Core.Package": PACKAGES, "SYNO.Storage.CGI.Storage": STORAGE}
        self._send({"success": True, "data": data[api]} if api in data else {"success": False, "error": {"code": 102}})

    def _send(self, body):
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


@pytest.fixture
def dsm(tmp_path):
    cert, key = make_cert(tmp_path, "dsm")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeDsm)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    FakeDsm.seen = []
    yield f"https://127.0.0.1:{srv.server_address[1]}"
    FakeDsm.admin = True
    srv.shutdown()
    srv.server_close()


def connect(admin, url, password=PASSWORD):
    _, client, h = admin
    return client.post("/api/settings/appliances", headers=h, json={"kind": "synology", "name": "nas", "url": url,
                                                                      "account": "vulnwatch", "token": password})


def findings(env, sid):
    with env.app.state.ctx.session_factory() as s:
        return {f.target: f for f in s.scalars(select(Finding).where(Finding.system_id == sid))}


def test_admin_reads_update_storage_and_packages(admin, dsm):
    env = admin[0]
    r = connect(admin, dsm)
    assert r.status_code == 200 and r.json()["ok"], r.text
    sid = r.json()["system_id"]
    f = findings(env, sid)
    up = f["host"]
    assert (up.cve_id, up.severity, up.installed_version, up.fixed_version, up.source) == \
        ("VW-UPDATE", "hoch", "7.2.2-72806 Update 3", "7.2.2-72806 Update 4", "synology")
    assert f["pool:reuse_1"].severity == "hoch"
    assert f["disk:/volume1"].cve_id == "VW-DISK" and f["disk:/volume1"].installed_version == "96 %"
    assert f["drive:Drive 2"].severity == "hoch" and "drive:Drive 1" not in f
    assert FakeDsm.seen[-1] == "SYNO.API.Auth.logout"
    with env.app.state.ctx.session_factory() as s:
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == sid)
        products = {p["product"]: p for p in appliance_products(s) if p["system_id"] == sid}
    assert row["checks"]["versionen"]["status"] == "fund"
    assert products["Synology DSM"]["version"] == "7.2.2-72806 Update 3"
    assert products["Container Manager"]["keyword"] == "container manager"
    _, client, h = admin
    st = next(x for x in client.get("/api/systems", headers=h).json() if x["id"] == sid)["connector"]["storage"]
    pool = next(p for p in st["pool_list"] if p["kind"] == "Storage pool")
    assert (pool["layout"], pool["disks"], pool["state"]) == ("SHR WITH 1 DISK PROTECT", ["Drive 1", "Drive 2"], "bad")
    drives = {d["name"]: d for d in st["disks"]}
    assert (drives["Drive 1"]["temp"], drives["Drive 1"]["pool"], drives["Drive 2"]["state"]) == (31, "reuse_1", "bad")


def test_non_admin_reads_version_only_and_is_na(admin, dsm):
    """Ohne Admin-Rechte bleibt die Update-Prüfung n/a mit Grund, nie ok."""
    env = admin[0]
    FakeDsm.admin = False
    r = connect(admin, dsm).json()
    assert r["ok"] and r["version"] == "7.2.2-72806 Update 3"
    assert findings(env, r["system_id"]) == {}
    with env.app.state.ctx.session_factory() as s:
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == r["system_id"])
    assert row["checks"]["versionen"]["status"] == "na" and "not an administrator" in row["checks"]["versionen"]["detail"]


def test_wrong_password_and_missing_account(admin, dsm):
    r = connect(admin, dsm, password="wrong password").json()
    assert r["ok"] is False and "rejected the account or password" in r["error"]
    _, client, h = admin
    r = client.post("/api/settings/appliances", headers=h,
                    json={"kind": "synology", "name": "nas2", "url": dsm, "token": PASSWORD})
    assert r.status_code == 422 and "Account required" in r.text


def test_http_refused(admin):
    r = connect(admin, "http://nas.lan:5000")
    assert r.status_code == 422 and "HTTPS" in r.text
