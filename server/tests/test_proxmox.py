"""Proxmox-VE-Connector (PLAN-extensions D1): nachgebauter PVE-Server mit TLS, Gäste den Agenten-Hosts zuordnen."""
import http.server
import json
import ssl
import threading
from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app import appliances
from app.coverage import calculate_coverage_matrix
from app.models import Finding, System, put_setting, setting
from app.proxmox import match_guests
from tests.test_appliances import make_cert

FIX = Path(__file__).parent / "fixtures"
UNTIL = (date.today() + timedelta(days=30)).isoformat()
TOKEN = "lablantern@pve!vw=0b7a3e1c-1111-2222-3333-444455556666"


def fixture(name):
    return json.loads((FIX / name).read_text())


class FakePve(http.server.BaseHTTPRequestHandler):
    apt_status = 200
    routes = {
        "/api2/json/version": fixture("pve-version.json"),
        "/api2/json/nodes": {"data": [{"node": "pve1", "status": "online"}]},
        "/api2/json/nodes/pve1/version": fixture("pve-version.json"),
        "/api2/json/nodes/pve1/apt/update": fixture("pve-apt-update.json"),
        "/api2/json/cluster/resources?type=vm": fixture("pve-resources.json"),
        "/api2/json/nodes/pve1/lxc/101/config": {"data": {"hostname": "db",
                                                          "net0": "name=eth0,bridge=vmbr0,ip=192.0.2.21/24,gw=192.0.2.1"}},
        "/api2/json/nodes/pve1/lxc/103/config": {"data": {"hostname": "old-test", "net0": "name=eth0,ip=dhcp"}},
        "/api2/json/nodes/pve1/qemu/102/agent/network-get-interfaces": {"data": {"result": [
            {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
            {"name": "eth0", "ip-addresses": [{"ip-address": "192.0.2.20", "ip-address-type": "ipv4"},
                                              {"ip-address": "fe80::1", "ip-address-type": "ipv6"}]}]}},
    }

    def do_GET(self):
        if self.headers.get("Authorization") != f"PVEAPIToken={TOKEN}":
            return self._send(401, {"data": None})
        if self.path.endswith("/apt/update") and self.apt_status != 200:
            return self._send(self.apt_status, {"data": None})
        if self.path not in self.routes:   # z. B. QEMU-Agent nicht installiert
            return self._send(500, {"data": None, "message": "QEMU guest agent is not running"})
        self._send(200, self.routes[self.path])

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


@pytest.fixture
def pve(tmp_path):
    cert, key = make_cert(tmp_path, "pve")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakePve)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def add_host(ctx, name, ip=""):
    with ctx.session_factory() as s:
        s.add(System(name=name, ip=ip, status="active"))
        s.commit()


def connect(admin, pve):
    env, client, h = admin
    r = client.post("/api/settings/appliances", headers=h,
                    json={"kind": "proxmox", "name": "proxmox", "url": pve, "token": f"PVEAPIToken={TOKEN}"})
    assert r.status_code == 200 and r.json()["ok"], r.text
    return r.json()["system_id"]


def guests_rows(env):
    with env.app.state.ctx.session_factory() as s:
        m = calculate_coverage_matrix(s)
    return {g["name"]: g for g in m["guests"]}, m


GUESTS = [{"subject": "pve-guest:pve1/100", "name": "web01", "ips": [], "template": False},
          {"subject": "pve-guest:pve1/102", "name": "vm-102", "ips": ["192.0.2.20"], "template": False},
          {"subject": "pve-guest:pve1/9000", "name": "tpl-debian", "ips": [], "template": True}]


def test_guest_matched_by_name():
    systems = [System(id=1, name="WEB01.lan", ip="192.0.2.99", status="active")]
    matched, unmatched = match_guests(GUESTS[:1], systems)
    assert matched == {"pve-guest:pve1/100": 1} and unmatched == []


def test_guest_matched_by_ip():
    systems = [System(id=1, name="web01", status="active"), System(id=2, name="other", ip="192.0.2.20", status="active")]
    matched, unmatched = match_guests(GUESTS[:2], systems)
    assert matched == {"pve-guest:pve1/100": 1, "pve-guest:pve1/102": 2} and unmatched == []


def test_template_skipped():
    matched, unmatched = match_guests(GUESTS, [])
    assert [g["name"] for g in unmatched] == ["web01", "vm-102"]   # die Vorlage ist weder zugeordnet noch Lücke


def test_unmatched_guest_is_gap(admin, pve):
    env, _, _ = admin
    ctx = env.app.state.ctx
    add_host(ctx, "web01")
    add_host(ctx, "builder", ip="192.0.2.20")   # vm-102 über die IP vom QEMU-Agenten
    connect(admin, pve)
    rows, m = guests_rows(env)
    assert set(rows) == {"web01", "vm-102", "db", "old-test"}   # Vorlage tpl-debian fehlt
    assert (rows["web01"]["status"], rows["web01"]["system_name"]) == ("ok", "web01")
    assert (rows["vm-102"]["status"], rows["vm-102"]["system_name"]) == ("ok", "builder")
    assert rows["db"]["status"] == "fehler" and "no agent" in rows["db"]["detail"]
    assert "192.0.2.21" in rows["db"]["detail"]   # IP aus der LXC-Konfiguration hilft beim Einrichten
    ok_before = m["ok_checks"]
    assert m["total_checks"] - ok_before >= 2   # db und old-test sind Lücken


def test_stopped_guest_excluded_with_reason(admin, pve):
    env, client, h = admin
    connect(admin, pve)
    rows, m = guests_rows(env)
    assert rows["old-test"]["status"] == "fehler" and "stopped, not checked" in rows["old-test"]["detail"]
    total = m["total_checks"]
    r = client.post("/api/coverage/exclusions", headers=h,
                    json={"subject": "pve-guest:pve1/103", "reason": "test container, kept for reference", "until": UNTIL})
    assert r.status_code == 200, r.text
    rows, m = guests_rows(env)
    assert rows["old-test"]["status"] == "excluded" and "kept for reference" in rows["old-test"]["detail"]
    assert m["total_checks"] == total - 1
    bad = client.post("/api/coverage/exclusions", headers=h,
                      json={"subject": "pve-guest:pve1/999", "reason": "unknown guest", "until": UNTIL})
    assert bad.status_code == 422


def test_pve_update_rating(admin, pve):
    env, _, _ = admin
    ctx = env.app.state.ctx
    sid = connect(admin, pve)
    with ctx.session_factory() as s:
        f = s.scalar(select(Finding).where(Finding.system_id == sid, Finding.cve_id == "LL-UPDATE"))
        assert (f.severity, f.installed_version, f.fixed_version, f.source) == ("hoch", "8.2.4", "8.2.7", "proxmox")
        assert "pve1" in f.title
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == sid)
    assert row["checks"]["versionen"]["status"] == "fund"
    assert row["checks"]["paket_cve"]["status"] == "na"


def test_apt_update_forbidden_is_na_not_ok(admin, pve):
    """Ältere PVE verlangen für /apt/update Sys.Modify. LabLantern bleibt lesend: die Prüfung ist n/a mit Grund."""
    env, _, _ = admin
    FakePve.apt_status = 403
    try:
        sid = connect(admin, pve)
    finally:
        FakePve.apt_status = 200
    with env.app.state.ctx.session_factory() as s:
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == sid)
    versions = row["checks"]["versionen"]
    assert versions["status"] == "na" and "Sys.Modify" in versions["detail"]


def test_pinning_mismatch_error(admin, pve):
    env, client, h = admin
    ctx = env.app.state.ctx
    sid = connect(admin, pve)
    with ctx.session_factory() as s:
        cfg = setting(s, appliances.CONFIG_KEY)
        cfg[str(sid)]["fingerprint"] = "AA" * 32
        put_setting(s, appliances.CONFIG_KEY, cfg)
        s.commit()
    r = client.post(f"/api/settings/appliances/{sid}/test", headers=h).json()
    assert r["ok"] is False and "certificate" in r["error"]
    rows, _ = guests_rows(env)
    assert rows["db"]["status"] == "fehler"   # letzte bekannte Gäste bleiben sichtbar
