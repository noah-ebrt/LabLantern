"""Portfreigaben aus OPNsense und UniFi (PLAN-extensions D2): nachgebaute Router mit TLS, Zuordnung wie FRITZ!Box."""
import base64
import http.server
import json
import ssl
import threading
from pathlib import Path

import pytest

from app import exposure
from app.containers import HOST
from app.coverage import calculate_coverage_matrix
from app.models import setting
from app.routerforwards import ROUTERS, parse_opnsense, parse_unifi
from tests.test_appliances import make_cert
from tests.test_fritzbox import two_hosts
from tests.test_scan_flow import ctx  # noqa: F401 (Fixture)

FIX = Path(__file__).parent / "fixtures"
OPN_KEY, OPN_SECRET, UNIFI_KEY = "opn-key-1234", "opn-secret-5678", "unifi-api-key-abcdef"


def fixture(name):
    return json.loads((FIX / name).read_text())


class FakeRouter(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        basic = "Basic " + base64.b64encode(f"{OPN_KEY}:{OPN_SECRET}".encode()).decode()
        if self.path.startswith("/api/firewall/d_nat/search_rule"):
            ok, body = self.headers.get("Authorization") == basic, fixture("opnsense-d_nat.json")
        elif self.path == "/proxy/network/api/s/default/rest/portforward":
            ok, body = self.headers.get("X-API-KEY") == UNIFI_KEY, fixture("unifi-portforward.json")
        else:
            ok, body = True, None
        status = 404 if body is None else 200 if ok else 401
        raw = json.dumps(body or {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


@pytest.fixture
def router(tmp_path):
    cert, key = make_cert(tmp_path, "router")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeRouter)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def by_port(forwards):
    return {f["external_port"]: f for f in forwards}


def test_opnsense_rows_normalized():
    fw = by_port(parse_opnsense(fixture("opnsense-d_nat.json")["rows"]))
    assert fw[443] == {"external_port": 443, "internal_client": "10.0.0.5", "internal_port": 443, "protocol": "TCP",
                       "enabled": True, "description": "npm https"}
    assert fw[25565]["internal_port"] == 25565   # ohne local-port: gleicher Port wie außen
    assert fw[8080]["enabled"] is False


def test_unifi_rows_normalized():
    fw = by_port(parse_unifi(fixture("unifi-portforward.json")["data"]))
    assert (fw[2222]["internal_client"], fw[2222]["internal_port"], fw[2222]["protocol"]) == ("10.0.0.6", 22, "TCP/UDP")
    assert fw[8080]["enabled"] is False


@pytest.mark.parametrize("kind", ["opnsense", "unifi"])
def test_mapping_per_source(admin, router, kind):
    env, client, h = admin
    ctx = env.app.state.ctx
    a, b = two_hosts(ctx)
    body = {"url": router, "secret": OPN_SECRET, "key": OPN_KEY} if kind == "opnsense" else \
        {"url": router, "secret": UNIFI_KEY, "site": "default"}
    r = client.put(f"/api/settings/router/{kind}", headers=h, json=body)
    assert r.status_code == 200, r.text
    state = client.post(f"/api/settings/router/{kind}/test", headers=h).json()
    assert state["ok"] is True, state
    assert state["exposed"][str(a)] == ["npm"]
    assert state["exposed"][str(b)] == (["mc-hardcore"] if kind == "opnsense" else [HOST])   # 25565 bzw. SSH auf 22
    label = ROUTERS[kind].label
    with ctx.session_factory() as s:
        assert exposure.exposure_via(s)[a]["npm"] == [f"via {label}: port 443"]
    assert OPN_SECRET not in client.get(f"/api/settings/router/{kind}").text
    assert UNIFI_KEY not in client.get(f"/api/settings/router/{kind}").text


def test_disabled_rule_skipped(admin, router):
    env, client, h = admin
    a, _ = two_hosts(env.app.state.ctx)
    client.put("/api/settings/router/unifi", headers=h, json={"url": router, "secret": UNIFI_KEY})
    state = client.post("/api/settings/router/unifi/test", headers=h).json()
    assert all("8080" not in u["forward"] for u in state["unmatched"])   # abgeschaltet: weder Treffer noch Liste
    assert state["exposed"][str(a)] == ["npm"]


def test_unmatched_forward_listed(admin, router):
    env, client, h = admin
    two_hosts(env.app.state.ctx)
    client.put("/api/settings/router/opnsense", headers=h, json={"url": router, "secret": OPN_SECRET, "key": OPN_KEY})
    state = client.post("/api/settings/router/opnsense/test", headers=h).json()
    reasons = {u["forward"]: u["reason"] for u in state["unmatched"]}
    assert reasons["UDP 51820 → 10.0.0.9:51820"] == "device is not monitored by vulnwatch"
    assert "alias" in reasons["TCP 8443 → webservers:8443"]


def test_auth_error_is_matrix_error(admin, router):
    env, client, h = admin
    client.put("/api/settings/router/opnsense", headers=h, json={"url": router, "secret": "wrong", "key": OPN_KEY})
    state = client.post("/api/settings/router/opnsense/test", headers=h).json()
    assert state["ok"] is False and "rejected" in state["error"]
    with env.app.state.ctx.session_factory() as s:
        rows = {r["key"]: r for r in calculate_coverage_matrix(s)["exposure_sources"]}
    assert rows["opnsense"]["status"] == "fehler" and "rejected" in rows["opnsense"]["detail"]


def test_settings_validate_and_remove(admin, router):
    env, client, h = admin
    assert client.put("/api/settings/router/opnsense", headers=h,
                      json={"url": "http://opnsense.lan", "secret": "x" * 8, "key": "k"}).status_code == 422   # nur HTTPS
    assert client.put("/api/settings/router/opnsense", headers=h,
                      json={"url": router, "secret": OPN_SECRET}).status_code == 422   # Key fehlt
    assert client.put("/api/settings/router/pfsense", headers=h, json={"url": router}).status_code == 404
    client.put("/api/settings/router/unifi", headers=h, json={"url": router, "secret": UNIFI_KEY})
    assert client.delete("/api/settings/router/unifi", headers=h).status_code == 200
    with env.app.state.ctx.session_factory() as s:
        assert setting(s, ROUTERS["unifi"].config_key) is None
