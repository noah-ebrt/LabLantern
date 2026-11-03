"""Connectors TrueNAS und Home Assistant (Phase 5): nachgebaute Geräte im Test, Funde, Abdeckung, Pinning."""
import base64
import hashlib
import http.server
import json
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from app import appliances
from app.coverage import calculate_coverage_matrix
from app.models import Finding, System
from app.rules import classify_appliance_alert, classify_task_age, classify_update

KEY = "1-truenas-api-key"
TOKEN = "ha-long-lived-token"


def make_cert(tmp_path, name="truenas"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    (tmp_path / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                             serialization.NoEncryption()))
    return tmp_path / f"{name}.pem", tmp_path / f"{name}.key"


class FakeTrueNas:
    """TLS-Server mit WebSocket und JSON-RPC wie `/api/current`. `answers` je Methode; fehlende = Method not found."""

    def __init__(self, tmp_path, answers, legacy=False):
        cert, key = make_cert(tmp_path)
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(cert, key)
        self.answers, self.calls, self.legacy = answers, [], legacy
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:   # geschlossen
                return
            try:
                conn = self.tls.wrap_socket(conn, server_side=True)
            except (OSError, ssl.SSLError):
                conn.close()
                continue
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with conn, conn.makefile("rb") as r:
            self._handle(conn, r)

    def close(self):
        self.sock.close()

    def _handle(self, conn, r):
        try:
            lines = []
            while (line := r.readline().decode().strip()):
                lines.append(line)
        except (OSError, ssl.SSLError):
            return
        if not lines:   # Fingerabdruck lesen: Verbindung ohne Anfrage
            return
        if lines[0].split()[1] != ("/websocket" if self.legacy else "/api/current"):
            conn.sendall(b"HTTP/1.1 302 Moved Temporarily\r\nLocation: /ui/\r\nContent-Length: 0\r\n\r\n")
            return
        key = next(x.split(":", 1)[1].strip() for x in lines if x.lower().startswith("sec-websocket-key"))
        accept = base64.b64encode(hashlib.sha1((key + appliances._WebSocket.GUID).encode()).digest()).decode()
        conn.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode())
        try:
            while True:
                b0, b1 = r.read(2)
                n = b1 & 0x7F
                if n == 126:
                    n = int.from_bytes(r.read(2), "big")
                mask = r.read(4)
                msg = json.loads(bytes(b ^ mask[i % 4] for i, b in enumerate(r.read(n))))
                if self.legacy and msg.get("msg") == "connect":
                    self.send(conn, {"msg": "connected", "session": "s"})
                    continue
                if msg.get("msg") == "pong":
                    self.pongs = getattr(self, "pongs", 0) + 1
                    continue
                self.calls.append((msg["method"], msg["params"]))
                if self.legacy:
                    out = ({"msg": "result", "id": msg["id"], "result": self.answers[msg["method"]]}
                           if msg["method"] in self.answers else
                           {"msg": "result", "id": msg["id"], "error": {"error": 22, "errname": "EINVAL",
                                                                         "reason": "Method does not exist"}})
                    self.send(conn, {"msg": "ping", "id": "p"})
                elif msg["method"] in self.answers:
                    out = {"jsonrpc": "2.0", "id": msg["id"], "result": self.answers[msg["method"]]}
                else:
                    out = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "Method not found"}}
                self.send(conn, {"jsonrpc": "2.0", "method": "collection_update"})   # Benachrichtigung dazwischen
                self.send(conn, out)
        except (OSError, ValueError):
            return

    @staticmethod
    def send(conn, obj):
        data = json.dumps(obj).encode()
        half = len(data) // 2   # in zwei Fragmenten, damit der Client sie zusammensetzen muss
        for i, (op, part) in enumerate(((0x1, data[:half]), (0x0, data[half:]))):
            head = bytes([(0x80 if i else 0) | op])
            n = len(part)
            head += bytes([n]) if n < 126 else bytes([126]) + n.to_bytes(2, "big")
            conn.sendall(head + part)


@pytest.fixture
def truenas(tmp_path):
    made = []

    def make(answers, legacy=False):
        made.append(FakeTrueNas(tmp_path, answers, legacy))
        return made[-1]
    yield make
    for nas in made:
        nas.close()


TRUENAS = {
    "auth.login_with_api_key": True,
    "system.info": {"version": "25.04.2.4", "hostname": "truenas"},
    "update.check_available": {"status": "AVAILABLE", "version": "25.04.2.5"},
    "alert.list": [{"uuid": "u1", "klass": "ZpoolCapacityWarning", "level": "WARNING", "formatted": "Pool 80% full",
                    "dismissed": False},
                   {"uuid": "u2", "klass": "Old", "level": "CRITICAL", "formatted": "old", "dismissed": True},
                   {"uuid": "u3", "klass": "Info", "level": "INFO", "formatted": "fyi", "dismissed": False}],
    # 25.10: version/latest_version sind die des App-Pakets, die App-Version steht in den Metadaten
    "app.query": [{"name": "plex", "state": "RUNNING", "version": "1.2.3", "latest_version": "1.2.5",
                   "human_version": "1.41.0_1.2.3", "metadata": {"app_version": "1.41.0"},
                   "upgrade_available": True, "image_updates_available": False,
                   "active_workloads": {"images": ["plexinc/pms-docker:1.41.0"]}},
                  {"name": "custom", "state": "RUNNING", "version": "1.0", "upgrade_available": False,
                   "image_updates_available": True},
                  {"name": "fine", "state": "RUNNING", "version": "2.0", "upgrade_available": False,
                   "image_updates_available": False}],
}


def test_update_rule_patch_is_high_new_line_medium():
    assert classify_update("25.04.2.4", "25.04.2.5") == "hoch"
    assert classify_update("2026.10.1", "2026.10.3") == "hoch"
    assert classify_update("2026.10.3", "2026.11.0") == "mittel"
    assert classify_update("16.2", "16.3") == "mittel"
    assert classify_update("", "1.0") == "mittel"
    assert [classify_appliance_alert(x) for x in ("CRITICAL", "ERROR", "WARNING", "INFO")] == ["hoch", "mittel", "mittel", None]


def test_truenas_findings_from_the_api(truenas):
    nas = truenas(TRUENAS)
    url = f"https://127.0.0.1:{nas.port}"
    data = appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY)
    assert nas.calls[0] == ("auth.login_with_api_key", [KEY])
    assert ("update.status", []) in nas.calls   # 25.10-Methode zuerst, dann Rückfall
    found = {f["target"]: f for f in appliances.truenas_findings(data)}
    assert found["host"]["severity"] == "hoch" and found["host"]["fixed_version"] == "25.04.2.5"
    assert found["app:plex"]["fixed_version"] == "1.2.5" and found["app:plex"]["severity"] == "hoch"
    assert found["app:plex"]["installed_version"] == "1.41.0"
    assert found["app:custom"]["fixed_version"] == "newer image"
    assert found["alert:u1"]["severity"] == "mittel"
    assert set(found) == {"host", "app:plex", "app:custom", "alert:u1"}   # verworfene und INFO-Alarme nicht


def test_truenas_25_10_update_status(truenas):
    answers = {**TRUENAS, "update.status": {"code": "NORMAL", "status": {"new_version": {"version": "25.10.1"}}}}
    nas = truenas(answers)
    url = f"https://127.0.0.1:{nas.port}"
    data = appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY)
    assert data["new_version"] == "25.10.1" and ("update.check_available", []) not in nas.calls


def test_truenas_before_24_10_uses_the_old_protocol_and_chart_releases(truenas):
    answers = {k: v for k, v in TRUENAS.items() if k != "app.query"}
    answers["chart.release.query"] = [{"name": "plex", "status": "ACTIVE", "human_version": "1.40_1.0",
                                       "human_latest_version": "1.41_1.1", "update_available": True,
                                       "container_images_update_available": False}]
    nas = truenas(answers, legacy=True)
    url = f"https://127.0.0.1:{nas.port}"
    data = appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY)
    assert data["version"] == "25.04.2.4" and data["new_version"] == "25.04.2.5" and nas.pongs
    assert data["apps"] == [{"name": "plex", "state": "ACTIVE", "version": "1.40_1.0", "chart": "1.40_1.0", "latest": "1.41_1.1",
                             "upgrade": True, "image_updates": False, "images": []}]


def test_wrong_certificate_never_receives_the_key(truenas):
    nas = truenas(TRUENAS)
    with pytest.raises(appliances.ApplianceError, match="certificate changed"):
        appliances.fetch_truenas(f"https://127.0.0.1:{nas.port}", "0" * 64, KEY)
    assert nas.calls == []


NOW = 1_800_000_000.0
DAY = 86400


def ms(days_ago):
    return {"$date": int((NOW - days_ago * DAY) * 1000)}


DAILY, WEEKLY = {"minute": "0", "hour": "4", "dom": "*", "month": "*", "dow": "*"}, {"dom": "*", "month": "*", "dow": "wed"}
HEALTH = {
    "pool.query": [
        {"name": "tank", "healthy": False, "status": "DEGRADED", "status_detail": "One or more devices are faulted.",
         "size": 100, "allocated": 96, "scan": {"function": "SCRUB", "state": "FINISHED", "end_time": ms(60), "errors": 3}},
        {"name": "ssd", "healthy": True, "status": "ONLINE", "status_code": "FEAT_DISABLED", "size": 100, "allocated": 50,
         "scan": {"function": "SCRUB", "state": "FINISHED", "end_time": ms(50), "errors": 0}},
        {"name": "fresh", "healthy": True, "status": "ONLINE", "size": 100, "allocated": 10, "scan": None},
        {"name": "resilvered", "healthy": True, "status": "ONLINE", "size": 100, "allocated": 10,
         "scan": {"function": "RESILVER", "state": "FINISHED", "end_time": ms(1)}},
    ],
    "pool.scrub.query": [{"pool_name": n, "threshold": 35, "enabled": True} for n in ("tank", "ssd", "fresh", "resilvered")],
    "pool.snapshottask.query": [{"dataset": "tank/home", "enabled": True, "state": {"state": "ERROR", "error": "no space"}},
                                {"dataset": "tank/off", "enabled": False, "state": {"state": "ERROR"}}],
    "replication.query": [
        {"name": "push", "enabled": True, "auto": True, "schedule": None, "periodic_snapshot_tasks": [{"schedule": DAILY}],
         "state": {"state": "FINISHED", "datetime": ms(5)}, "job": None},
        {"name": "after-reboot", "enabled": True, "auto": True, "schedule": None, "state": {"state": "PENDING"}, "job": None},
    ],
    "cloudsync.query": [{"description": "offsite", "enabled": True, "schedule": WEEKLY,
                         "job": {"state": "SUCCESS", "time_finished": ms(10)}}],
    "rsynctask.query": [{"desc": "pull", "enabled": True, "schedule": DAILY,
                         "job": {"state": "FAILED", "error": "rsync: connection refused"}}],
    "service.query": [{"service": "cifs", "state": "RUNNING"}, {"service": "ssh", "state": "STOPPED"},
                      {"service": "ftp", "state": "RUNNING"}],
    "smb.config": {"enable_smb1": True},
    "ssh.config": {"passwordauth": True, "host_ed25519_key": "PRIVATE"},
    "ftp.config": {"tls": True},
    "system.general.config": {"ui_httpsredirect": False},
    "auth.twofactor.config": {"enabled": True},
    "user.query": [{"username": "root", "roles": ["FULL_ADMIN"], "password_disabled": False, "twofactor_auth_configured": True},
                   {"username": "admin", "roles": ["FULL_ADMIN"], "password_disabled": False,
                    "twofactor_auth_configured": False},
                   {"username": "lablantern", "roles": ["READONLY_ADMIN"], "password_disabled": True,
                    "twofactor_auth_configured": False}],
}


def test_truenas_pools_backups_and_hardening(truenas):
    nas = truenas({**TRUENAS, **HEALTH})
    url = f"https://127.0.0.1:{nas.port}"
    data = appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY)
    assert "PRIVATE" not in json.dumps(data)   # ssh.config trägt die Host-Schlüssel: nur die Schalter bleiben
    found = {f["target"]: f for f in appliances.truenas_findings(data, NOW)}
    assert found["pool:tank"]["severity"] == "hoch" and "DEGRADED" in found["pool:tank"]["title"]
    assert found["disk:tank"]["severity"] == "hoch"
    assert found["scrub:tank"]["severity"] == "hoch" and "3 errors" in found["scrub:tank"]["title"]
    assert found["scrub:ssd"]["severity"] == "mittel"          # 50 Tage > 35 + 7
    assert "never" in found["scrub:fresh"]["title"]
    assert "pool:ssd" not in found and "scrub:resilvered" not in found   # Feature-Hinweis, Resilver: kein Fund
    assert found["task:snapshot:tank/home"]["title"].endswith("no space")
    assert found["task:replication:push"]["severity"] == "mittel"     # täglich, 5 Tage alt
    assert "task:replication:after-reboot" not in found and "task:cloudsync:offsite" not in found   # wöchentlich, 10 Tage
    assert "connection refused" in found["task:rsync:pull"]["title"]
    assert "backup" not in found
    assert found["config:smb1"]["severity"] == "hoch"
    assert "config:ssh_password" not in found and "config:ftp_plain" not in found   # SSH aus, FTP mit TLS
    assert found["config:ui_http"]["severity"] == "mittel" and "config:twofa_off" not in found
    assert found["config:admins_without_2fa"]["installed_version"] == "admin"


def test_truenas_without_backup_tasks_and_older_versions(truenas):
    nas = truenas({**TRUENAS, "replication.query": [], "rsynctask.query": [{"desc": "off", "enabled": False}]})
    url = f"https://127.0.0.1:{nas.port}"
    found = {f["target"] for f in appliances.truenas_findings(appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY), NOW)}
    assert "backup" in found and not any(t.startswith(("pool:", "scrub:", "config:")) for t in found)


def test_task_age_rule_follows_the_schedule():
    assert appliances._interval_days(DAILY) == 1 and appliances._interval_days(WEEKLY) == 7
    assert appliances._interval_days({"dom": "1", "dow": "*"}) == 31
    assert [classify_task_age(d, 1) for d in (3, 3.5, 8)] == [None, "mittel", "hoch"]
    assert [classify_task_age(d, 7) for d in (14, 16, 32)] == [None, "mittel", "hoch"]


def test_rejected_key_is_an_error(truenas):
    nas = truenas({**TRUENAS, "auth.login_with_api_key": False})
    url = f"https://127.0.0.1:{nas.port}"
    with pytest.raises(appliances.ApplianceError, match="rejected"):
        appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY)


class FakeHomeAssistant(http.server.BaseHTTPRequestHandler):
    states = [
        {"entity_id": "update.home_assistant_core_update", "state": "on",
         "attributes": {"title": "Home Assistant Core", "installed_version": "2026.10.1", "latest_version": "2026.10.3"}},
        {"entity_id": "update.home_assistant_operating_system_update", "state": "off",
         "attributes": {"title": "Home Assistant Operating System", "installed_version": "16.2", "latest_version": "16.2"}},
        {"entity_id": "update.esphome_flur", "state": "on",
         "attributes": {"friendly_name": "Flur Firmware", "installed_version": "2026.9.0", "latest_version": "2026.10.0"}},
        {"entity_id": "light.kitchen", "state": "on", "attributes": {}},
        # Backup-Sensoren auf Deutsch: nächstes geplantes, letzter Erfolg, letzter Versuch
        {"entity_id": "sensor.backup_nachstes_geplantes_automatisches_backup", "state": "2099-01-01T03:00:00+00:00",
         "attributes": {"device_class": "timestamp"}},
        {"entity_id": "sensor.backup_letztes_erfolgreiches_automatisches_backup", "state": "2020-01-01T03:00:00+00:00",
         "attributes": {"device_class": "timestamp"}},
        {"entity_id": "sensor.backup_zuletzt_versuchtes_automatisches_backup", "state": "2020-01-01T03:00:00+00:00",
         "attributes": {"device_class": "timestamp"}},
        {"entity_id": "sensor.backup_backup_manager_zustand", "state": "idle", "attributes": {"device_class": "enum"}},
        {"entity_id": "sensor.wohnungstur_battery", "state": "9",
         "attributes": {"device_class": "battery", "unit_of_measurement": "%", "friendly_name": "Wohnungstür Batterie"}},
        {"entity_id": "sensor.ikea_switch_1_battery", "state": "80",
         "attributes": {"device_class": "battery", "unit_of_measurement": "%"}},
        {"entity_id": "binary_sensor.wassersensor1_battery_low", "state": "on",
         "attributes": {"device_class": "battery", "friendly_name": "Wassersensor 1"}},
        {"entity_id": "sensor.system_monitor_disk_use_percent_config", "state": "41.2",
         "attributes": {"unit_of_measurement": "%"}},
        {"entity_id": "sensor.home_assistant_host_disk_used", "state": "27.5", "attributes": {"unit_of_measurement": "GB"}},
        {"entity_id": "sensor.home_assistant_host_disk_total", "state": "30.0", "attributes": {"unit_of_measurement": "GB"}},
    ]
    config = {"version": "2026.10.1", "state": "RUNNING", "safe_mode": False, "recovery_mode": False,
              "latitude": 52.5, "longitude": 13.4, "external_url": "https://ha.example.org",
              "components": ["sensor", "sensor.shelly", "shelly", "nuki", "matter", "mqtt", "backup", "automation",
                             "door", "motion", "thread", "ping"]}

    def do_GET(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps(self.config if self.path == "/api/config" else self.states).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def hass():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHomeAssistant)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_homeassistant_connector_end_to_end(admin, hass):
    env, client, h = admin
    ctx = env.app.state.ctx
    body = {"kind": "homeassistant", "name": "homeassistant", "url": hass, "token": TOKEN}
    r = client.post("/api/settings/appliances", headers=h, json=body)
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert TOKEN not in client.get("/api/settings/appliances").text
    sid = r.json()["system_id"]
    with ctx.session_factory() as s:
        found = {f.component: f for f in s.scalars(select(Finding).where(Finding.system_id == sid))}
        assert set(found) == {"Home Assistant Core", "Flur Firmware", "Home Assistant backup", "Wohnungstür Batterie",
                              "Wassersensor 1", "home assistant host disk"}
        assert (found["Home Assistant Core"].severity, found["Flur Firmware"].severity) == ("hoch", "mittel")
        assert found["Home Assistant backup"].severity == "hoch"   # 2020: über 7 Tage
        assert found["home assistant host disk"].severity == "mittel"   # 27,5 von 30 GB = 92 %
        assert found["Wohnungstür Batterie"].severity == "info"
        inv = json.loads(s.get(System, sid).inventory_json)["connector"]
        assert inv["integrations"] == ["matter", "mqtt", "nuki", "shelly"]
        assert "latitude" not in json.dumps(inv) and "ha.example.org" not in json.dumps(inv)
        assert found["Flur Firmware"].source == "homeassistant"
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == sid)
    assert row["checks"]["versionen"]["status"] == "fund" and row["checks"]["paket_cve"]["status"] == "na"
    sysrow = next(x for x in client.get("/api/systems").json() if x["id"] == sid)
    assert (sysrow["state"], sysrow["connector"]["version"]) == ("online", "2026.10.1")
    assert sysrow["needs_reenroll"] is False and sysrow["agent_outdated"] is False   # kein Agent, nichts einzurichten
    watched = client.get(f"/api/early-warnings/watched/{sid}").json()["items"]
    groups = {}
    for w in watched:
        groups.setdefault(w["group"], set()).add(w["keyword"])
    assert groups["Integrations"] == {"matter", "mqtt", "nuki", "shelly"}   # Gerätearten wie „door“ nicht
    assert "home assistant" in groups["Updates (core, OS, add-ons, firmware)"]

    # Update eingespielt: Fund erledigt
    FakeHomeAssistant.states, old = [dict(e, state="off") if e["entity_id"].startswith("update.") else e
                                     for e in FakeHomeAssistant.states], FakeHomeAssistant.states
    try:
        assert client.post(f"/api/settings/appliances/{sid}/test", headers=h).json()["findings"] == 4
    finally:
        FakeHomeAssistant.states = old
    with ctx.session_factory() as s:
        assert {f.status for f in s.scalars(select(Finding).where(Finding.system_id == sid,
                                                                  Finding.cve_id == "LL-UPDATE"))} == {"resolved"}

    # falscher Token: Fehler in der Abdeckung statt stiller Lücke
    assert client.put(f"/api/settings/appliances/{sid}", headers=h, json={**body, "token": "wrong-token"}).json()["ok"] is False
    with ctx.session_factory() as s:
        row = next(x for x in calculate_coverage_matrix(s)["systems"] if x["system_id"] == sid)
    assert row["checks"]["versionen"] == {"status": "fehler", "detail": "Home Assistant rejected the token"}

    assert client.delete(f"/api/settings/appliances/{sid}", headers=h).status_code == 200
    with ctx.session_factory() as s:
        assert s.get(System, sid) is None
    assert ctx.secrets.get(appliances.secret_name(sid)) is None


def test_truenas_requires_https_and_unique_names(admin):
    env, client, h = admin
    r = client.post("/api/settings/appliances", headers=h,
                    json={"kind": "truenas", "name": "nas", "url": "http://truenas.lan", "token": KEY})
    assert r.status_code == 422 and "HTTPS" in r.text
    with env.app.state.ctx.session_factory() as s:
        s.add(System(name="host-c", status="active"))
        s.commit()
    r = client.post("/api/settings/appliances", headers=h,
                    json={"kind": "homeassistant", "name": "host-c", "url": "http://127.0.0.1:1", "token": TOKEN})
    assert r.status_code == 409


def test_homeassistant_backup_failure_missing_backups_and_recovery_mode():
    now = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
    ts = lambda eid, v: {"entity_id": eid, "state": v, "attributes": {"device_class": "timestamp"}}  # noqa: E731
    ok_then_failed = [ts("sensor.backup_a", "2026-10-25T03:00:00+00:00"),   # letzter Erfolg gestern
                      ts("sensor.backup_b", "2026-10-26T03:00:00+00:00"),   # letzter Versuch heute
                      ts("sensor.backup_c", "2026-10-27T03:00:00+00:00")]   # nächster geplanter
    found = appliances.homeassistant_findings(appliances.parse_homeassistant(ok_then_failed, {}), now)
    assert [(f["cve_id"], f["severity"]) for f in found] == [("LL-BACKUP", "mittel")] and "failed" in found[0]["title"]

    found = appliances.homeassistant_findings(appliances.parse_homeassistant([], {"recovery_mode": True}), now)
    assert {f["cve_id"]: f["severity"] for f in found} == {"LL-HA-MODE": "hoch", "LL-BACKUP": "mittel"}
    assert "No automatic backups configured" in next(f for f in found if f["cve_id"] == "LL-BACKUP")["title"]
