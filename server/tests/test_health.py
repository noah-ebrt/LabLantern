import http.server
import json
import socket
import struct
import threading

import pytest
from sqlalchemy import select

from app import health
from app.health import InlineExecutor, aggregate, apply_result, state_durations, uptime_of
from app.healthprobes import ProbeResult, ProbeSpec, clean_params, run_probe
from app.models import HealthCheck, HealthEvent, HealthMonitor, Setting, System


class Probes:
    """Ersetzt das Netz: Ergebnis je Host, Standard erreichbar."""

    def __init__(self):
        self.results: dict[str, ProbeResult] = {}
        self.calls: list[ProbeSpec] = []

    def __call__(self, spec: ProbeSpec) -> ProbeResult:
        self.calls.append(spec)
        return self.results.get(spec.host, ProbeResult(True, 3.0))


@pytest.fixture
def hw(admin):
    """Admin, Engine mit Sofort-Ausführung und abgefangenem Alarm."""
    env, client, h = admin
    engine = env.app.state.health
    probes = Probes()
    engine.executor, engine.probe = InlineExecutor(), probes
    engine.hooks = InlineExecutor()
    sent = []
    env.app.state.ctx.notifier = lambda title, body, html=None, kind="report": sent.append((title, body, kind)) or (True, None)
    return env, client, h, engine, probes, sent


def run(env, engine, ticks=1, step=31.0):
    for _ in range(ticks):
        engine.tick()
        env.clock.advance(step)
    engine.tick()


def token(client, h, name="esp"):
    r = client.post("/api/health/tokens", json={"name": name}, headers=h)
    assert r.status_code == 200
    return r.json()["token"]


def create(client, h, **kw):
    body = {"name": "NAS", "host": "192.0.2.20", "checks": [{"kind": "ping"}, {"kind": "tcp", "params": {"port": 445}}]}
    body.update(kw)
    r = client.post("/api/health/monitors", json=body, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


# --- Zustandsmaschine und Zusammenfassung ---

def test_check_needs_consecutive_failures_before_degraded_and_down():
    c = HealthCheck(kind="tcp", fails=0, fails_degraded=2, fails_down=4, state="up")
    states = []
    for _ in range(4):
        apply_result(c, ProbeResult(False, error="refused"), 100.0)
        states.append(c.state)
    assert states == ["up", "degraded", "degraded", "down"]
    apply_result(c, ProbeResult(True, 2.0), 101.0)
    assert (c.state, c.fails, c.error) == ("up", 0, "")


def test_warning_and_inconclusive_results():
    c = HealthCheck(kind="tls", fails=0, fails_degraded=2, fails_down=4, state="up")
    apply_result(c, ProbeResult(True, 5.0, warn="certificate expires in 3 days"), 1.0)
    assert (c.state, c.error) == ("degraded", "certificate expires in 3 days")
    apply_result(c, ProbeResult(False, error="FRITZ!Box unreachable", inconclusive=True), 2.0)
    assert c.state == "unknown" and c.fails == 0


@pytest.mark.parametrize("checks, expected", [
    ([("ping", "up"), ("agent", "up")], ("up", "")),
    ([("ping", "up"), ("agent", "down")], ("up", "Agent not reporting")),
    ([("ping", "down"), ("agent", "down")], ("down", "")),
    ([("ping", "down"), ("agent", "up")], ("degraded", "Agent still reports: likely a network or firewall problem")),
    ([("ping", "up"), ("http", "down")], ("degraded", "")),
    ([("agent", "up")], ("up", "")),
    ([("ping", "unknown")], ("unknown", "")),
    ([], ("unknown", "")),
])
def test_aggregate(checks, expected):
    assert aggregate(checks) == expected


def test_params_are_validated():
    assert clean_params("http", {"scheme": "https"})["port"] == 443
    for kind, bad in [("http", {"path": "no-slash"}), ("http", {"expect": "abc"}), ("tcp", {"port": 70000}),
                      ("dns", {"name": "bad..name"}), ("fritz_host", {"target": "not a mac"}),
                      ("ping", {"target": "x; rm -rf /"})]:
        with pytest.raises(ValueError):
            clean_params(kind, bad)


def test_a_pasted_url_is_split_into_the_fields():
    p = clean_params("http", {"target": "http://192.0.2.39/index.html", "scheme": "https", "port": 443})
    assert (p["target"], p["scheme"], p["port"], p["path"]) == ("192.0.2.39", "http", 80, "/index.html")
    p = clean_params("http", {"target": "https://printer.lan:8443/status?x=1"})
    assert (p["target"], p["scheme"], p["port"], p["path"]) == ("printer.lan", "https", 8443, "/status?x=1")
    assert clean_params("ping", {"target": "http://192.0.2.39/"})["target"] == "192.0.2.39"
    assert clean_params("tls", {"target": "https://nas.lan:5001/"})["port"] == 5001
    for bad in ("ftp://printer.lan/", "http://", "http://printer.lan:99999/"):
        with pytest.raises(ValueError):
            clean_params("http", {"target": bad})


def test_monitor_host_may_be_a_url(hw):
    env, client, h, *_ = hw
    r = create(client, h, host="http://192.0.2.39/index.html",
               checks=[{"kind": "http", "params": {"target": "http://192.0.2.39:8080/index.html"}}])
    mon = client.get("/api/health/overview").json()["monitors"][0]
    assert r["slug"] == "nas" and mon["host"] == "192.0.2.39"
    with env.app.state.ctx.session_factory() as s:
        c = s.scalars(select(HealthCheck)).one()
        params = json.loads(c.params)
    assert (params["target"], params["scheme"], params["port"], params["path"]) == ("192.0.2.39", "http", 8080, "/index.html")


# --- Engine über die API ---

def test_monitor_goes_down_alerts_once_and_recovers(hw):
    env, client, h, engine, probes, sent = hw
    create(client, h)
    run(env, engine)
    tok = token(client, h)
    r = client.get("/api/health/states", headers={"Authorization": f"Bearer {tok}"})
    assert r.json()["states"] == {"nas": "up"} and r.json()["engine_ok"] is True

    probes.results["192.0.2.20"] = ProbeResult(False, error="timed out")
    run(env, engine, ticks=6, step=11)
    doc = client.get("/api/health/status/nas", headers={"Authorization": f"Bearer {tok}"}).json()
    assert doc["state"] == "down"
    assert {c["error"] for c in doc["checks"]} == {"timed out"}
    assert len(sent) == 1 and "NAS is DOWN" in sent[0][0] and sent[0][2] == "alert"

    mid = client.get("/api/health/overview").json()["monitors"][0]["id"]
    for period in ("24h", "7d", "30d"):
        hist = client.get(f"/api/health/monitors/{mid}/history?range={period}").json()
        assert hist["range"] == period and len(hist["checks"]) == 2
    assert any(v is not None for v in hist["checks"][0]["uptime"])

    del probes.results["192.0.2.20"]
    run(env, engine, ticks=2)
    assert client.get("/api/health/states", headers={"Authorization": f"Bearer {tok}"}).json()["states"]["nas"] == "up"
    assert "recovered" in sent[-1][0]
    with env.app.state.ctx.session_factory() as s:
        assert [e.state for e in s.scalars(select(HealthEvent).order_by(HealthEvent.ts))] == ["up", "degraded", "down", "up"]


def test_many_hosts_down_at_once_is_one_outage_alert(hw):
    env, client, h, engine, probes, sent = hw
    for i in range(4):
        create(client, h, name=f"Host {i}", host=f"192.0.2.{30 + i}", checks=[{"kind": "ping"}])
    run(env, engine)
    for i in range(4):
        probes.results[f"192.0.2.{30 + i}"] = ProbeResult(False, error="no echo reply")
    run(env, engine, ticks=6, step=11)
    assert len(sent) == 1 and "network outage" in sent[0][0]


def test_stale_engine_reports_unknown_not_up(hw):
    env, client, h, engine, probes, sent = hw
    create(client, h)
    run(env, engine)
    env.clock.advance(health.ENGINE_STALE + 1)
    doc = client.get("/api/health/status", headers={"Authorization": f"Bearer {token(client, h)}"}).json()
    assert doc["engine"]["ok"] is False and doc["monitors"][0]["state"] == "unknown"
    assert all(c["stale"] for c in doc["monitors"][0]["checks"])


def test_live_updates_are_pushed_not_polled(hw):
    env, client, h, engine, probes, sent = hw
    pushed = []
    engine.publish = pushed.append
    create(client, h)
    for _ in range(4):   # 4 Runden à 2 s: neue Messwerte, aber höchstens eine Meldung je 15 s
        engine.tick()
        env.clock.advance(2)
    assert pushed == [["health-metrics"]]
    env.clock.advance(health.METRICS_PUSH)
    engine.poke()
    engine.tick()
    assert pushed == [["health-metrics"]] * 2

    # Stehen die Prüfungen, meldet der Live-Wächter „health“ (Schnappschuss kippt ohne Schreibzugriff)
    hub = env.app.state.events
    before = hub.snapshot()
    assert before["health"] is True
    env.clock.advance(health.ENGINE_STALE + 1)
    assert hub.snapshot()["health"] is False and hub.snapshot()["systems"] == before["systems"]


def test_api_needs_a_valid_token_or_session(hw):
    env, client, h, engine, probes, sent = hw
    anon = env.new_client()
    assert anon.get("/api/health/states").status_code == 401
    assert anon.get("/api/health/states", headers={"Authorization": "Bearer wrong"}).status_code == 401
    tok = token(client, h)
    assert anon.get("/api/health/states", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert client.get("/api/health/states").status_code == 200   # angemeldet
    tid = client.get("/api/health/tokens").json()[0]["id"]
    client.delete(f"/api/health/tokens/{tid}", headers=h)
    assert anon.get("/api/health/states", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_states_keep_their_fields_and_add_rev_etag(hw):
    env, client, h, engine, probes, sent = hw
    mid = create(client, h)["id"]
    run(env, engine)
    auth = {"Authorization": f"Bearer {token(client, h)}"}
    r = client.get("/api/health/states", headers=auth)
    doc = r.json()
    assert {"engine_ok", "generated_at", "states", "critical"} <= set(doc) and "hosts" not in doc   # wie bisher
    assert doc["v"] == 1 and doc["engine"]["ok"] is True and doc["engine"]["interval_s"] == health.TICK
    assert doc["server_time"].endswith("Z") and doc["engine"]["last_cycle_at"].endswith("Z")
    rev = doc["rev"]
    assert r.headers["ETag"] == f'"{rev}"'

    assert client.get("/api/health/states", headers={**auth, "If-None-Match": f'"{rev}"'}).status_code == 304
    assert client.get(f"/api/health/states?since={rev}", headers=auth).status_code == 304
    run(env, engine)   # neue Messwerte, gleicher Stand: rev bleibt
    assert client.get(f"/api/health/states?since={rev}", headers=auth).status_code == 304
    assert client.get("/api/health/states?since=1", headers=auth).json()["rev"] == rev   # z. B. nach Neustart: sofort

    client.put(f"/api/health/monitors/{mid}", json={"name": "TrueNAS", "host": "192.0.2.20", "critical": False,
                                                     "checks": [{"kind": "ping"}]}, headers=h)
    doc = client.get(f"/api/health/states?since={rev}&hosts=1", headers=auth).json()
    assert doc["rev"] > rev and doc["critical"] == []
    assert doc["hosts"] == {"nas": {"label": "TrueNAS", "critical": False, "kind": "service"}}
    assert client.get("/api/health/status", headers=auth).json()["rev"] == doc["rev"]

    env.clock.advance(health.ENGINE_STALE + 1)   # stehende Engine: neuer rev, alles unknown
    stale = client.get("/api/health/states", headers=auth).json()
    assert stale["rev"] > doc["rev"] and stale["engine_ok"] is False and stale["states"] == {"nas": "unknown"}


def test_long_poll_waits_for_a_change(hw, monkeypatch):
    import time
    from app import health_api
    env, client, h, engine, probes, sent = hw
    mid = create(client, h)["id"]
    run(env, engine)
    auth = {"Authorization": f"Bearer {token(client, h)}"}
    rev = client.get("/api/health/states", headers=auth).json()["rev"]

    t0 = time.monotonic()
    r = client.get(f"/api/health/states?since={rev}&wait=0.3", headers=auth)
    assert r.status_code == 304 and time.monotonic() - t0 >= 0.3
    monkeypatch.setattr(health_api, "MAX_WAIT", 0.2)
    t0 = time.monotonic()
    assert client.get(f"/api/health/states?since={rev}&wait=55", headers=auth).status_code == 304
    assert time.monotonic() - t0 < 5   # auf MAX_WAIT gekappt
    monkeypatch.setattr(health_api, "MAX_WAIT", 10.0)

    def pause_soon():
        time.sleep(0.3)
        with env.app.state.ctx.session_factory() as s:
            s.get(HealthMonitor, mid).paused = True
            s.commit()
        engine.feed.refresh()

    threading.Thread(target=pause_soon).start()
    t0 = time.monotonic()
    r = client.get(f"/api/health/states?since={rev}&wait=10", headers=auth)
    assert r.status_code == 200 and r.json()["states"] == {"nas": "paused"} and time.monotonic() - t0 < 5

    # /status kann dasselbe, für Geräte, die Latenz und Alter mit anzeigen
    r = client.get("/api/health/status", headers=auth)
    rev = r.headers["X-Lablantern-Rev"]
    assert rev == str(r.json()["rev"])
    run(env, engine)   # neue Messwerte, kein Wechsel
    assert client.get(f"/api/health/status?since={rev}&wait=0.2", headers=auth).status_code == 304
    client.post(f"/api/health/monitors/{mid}/pause", json={"paused": False}, headers=h)
    r = client.get(f"/api/health/status?since={rev}&wait=10", headers=auth)
    assert r.status_code == 200 and r.json()["monitors"][0]["state"] == "unknown" and r.headers["X-Lablantern-Rev"] != rev


def test_token_is_rate_limited_and_shows_last_ip(hw):
    from app.health_api import TOKEN_RATE
    env, client, h, engine, probes, sent = hw
    auth = {"Authorization": f"Bearer {token(client, h)}"}
    for _ in range(TOKEN_RATE[0]):
        assert client.get("/api/health/states", headers=auth).status_code == 200
    r = client.get("/api/health/states", headers=auth)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert client.get("/api/health/states").status_code == 200   # Sitzung: nicht begrenzt
    assert client.get("/api/health/tokens").json()[0]["last_ip"] == "testclient"


def test_agents_are_monitored_automatically(hw):
    env, client, h, engine, probes, sent = hw
    ctx = env.app.state.ctx
    with ctx.session_factory() as s:
        s.add(System(name="pve", ip="192.0.2.5", status="active", last_contact=env.clock()))
        s.add(System(name="waiting", ip="192.0.2.6", status="pending"))
        s.commit()
    run(env, engine)
    mons = client.get("/api/health/overview").json()["monitors"]
    assert [(m["name"], m["auto"], m["state"]) for m in mons] == [("pve", True, "up")]
    assert sorted(c["kind"] for c in mons[0]["checks"]) == ["agent", "ping"]
    assert client.delete(f"/api/health/monitors/{mons[0]['id']}", headers=h).status_code == 409

    # Agent schweigt, Ping klappt: weiter up, aber mit Warnung (nach der Anlaufzeit)
    env.clock.advance(health.AGENT_GRACE)
    run(env, engine, ticks=5)
    m = client.get("/api/health/overview").json()["monitors"][0]
    assert (m["state"], m["warning"]) == ("up", "Agent not reporting")

    with ctx.session_factory() as s:
        s.scalars(select(System)).first().status = "revoked"
        s.commit()
    engine.last_sync = 0
    run(env, engine)
    assert client.get("/api/health/overview").json()["monitors"] == []


def test_connector_devices_are_monitored_and_matching_monitors_adopted(hw):
    env, client, h, engine, probes, sent = hw
    ctx = env.app.state.ctx
    create(client, h, name="TrueNAS", host="192.0.2.20", checks=[{"kind": "tcp", "params": {"port": 445}}])
    create(client, h, name="AdGuard Home", host="192.0.2.56", checks=[{"kind": "dns"}])
    with ctx.session_factory() as s:
        nas = System(name="truenas", host_type="truenas", ip="192.0.2.20", status="connector")
        ha = System(name="homeassistant", host_type="homeassistant", ip="192.0.2.57", status="connector")
        pi = System(name="raspberrypi", ip="192.0.2.56", status="active", last_contact=env.clock())
        s.add_all([nas, ha, pi])
        s.flush()
        s.add(Setting(key="appliances.config", value=json.dumps({
            str(nas.id): {"kind": "truenas", "url": "https://192.0.2.20", "fingerprint": "ab" * 32},
            str(ha.id): {"kind": "homeassistant", "url": "http://192.0.2.57:8123", "fingerprint": ""}})))
        s.commit()
    engine.last_sync = 0
    run(env, engine)
    mons = {m["name"]: m for m in client.get("/api/health/overview").json()["monitors"]}
    assert set(mons) == {"truenas", "homeassistant", "raspberrypi", "AdGuard Home"}

    # TrueNAS-Monitor übernommen: Schlüssel und SMB-Prüfung bleiben, Ping und Web-Adresse kommen dazu
    nas_m = mons["truenas"]
    assert (nas_m["slug"], nas_m["source"], nas_m["auto"]) == ("truenas", "connector", True)
    by_kind = {c["kind"]: c["params"] for c in nas_m["checks"]}
    assert set(by_kind) == {"tcp", "ping", "http"}
    assert by_kind["http"]["scheme"] == "https" and by_kind["http"]["verify_tls"] is False   # Fingerabdruck statt CA
    ha_checks = {c["kind"]: c["params"] for c in mons["homeassistant"]["checks"]}
    assert ha_checks["http"]["port"] == 8123 and ha_checks["http"]["verify_tls"] is True

    # AdGuard läuft auf dem Pi, ist aber nicht der Pi: bleibt ein eigener Monitor
    assert mons["AdGuard Home"]["auto"] is False and mons["raspberrypi"]["source"] == "agent"

    with ctx.session_factory() as s:
        s.delete(s.scalars(select(System).where(System.name == "homeassistant")).one())
        s.commit()
    engine.last_sync = 0
    run(env, engine)
    assert "homeassistant" not in {m["name"] for m in client.get("/api/health/overview").json()["monitors"]}


def test_heartbeat_and_announced_shutdown(hw):
    env, client, h, engine, probes, sent = hw
    out = create(client, h, name="Laptop", host="", checks=[{"kind": "heartbeat", "interval_s": 60}])
    beat_token = next(iter(out["heartbeat_tokens"].values()))
    anon = env.new_client()
    assert anon.get(f"/api/health/beat/{beat_token}").text == "ok\n"
    run(env, engine)
    assert client.get("/api/health/states").json()["states"]["laptop"] == "up"
    assert anon.post(f"/api/health/beat/{beat_token}?state=down").text == "bye\n"
    run(env, engine)
    assert client.get("/api/health/states").json()["states"]["laptop"] == "down"
    assert anon.get("/api/health/beat/nope").status_code == 404


def test_fritz_checks_need_the_connector(hw):
    env, client, h, engine, probes, sent = hw
    r = client.post("/api/health/monitors", json={"name": "Phone", "checks": [{"kind": "fritz_host", "params": {"target": "00:00:5E:00:53:AF"}}]}, headers=h)
    assert r.status_code == 422
    kinds = {k["kind"]: k for k in client.get("/api/health/options").json()["kinds"]}
    assert kinds["fritz_host"]["available"] is False and "FRITZ!Box" in kinds["fritz_host"]["reason"]

    ctx = env.app.state.ctx
    ctx.secrets.set("fritz.password", "pw")
    with ctx.session_factory() as s:
        s.add(Setting(key="fritz.config", value='{"url": "http://192.0.2.1", "user": "vw"}'))
        s.commit()
    create(client, h, name="Phone", host="", checks=[{"kind": "fritz_host", "params": {"target": "00:00:5e:00:53:af"}}])
    create(client, h, name="Internet", host="", checks=[{"kind": "fritz_wan"}])
    run(env, engine)
    spec = next(c for c in probes.calls if c.kind == "fritz_host")
    assert spec.host == "00:00:5E:00:53:AF" and spec.fritz["password"] == "pw"
    assert any(c.kind == "fritz_wan" for c in probes.calls)   # läuft ohne Host
    assert spec.fritz["url"] == "http://192.0.2.1:49000"


def test_http_auth_is_stored_encrypted_and_never_returned(hw):
    env, client, h, engine, probes, sent = hw
    create(client, h, name="HA", checks=[{"kind": "http", "params": {"port": 8123}, "auth": "Bearer abc"}])
    run(env, engine)
    assert probes.calls[-1].auth == "Bearer abc"
    mon = client.get("/api/health/overview").json()["monitors"][0]
    assert mon["checks"][0]["has_auth"] is True and "abc" not in str(mon)


def test_uptime_from_state_changes(session_factory):
    with session_factory() as s:
        s.add(HealthMonitor(id=1, name="x", slug="x"))
        s.flush()
        s.add_all([HealthEvent(monitor_id=1, ts=0, state="up"), HealthEvent(monitor_id=1, ts=75, state="down")])
        s.commit()
        d = state_durations(s, 1, 0, 100)[0]
        assert uptime_of(d) == 75.0
        halves = state_durations(s, 1, 0, 100, 2)
        assert [uptime_of(x) for x in halves] == [100.0, 50.0]


# --- echte Prüfungen gegen lokale Dienste ---

def test_tcp_and_http_probes_against_local_servers():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/" else 503)
            self.end_headers()
            self.wfile.write(b"hello healthy world")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        assert run_probe(ProbeSpec("tcp", "127.0.0.1", {"port": port}, 2)).ok
        ok = run_probe(ProbeSpec("http", "127.0.0.1", clean_params("http", {"port": port, "match": "healthy"}), 2))
        assert ok.ok and ok.latency_ms is not None
        miss = run_probe(ProbeSpec("http", "127.0.0.1", clean_params("http", {"port": port, "match": "nope"}), 2))
        assert not miss.ok and "expected text" in miss.error
        bad = run_probe(ProbeSpec("http", "127.0.0.1", clean_params("http", {"port": port, "path": "/x"}), 2))
        assert not bad.ok and "HTTP 503" in bad.error
    finally:
        srv.shutdown()
        srv.server_close()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed = s.getsockname()[1]
    r = run_probe(ProbeSpec("tcp", "127.0.0.1", {"port": closed}, 2))
    assert not r.ok and r.error == "connection refused"


def test_dns_probe_against_local_udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def answer(rcode, ancount):
        data, addr = sock.recvfrom(512)
        flags = 0x8180 | rcode
        sock.sendto(data[:2] + struct.pack("!HHHHH", flags, 1, ancount, 0, 0) + data[12:], addr)

    try:
        t = threading.Thread(target=answer, args=(0, 1))
        t.start()
        assert run_probe(ProbeSpec("dns", "127.0.0.1", clean_params("dns", {"port": port}), 2)).ok
        t.join()
        t = threading.Thread(target=answer, args=(3, 0))
        t.start()
        r = run_probe(ProbeSpec("dns", "127.0.0.1", clean_params("dns", {"port": port}), 2))
        t.join()
        assert not r.ok and "does not exist" in r.error
    finally:
        sock.close()


# --- Webhooks ---

@pytest.fixture
def receiver():
    """Lokales Webhook-Ziel: merkt sich Body und Header jedes POST."""
    got = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append((dict(self.headers), body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/hook?key=abc", got
    srv.shutdown()
    srv.server_close()


def test_webhook_gets_signed_events(hw, receiver):
    import hashlib
    import hmac
    env, client, h, engine, probes, sent = hw
    url, got = receiver
    create(client, h)
    r = client.post("/api/health/webhooks", json={"name": "LED", "url": url}, headers=h)
    assert r.status_code == 200, r.text
    key = r.json()["secret"]
    listed = client.get("/api/health/webhooks").json()
    assert listed[0]["target"].startswith("http://127.0.0.1:") and "key=abc" not in json.dumps(listed)

    run(env, engine)   # erste Runde: die Engine läuft an, alles von unknown auf up
    headers, body = got[-1]
    doc = json.loads(body)
    assert headers["X-Lablantern-Event"] == "engine_up" == doc["event"] and doc["states"] == {"nas": "up"}
    assert doc["changes"][0] | {"at": None} == {"slug": "nas", "name": "NAS", "critical": True, "from": "unknown",
                                                "to": "up", "at": None}
    assert doc["v"] == 1 and doc["rev"] and doc["hosts"]["nas"] == {"label": "NAS", "critical": True, "kind": "service"}
    signed = headers["X-Lablantern-Timestamp"].encode() + b"." + body
    assert headers["X-Lablantern-Signature"] == "sha256=" + hmac.new(key.encode(), signed, hashlib.sha256).hexdigest()
    assert len(headers["X-Lablantern-Delivery"]) == 36

    n = len(got)
    run(env, engine)   # kein Wechsel, kein Aufruf
    assert len(got) == n

    mid = client.get("/api/health/overview").json()["monitors"][0]["id"]
    client.post(f"/api/health/monitors/{mid}/pause", json={"paused": True}, headers=h)
    doc = json.loads(got[-1][1])
    assert doc["event"] == "state_changed" and doc["states"] == {"nas": "paused"}
    assert [(c["from"], c["to"]) for c in doc["changes"]] == [("up", "paused")]

    wid = listed[0]["id"]
    r = client.post(f"/api/health/webhooks/{wid}/test", headers=h)
    assert r.json() == {"ok": True, "error": ""} and json.loads(got[-1][1])["event"] == "test"
    assert client.get("/api/health/webhooks").json()[0]["last_event"] == "test"

    # Stillstand meldet der Wächter, nicht die (stehende) Engine
    client.post(f"/api/health/monitors/{mid}/pause", json={"paused": False}, headers=h)
    run(env, engine)
    env.clock.advance(health.ENGINE_STALE + 1)
    engine.feed.watch_once()
    doc = json.loads(got[-1][1])
    assert doc["event"] == "engine_down" and doc["engine_ok"] is False and doc["states"] == {"nas": "unknown"}

    assert client.delete(f"/api/health/webhooks/{wid}", headers=h).status_code == 200
    assert client.get("/api/health/webhooks").json() == []
    assert env.app.state.ctx.secrets.get(f"health.webhook.{wid}.url") is None


def test_webhook_filters_by_event_and_host(hw, receiver):
    env, client, h, engine, probes, sent = hw
    url, got = receiver
    create(client, h)
    create(client, h, name="PVE", host="192.0.2.21", checks=[{"kind": "ping"}])
    run(env, engine)
    r = client.post("/api/health/webhooks", json={"name": "HA", "url": url, "events": ["state_changed"],
                                                  "monitors": ["pve"], "heartbeat_min": 0}, headers=h)
    wid = r.json()["id"]
    assert client.get("/api/health/webhooks").json()[0] | {"last_sent": None} == {
        "id": wid, "name": "HA", "target": url.split("/hook")[0], "created_at": env.clock.now, "events": ["state_changed"],
        "monitors": ["pve"], "heartbeat_min": 0, "last_sent": None, "last_event": "", "last_error": ""}

    probes.results["192.0.2.20"] = ProbeResult(False, error="timed out")   # nur NAS: nicht abonniert
    run(env, engine, ticks=6, step=11)
    assert got == []
    probes.results["192.0.2.21"] = ProbeResult(False, error="timed out")
    run(env, engine, ticks=6, step=11)
    docs = [json.loads(b) for _, b in got]
    assert docs and all(set(d["states"]) == {"pve"} and {c["slug"] for c in d["changes"]} == {"pve"} for d in docs)

    env.clock.advance(health.ENGINE_STALE + 1)
    engine.feed.watch_once()   # engine_down ist nicht abonniert
    assert all(json.loads(b)["event"] == "state_changed" for _, b in got)

    r = client.put(f"/api/health/webhooks/{wid}", json={"name": "HA", "events": ["nope"]}, headers=h)
    assert r.status_code == 422
    r = client.put(f"/api/health/webhooks/{wid}", json={"name": "HA 2", "events": [], "monitors": []}, headers=h)
    assert r.status_code == 200
    w = client.get("/api/health/webhooks").json()[0]
    assert (w["name"], w["events"], w["monitors"], w["target"]) == ("HA 2", [], [], url.split("/hook")[0])


def test_webhook_heartbeat_and_retries(hw, receiver, monkeypatch):
    from app import healthwebhooks
    env, client, h, engine, probes, sent = hw
    url, got = receiver
    create(client, h)
    run(env, engine)
    wid = client.post("/api/health/webhooks", json={"name": "n8n", "url": url, "events": ["state_changed"],
                                                    "heartbeat_min": 5}, headers=h).json()["id"]
    engine.feed.watch_once()
    env.clock.advance(4 * 60)
    engine.feed.watch_once()
    assert got == []
    env.clock.advance(60)
    engine.feed.watch_once()
    assert [json.loads(b)["event"] for _, b in got] == ["heartbeat"] and got[0][0]["X-Lablantern-Event"] == "heartbeat"

    # Ziel weg: Wiederholungen nach BACKOFF, ohne zu schlafen; gleiche Delivery-ID
    queued = []
    monkeypatch.setattr(healthwebhooks, "later", lambda delay, fn, *args: queued.append((delay, fn, args)))
    env.app.state.ctx.secrets.set(f"health.webhook.{wid}.url", "http://127.0.0.1:9/gone")
    env.clock.advance(5 * 60)
    engine.feed.watch_once()
    assert [d for d, _, _ in queued] == [5]
    assert "retry 1 of 3" in client.get("/api/health/webhooks").json()[0]["last_error"]
    while len(queued) < 10:
        delay, fn, args = queued[-1]
        before = len(queued)
        fn(*args)
        if len(queued) == before:
            break
    assert [d for d, _, _ in queued] == [5, 30, 120] and len({a[5] for _, _, a in queued}) == 1
    assert "retry" not in client.get("/api/health/webhooks").json()[0]["last_error"]


def test_webhook_rejects_bad_urls(hw):
    env, client, h, *_ = hw
    for url in ("ftp://example.org/x", "http:///nohost", "https://user:pw@example.org/x"):
        assert client.post("/api/health/webhooks", json={"name": "x", "url": url}, headers=h).status_code == 422
