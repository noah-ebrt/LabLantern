"""Cloudflare Tunnel als Expositionsquelle (PLAN-extensions A5): Ingress-Regeln → Container oder Host."""
import io
import json
import time
import urllib.error
from pathlib import Path

from app import cftunnel
from app.containers import HOST
from app.exposure import exposure_via, source_rows
from app.models import System, put_setting
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)

FIX = Path(__file__).parent / "fixtures"


def hosts(ctx):
    a, b = make_system(ctx, "docker-a"), make_system(ctx, "nas-b")
    with ctx.session_factory() as s:
        s.get(System, a).ip, s.get(System, b).ip = "10.0.0.5", "10.0.0.6"
        s.get(System, a).inventory_json = json.dumps({"containers": [
            {"name": "vaultwarden", "image": "vaultwarden/server:1.32"},
            {"name": "tunnel", "image": "docker.io/cloudflare/cloudflared:2024.10.0"},
            {"name": "homeassistant", "image": "ghcr.io/home-assistant/home-assistant:2024.10", "ports": [8123]}]})
        s.get(System, b).inventory_json = json.dumps({"containers": [{"name": "truenas-ui", "ports": [8443]}]})
        s.commit()
    return a, b


def rules():
    return json.loads((FIX / "cf-tunnel-config.json").read_text())["result"]["config"]["ingress"]


def mapped(ctx, rules_, tunnel="home"):
    with ctx.session_factory() as s:
        systems = s.query(System).filter(System.status == "active").all()
        return cftunnel.map_ingress([{**r, "tunnel": tunnel} for r in rules_], systems)


def test_container_name_ip_and_localhost_mapping(ctx):
    a, b = hosts(ctx)
    exposed, via, unmatched = mapped(ctx, rules())
    assert exposed == {a: ["homeassistant", "vaultwarden"], b: ["truenas-ui"]}
    assert via[a]["vaultwarden"] == ["vw.example.org"] and via[a]["homeassistant"] == ["ha.example.org"]
    assert [u["what"] for u in unmatched] == ["x.example.org"]   # Name im LAN: von Hand markieren


def test_catch_all_skipped(ctx):
    hosts(ctx)
    _, _, unmatched = mapped(ctx, [{"service": "http_status:404"}, {"hostname": "a.example.org", "service": "hello_world"}])
    assert unmatched == []


def test_localhost_ambiguous_with_two_cloudflared(ctx):
    a, b = hosts(ctx)
    with ctx.session_factory() as s:
        s.get(System, b).inventory_json = json.dumps({"containers": [{"name": "cf", "image": "cloudflare/cloudflared"}]})
        s.commit()
    _, _, unmatched = mapped(ctx, [{"hostname": "ha.example.org", "service": "http://localhost:8123"}])
    assert unmatched[0]["why"] == "ambiguous: cloudflared on several hosts"


def fake_api(monkeypatch, answers):
    def urlopen(req, timeout):
        path = req.full_url.split("/client/v4", 1)[1].split("?", 1)[0]
        got = answers[path]
        if isinstance(got, Exception):
            raise got
        return io.BytesIO(json.dumps(got).encode())

    monkeypatch.setattr(cftunnel.urllib.request, "urlopen", urlopen)


def configure(ctx):
    with ctx.session_factory() as s:
        put_setting(s, cftunnel.CF_CONFIG, {"account_id": "acc1"})
        s.commit()
    ctx.secrets.set(cftunnel.CF_SECRET, "tok")


def test_local_tunnel_unmatched_and_refresh(ctx, monkeypatch):
    a, _ = hosts(ctx)
    configure(ctx)
    fake_api(monkeypatch, {"/accounts/acc1/cfd_tunnel": json.loads((FIX / "cf-tunnels.json").read_text()),
                           "/accounts/acc1/cfd_tunnel/aaaa-1111/configurations":
                               json.loads((FIX / "cf-tunnel-config.json").read_text())})
    state = cftunnel.refresh_cftunnel(ctx)
    assert state["ok"] and state["tunnels"] == 2
    assert {"what": "legacy", "why": "ingress not readable (locally managed config.yml)"} in state["unmatched"]
    with ctx.session_factory() as s:
        assert "via Cloudflare Tunnel: vw.example.org" in exposure_via(s)[a]["vaultwarden"]
        assert [(r["key"], r["status"]) for r in source_rows(s, time.time())] == [("cftunnel", "ok")]


def test_api_403_is_error_row(ctx, monkeypatch):
    hosts(ctx)
    configure(ctx)
    err = urllib.error.HTTPError("u", 403, "Forbidden", {}, io.BytesIO(b"{}"))
    fake_api(monkeypatch, {"/accounts/acc1/cfd_tunnel": err})
    state = cftunnel.refresh_cftunnel(ctx)
    assert state["ok"] is False and "Cloudflare Tunnel: Read" in state["error"]
    with ctx.session_factory() as s:
        row = source_rows(s, time.time())[0]
    assert (row["key"], row["status"]) == ("cftunnel", "fehler")


def test_host_service_via_localhost(ctx):
    a, _ = hosts(ctx)
    with ctx.session_factory() as s:
        inv = json.loads(s.get(System, a).inventory_json)
        s.get(System, a).inventory_json = json.dumps({**inv, "host_ports": [22]})
        s.commit()
    exposed, _, _ = mapped(ctx, [{"hostname": "ssh.example.org", "service": "ssh://localhost:22"}])
    assert exposed == {a: [HOST]}


def test_settings_api_validates_and_hides_token(admin):
    _, client, h = admin
    acc = "0123456789abcdef0123456789abcdef"
    assert client.put("/api/settings/cftunnel", headers=h, json={"account_id": "x" * 32, "token": "t" * 40}).status_code == 422
    assert client.put("/api/settings/cftunnel", headers=h, json={"account_id": acc}).status_code == 422   # Token fehlt
    assert client.put("/api/settings/cftunnel", headers=h, json={"account_id": acc, "token": "t" * 40}).status_code == 200
    got = client.get("/api/settings/cftunnel").json()
    assert got["config"] == {"account_id": acc} and "t" * 40 not in json.dumps(got)
