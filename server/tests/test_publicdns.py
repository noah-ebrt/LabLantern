"""Öffentliche DNS-Prüfung für Proxy-Routen (PLAN-extensions A4): nur was öffentlich auflöst, gilt als erreichbar."""
import json

import pytest

from app import connectors, publicdns
from app.exposure import source_rows
from app.models import put_setting, setting
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)


def answers(a=None, aaaa=None, status=0):
    def resolver(name, rtype):
        ips = a if rtype == "A" else aaaa
        return {"Status": status, "Answer": [{"type": 1 if rtype == "A" else 28, "data": ip} for ip in ips or []]}
    return resolver


def test_public_ip_is_public():
    assert publicdns.classify_hostname("app.example.org", answers(a=["93.184.216.34"])) == "public"
    assert publicdns.classify_hostname("app.example.org", answers(aaaa=["2606:4700::1"])) == "public"


def test_private_ip_is_lan():
    assert publicdns.classify_hostname("nas.example.org", answers(a=["192.168.1.10"], aaaa=["fd00::5"])) == "lan"


def test_nxdomain_is_lan():
    assert publicdns.classify_hostname("gone.example.org", answers(status=3)) == "lan"


def test_resolver_down_counts_exposed_and_warns():
    def down(name, rtype):
        raise OSError("timed out")

    assert publicdns.classify_hostname("app.example.org", down) == "unknown"
    assert publicdns.classify_hostname("app.example.org", answers(status=2)) == "unknown"   # SERVFAIL
    assert publicdns.decide("app.example.org", [], {}, lambda n: "unknown") == (True, publicdns.CHECK_FAILED)


@pytest.mark.parametrize("name", ["nas.lan", "printer.home.arpa", "pi.local", "git.corp.internal"])
def test_home_arpa_no_request(name):
    def forbidden(name, rtype):
        raise AssertionError("no request for local names")

    assert publicdns.classify_hostname(name, forbidden) == "lan"


def test_override_wins():
    overrides = {"hosts": {"app.example.org": "lan"}, "entrypoints": {"websecure": "public"}}
    assert publicdns.decide("app.example.org", ["websecure"], overrides, lambda n: "public")[0] is False
    assert publicdns.decide("b.example.org", ["websecure"], overrides, lambda n: "lan")[0] is True
    assert publicdns.decide("b.example.org", ["web"], {"entrypoints": {"web": "lan"}}, lambda n: "public")[0] is False
    assert publicdns.decide("b.example.org", [], overrides, lambda n: "lan") == (False, "no public address in public DNS")


def npm_with(ctx, monkeypatch, sid, resolver):
    hosts = [{"domains": ["vw.example.org"], "forward_host": "vw", "forward_port": 80, "certificate_id": None, "enabled": True},
             {"domains": ["nas.example.org"], "forward_host": "nas", "forward_port": 80, "certificate_id": None, "enabled": True}]
    monkeypatch.setattr(connectors, "fetch_npm", lambda *a: (hosts, []))
    monkeypatch.setattr(publicdns, "doh_query", resolver)
    ctx.secrets.set(connectors.NPM_SECRET, "pw")
    with ctx.session_factory() as s:
        put_setting(s, connectors.NPM_CONFIG, {"url": "http://npm.lan:81", "email": "a@b.c", "system_id": sid})
        s.commit()
    return connectors.refresh_npm(ctx)


def two_containers(ctx):
    sid = make_system(ctx)
    from app.models import System
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps({"containers": [{"name": "vw"}, {"name": "nas"}]})
        s.commit()
    return sid


def test_npm_lan_host_not_exposed(ctx, monkeypatch):
    sid = two_containers(ctx)
    state = npm_with(ctx, monkeypatch, sid, lambda n, t: {"Status": 0, "Answer": [
        {"type": 1, "data": "93.184.216.34" if n.startswith("vw.") else "192.168.1.10"}] if t == "A" else []})
    assert state["exposed"] == {str(sid): ["vw"]}
    assert state["lan_only"] == [{"domains": ["nas.example.org"], "target": "nas:80",
                                  "reason": "no public address in public DNS"}]
    with ctx.session_factory() as s:
        assert [r["status"] for r in source_rows(s, state["at"])] == ["ok"]


def test_npm_public_host_unchanged(ctx, monkeypatch):
    sid = two_containers(ctx)
    state = npm_with(ctx, monkeypatch, sid, answers(a=["93.184.216.34"]))
    assert state["exposed"] == {str(sid): ["nas", "vw"]} and state["lan_only"] == []


def test_npm_dns_down_keeps_exposed_and_is_error_row(ctx, monkeypatch):
    sid = two_containers(ctx)

    def down(name, rtype):
        raise OSError("timed out")

    state = npm_with(ctx, monkeypatch, sid, down)
    assert state["exposed"] == {str(sid): ["nas", "vw"]}
    with ctx.session_factory() as s:
        row = source_rows(s, state["at"])[0]
        assert setting(s, connectors.NPM_STATE)["dns_failed"] == ["vw.example.org", "nas.example.org"]
    assert row["status"] == "fehler" and "public DNS check failed" in row["detail"]


def test_overrides_api_admin_only_and_applied(ctx, monkeypatch, admin):
    _, client, h = admin
    sid = two_containers(ctx)
    assert client.put("/api/settings/exposure-overrides", json={"hosts": {}}).status_code == 403   # ohne CSRF
    r = client.put("/api/settings/exposure-overrides", headers=h, json={"hosts": {"VW.example.org": "lan"}})
    assert r.status_code == 200 and r.json()["hosts"] == {"vw.example.org": "lan"}
    assert client.put("/api/settings/exposure-overrides", headers=h, json={"hosts": {"x": "maybe"}}).status_code == 422
    state = npm_with(ctx, monkeypatch, sid, answers(a=["93.184.216.34"]))
    assert state["exposed"] == {str(sid): ["nas"]}
    assert state["lan_only"][0]["reason"] == "marked LAN only by hand"
    assert client.get("/api/settings/npm").json()["overrides"]["hosts"] == {"vw.example.org": "lan"}
