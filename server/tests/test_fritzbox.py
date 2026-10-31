"""FRITZ!Box-Connector und automatisch erkannte Internet-Erreichbarkeit (NPM + Router, Dienste des Hosts)."""
import json

from sqlalchemy import select

from app import fritzbox
from app.connectors import connector_exposed, match_hosts
from app.containers import HOST
from app.models import Finding, System, put_setting
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)

ENTRY = """<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:dslforum-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>{port}</NewInternalPort><NewInternalClient>{ip}</NewInternalClient><NewEnabled>{on}</NewEnabled>
<NewPortMappingDescription>{desc}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""


def two_hosts(ctx):
    a, b = make_system(ctx, "host-c"), make_system(ctx, "host-a")
    with ctx.session_factory() as s:
        s.get(System, a).ip, s.get(System, b).ip = "10.0.0.5", "10.0.0.6"
        s.get(System, a).inventory_json = json.dumps({"containers": [{"name": "npm", "ports": [80, 443]}]})
        # mc-hardcore läuft im Host-Netz: der Agent ab 0.14 meldet seinen Port wie einen veröffentlichten
        s.get(System, b).inventory_json = json.dumps({"containers": [{"name": "mc-hardcore", "ports": [8099, 25565]}],
                                                       "host_ports": [22, 8930]})
        s.commit()
    return a, b


def test_npm_falls_back_to_a_host_service_on_the_port(ctx):
    a, b = two_hosts(ctx)
    hosts = [{"domains": ["mc.example.org"], "forward_host": "10.0.0.6", "forward_port": 8099, "enabled": True},
             {"domains": ["ff.example.org"], "forward_host": "10.0.0.6", "forward_port": 8930, "enabled": True},
             {"domains": ["x.example.org"], "forward_host": "10.0.0.6", "forward_port": 9999, "enabled": True}]
    with ctx.session_factory() as s:
        exposed, unmatched = match_hosts(s, hosts, a)
    assert exposed == {b: [HOST, "mc-hardcore"]}
    assert [u["domains"] for u in unmatched] == [["x.example.org"]] and "port 9999" in unmatched[0]["reason"]


def test_router_forwards_are_read_and_matched(ctx, monkeypatch):
    a, b = two_hosts(ctx)
    entries = [dict(ext=443, port=443, ip="10.0.0.5", on=1, desc="https"),
               dict(ext=25565, port=25565, ip="10.0.0.6", on=1, desc="minecraft"),
               dict(ext=2222, port=22, ip="10.0.0.6", on=0, desc="ssh (aus)"),
               dict(ext=51820, port=51820, ip="10.0.0.99", on=1, desc="wireguard")]

    class Resp:
        def __init__(self, body):
            self.body = body.encode()

        def read(self, n):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, timeout):
            action = req.headers["Soapaction"].rsplit("#", 1)[1]
            if action == "GetPortMappingNumberOfEntries":
                return Resp(f"<r><NewPortMappingNumberOfEntries>{len(entries)}</NewPortMappingNumberOfEntries></r>")
            i = int(req.data.decode().split("<NewPortMappingIndex>")[1].split("<")[0])
            return Resp(ENTRY.format(**entries[i]))

    monkeypatch.setattr(fritzbox.urllib.request, "build_opener", lambda *h: Opener())
    forwards = fritzbox.fetch_forwards("http://fritz.box:49000", "vw", "pw")
    assert [f["external_port"] for f in forwards] == [443, 25565, 2222, 51820] and not forwards[2]["enabled"]
    with ctx.session_factory() as s:
        exposed, unmatched = fritzbox.match_forwards(s, forwards)
    assert exposed == {a: ["npm"], b: ["mc-hardcore"]}
    assert unmatched == [{"forward": "TCP 51820 → 10.0.0.99:51820", "description": "wireguard",
                          "reason": "device is not monitored by vulnwatch"}]


def test_tr064_port_is_added_when_missing():
    assert fritzbox.tr064_url("http://192.168.178.1/") == "http://192.168.178.1:49000"
    assert fritzbox.tr064_url("https://fritz.box") == "https://fritz.box:49443"
    assert fritzbox.tr064_url("http://fritz.box:49000") == "http://fritz.box:49000"


def test_router_failure_keeps_the_last_mapping(ctx, monkeypatch):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        put_setting(s, fritzbox.FRITZ_CONFIG, {"url": "http://fritz.box:49000", "user": "vw"})
        put_setting(s, fritzbox.FRITZ_STATE, {"exposed": {str(sid): ["web"]}, "forwards": 3})
        s.commit()
    ctx.secrets.set(fritzbox.FRITZ_SECRET, "pw")

    def fail(*a):
        raise fritzbox.FritzError("FRITZ!Box unreachable (timed out)")

    monkeypatch.setattr(fritzbox, "fetch_forwards", fail)
    state = fritzbox.refresh_fritz(ctx)
    assert (state["ok"], state["exposed"], state["forwards"]) == (False, {str(sid): ["web"]}, 3)


def test_router_and_npm_exposure_both_reach_the_rating(ctx):
    from tests.test_scan_flow import raw, run_once

    sid = make_system(ctx)
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps({"containers": [
            {"name": "vw", "image": "vw:1"}, {"name": "mc", "image": "mc:1"}]})
        put_setting(s, "npm.state", {"exposed": {str(sid): ["vw"]}})
        put_setting(s, fritzbox.FRITZ_STATE, {"exposed": {str(sid): ["mc", "vw", HOST]}})
        s.commit()
        assert connector_exposed(s) == {sid: {"vw": ["NPM", "router"], "mc": ["router"], HOST: ["router"]}}
    run_once(ctx, [(sid, [{**raw(cve="CVE-1", cvss=9.1), "target": "image:mc:1"},
                          {**raw(cve="CVE-2", cvss=9.1), "target": "host"}], None)])
    with ctx.session_factory() as s:
        got = {f.cve_id: (f.severity, f.internet_exposed) for f in s.scalars(select(Finding))}
    assert got == {"CVE-1": ("kritisch", True), "CVE-2": ("kritisch", True)}
