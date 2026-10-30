"""Traefik-Router aus Docker-Labels als Expositionsquelle (PLAN-extensions B1)."""
import json
import time

import pytest

from app import traefik
from app.exposure import exposure_via, source_rows
from app.models import System, put_setting
from app.publicdns import OVERRIDES_KEY
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)


@pytest.mark.parametrize("rule,hosts", [
    ("Host(`a.example.org`)", ["a.example.org"]),
    ("Host(`a.example.org`, `b.example.org`)", ["a.example.org", "b.example.org"]),
    ("Host(`a.example.org`) || Host(`b.example.org`)", ["a.example.org", "b.example.org"]),
    ("Host(`a.example.org`) && PathPrefix(`/api`)", ["a.example.org"]),
    ("HostSNI(`mc.example.org`)", ["mc.example.org"]),
    ('Host("a.example.org")', ["a.example.org"]),
])
def test_parse_rule_hosts(rule, hosts):
    assert traefik.parse_rule(rule) == (hosts, None)


@pytest.mark.parametrize("rule", ["HostSNI(`*`)", "PathPrefix(`/x`)", "Host(`a.example.org`) || HostRegexp(`^.+\\.x$`)"])
def test_parse_rule_unmatched(rule):
    hosts, why = traefik.parse_rule(rule)
    assert hosts == [] and why


def test_hostregexp_unmatched(ctx):
    sid = with_labels(ctx, {"app": {"traefik.http.routers.app.rule": "HostRegexp(`{sub:[a-z]+}.example.org`)"}})
    state = traefik.refresh_traefik(ctx)
    assert state["exposed"] == {} and state["unmatched"][0]["what"] == "app on host-c"
    assert "HostRegexp" in state["unmatched"][0]["why"]
    assert sid


def with_labels(ctx, containers: dict[str, dict]):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps({"containers": [
            {"name": n, "image": "x:1", "labels": labels} for n, labels in containers.items()]})
        s.commit()
    return sid


def public(name, rtype):
    return {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}] if rtype == "A" else []}


def test_router_labels_expose_container(ctx, monkeypatch):
    monkeypatch.setattr("app.publicdns.doh_query", public)
    sid = with_labels(ctx, {
        "app": {"traefik.http.routers.app.rule": "Host(`app.example.org`)",
                "traefik.http.routers.app.entrypoints": "websecure"},
        "off": {"traefik.enable": "false", "traefik.http.routers.off.rule": "Host(`off.example.org`)"},
        "plain": {"com.docker.compose.project": "x"}})
    state = traefik.refresh_traefik(ctx)
    assert state["exposed"] == {str(sid): ["app"]}
    with ctx.session_factory() as s:
        assert exposure_via(s)[sid]["app"] == ["via Traefik: app.example.org"]
        row = source_rows(s, time.time())[0]
    assert (row["label"], row["status"]) == ("Traefik (Docker labels)", "ok")


def test_entrypoint_override_lan(ctx, monkeypatch):
    monkeypatch.setattr("app.publicdns.doh_query", public)
    sid = with_labels(ctx, {"app": {"traefik.http.routers.app.rule": "Host(`app.example.org`)",
                                    "traefik.http.routers.app.entrypoints": "lan, internal"}})
    with ctx.session_factory() as s:
        put_setting(s, OVERRIDES_KEY, {"hosts": {}, "entrypoints": {"lan": "lan", "internal": "lan"}})
        s.commit()
    state = traefik.refresh_traefik(ctx)
    assert state["exposed"] == {} and state["lan_only"][0]["reason"] == "entrypoint marked LAN only by hand"
    assert state["entrypoints"] == ["internal", "lan"]
    assert sid


def test_no_traefik_labels_no_row(ctx):
    with_labels(ctx, {"plain": {"com.docker.compose.project": "x"}})
    assert traefik.refresh_traefik(ctx)["configured"] is False
    with ctx.session_factory() as s:
        assert source_rows(s, time.time()) == []


def test_scan_run_uses_fresh_traefik_labels(ctx, monkeypatch):
    from sqlalchemy import select

    from app.models import Finding
    from tests.test_scan_flow import raw, run_once

    monkeypatch.setattr("app.publicdns.doh_query", public)
    sid = with_labels(ctx, {"app": {"traefik.http.routers.app.rule": "Host(`app.example.org`)"}})
    run_once(ctx, [(sid, [{**raw(cve="CVE-1", cvss=9.1), "target": "image:x:1"}], None)])
    with ctx.session_factory() as s:
        f = s.scalar(select(Finding))
    assert (f.severity, f.internet_exposed) == ("kritisch", True)
