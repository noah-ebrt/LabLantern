"""Produktstände (Phase 4): Image-Aktualität gegen eine nachgebaute Registry, EOL, Funde und Abdeckung, NPM."""
import io
import json
import time
import urllib.error
from datetime import datetime, timezone
from email.message import Message

import pytest
from sqlalchemy import select

from app import eol, products
from app.connectors import match_hosts
from app.freshness import DOCKERHUB, Registry, check, parse_ref
from app.models import Finding, System, put_setting
from app.rules import classify_product, is_patch_step
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)

IDX_NEW, IDX_OLD = "sha256:" + "a" * 64, "sha256:" + "b" * 64
CFG_NEW, CFG_OLD = "sha256:" + "c" * 64, "sha256:" + "d" * 64


class Resp(io.BytesIO):
    def __init__(self, body=b"", headers=None):
        super().__init__(body)
        self.headers = Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v


class FakeRegistry:
    """Antwortet wie eine OCI-Registry; zählt GET-Anfragen auf Manifeste (Docker Hub zählt sie als Pull)."""

    def __init__(self, tags=None, digest=IDX_NEW, missing=()):
        self.tags = tags or {"latest": IDX_NEW, "1.2.3": IDX_OLD, "1.2.4": IDX_NEW}
        self.digest, self.missing, self.gets = digest, set(missing), 0

    def __call__(self, req, timeout=None):
        url, method = req.full_url, req.get_method()
        repo = url.split("/v2/", 1)[1].split("/manifests/")[0].split("/tags/")[0] if "/v2/" in url else ""
        if repo in self.missing:
            raise urllib.error.HTTPError(url, 404, "nf", Message(), None)
        if "/tags/list" in url:
            return Resp(json.dumps({"tags": list(self.tags)}).encode())
        ref = url.rsplit("/manifests/", 1)[1]
        if method == "HEAD":
            if ref not in self.tags:
                raise urllib.error.HTTPError(url, 404, "nf", Message(), None)
            return Resp(headers={"Docker-Content-Digest": self.tags[ref]})
        self.gets += 1
        if ref in (IDX_NEW, IDX_OLD):   # Index -> Plattform-Manifest
            return Resp(json.dumps({"manifests": [{"digest": "sha256:" + ref[7] * 63 + "f",
                                                   "platform": {"os": "linux", "architecture": "amd64"}}]}).encode())
        return Resp(json.dumps({"config": {"digest": CFG_NEW if ref[7] == "a" else CFG_OLD}}).encode())


def test_parse_ref_like_image_check():
    assert parse_ref("lscr.io/linuxserver/plex:latest") == ("lscr.io", "linuxserver/plex", "latest")
    assert parse_ref("mariadb:10.11") == (DOCKERHUB, "library/mariadb", "10.11")
    assert parse_ref("caddy@sha256:abc") is None


def test_same_tag_new_digest_is_outdated_with_repo_digests():
    reg = Registry(opener=FakeRegistry())
    assert check("img/app:latest", {IDX_OLD}, "", "amd64", "", reg, {})[0] == "outdated"
    assert check("img/app:latest", {IDX_NEW}, "", "amd64", "", reg, {})[:2] == ("current", "1.2.4")


def test_pinned_version_with_newer_patch_is_newer_version():
    reg = Registry(opener=FakeRegistry())
    status, running, newer, _ = check("img/app:1.2.3", {IDX_OLD}, "", "amd64", "", reg, {})
    assert (status, running, newer) == ("newer-version", "1.2.3", "1.2.4")


def test_without_repo_digests_the_config_digest_decides():
    fake = FakeRegistry()
    reg = Registry(opener=fake)
    assert check("ghcr.io/x/app:latest", set(), CFG_NEW, "amd64", "", reg, {})[0] == "current"
    assert check("ghcr.io/x/app:latest", set(), CFG_OLD, "amd64", "", Registry(opener=fake), {})[0] == "outdated"


def test_docker_hub_budget_leaves_the_rest_pending_and_the_cache_carries_over(tmp_path):
    fake = FakeRegistry()
    reg = Registry(tmp_path, opener=fake)
    reg.budget[DOCKERHUB] = 1   # reicht nicht für Index + Manifest
    assert check("library/app:latest", set(), CFG_NEW, "amd64", "", reg, {})[0] == "pending"
    reg2 = Registry(tmp_path, opener=fake)
    assert check("library/app:latest", set(), CFG_NEW, "amd64", "", reg2, {})[0] == "current"
    reg2.save_cache()
    gets = fake.gets
    reg3 = Registry(tmp_path, opener=fake)   # aus dem Cache: keine weiteren GETs
    assert check("library/app:latest", set(), CFG_NEW, "amd64", "", reg3, {})[0] == "current"
    assert fake.gets == gets


def test_local_builds_and_untagged_images():
    reg = Registry(opener=FakeRegistry(missing={"library/myapp"}))
    assert check("myapp:latest", set(), CFG_NEW, "amd64", "", reg, {})[0] == "local"
    assert check("sha256:" + "e" * 64, set(), "", "amd64", "", reg, {})[0] == "unknown"


def test_product_rules():
    assert classify_product("outdated") == classify_product("eol") == "hoch"
    assert classify_product("newer", patch_only=True) == "hoch"
    assert classify_product("newer", patch_only=False) == "mittel"
    assert is_patch_step("19.5.1-ce.0", "19.5.3-ce.0") and not is_patch_step("3.11-slim", "3.15-slim")


EOL_DATA = {"result": [
    {"name": "mariadb", "label": "MariaDB", "identifiers": [{"id": "pkg:docker/library/mariadb"}],
     "releases": [{"name": "11.8", "isEol": False, "latest": {"name": "11.8.9"}},
                  {"name": "10.11", "isEol": False, "latest": {"name": "10.11.19"}},
                  {"name": "10.6", "isEol": True, "eolFrom": "2026-07-06", "latest": {"name": "10.6.30"}}]},
    {"name": "ubuntu", "label": "Ubuntu", "identifiers": [],
     "releases": [{"name": "24.04", "isEol": False}, {"name": "20.04", "isEol": True, "eolFrom": "2025-05-31"}]},
    {"name": "redis", "label": "Redis", "identifiers": [{"id": "pkg:docker/library/redis"}],
     "releases": [{"name": "8.2", "isEol": False}, {"name": "8.0", "isEol": True}]},
]}


def test_eol_release_matching():
    db = eol.EolDb(EOL_DATA["result"])
    assert db.docker["library/mariadb"] == "mariadb" and db.docker["gitlab/gitlab-ce"] == "gitlab"
    assert db.release("mariadb", "10.11.18")["name"] == "10.11"
    assert db.release("mariadb", "10.6")["isEol"] is True
    assert db.release("redis", "8")["name"] == "8.2"   # Tag 8-alpine folgt der neuesten 8er-Linie
    assert db.release("mariadb", "9.1") is None
    assert db.newest_maintained("mariadb") == "11.8.9"


def test_eol_load_uses_cache_and_reports_stale_data(tmp_path):
    data = json.dumps(EOL_DATA).encode()
    db, err = eol.load(tmp_path, fetch=lambda: data)
    assert db and err == ""

    def down():
        raise urllib.error.URLError("offline")

    db, err = eol.load(tmp_path, fetch=down, now=time.time() + 2 * 86400)
    assert db and err == ""            # Cache 2 Tage alt: gilt noch
    db, err = eol.load(tmp_path, fetch=down, now=time.time() + 8 * 86400)
    assert db is None and "not reachable" in err


def _inventory(ctx, sid, containers, os_version="24.04"):
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps({"os_id": "ubuntu", "os_version_id": os_version,
                                                        "os_name": f"Ubuntu {os_version}", "arch": "amd64",
                                                        "containers": containers})
        s.commit()


def _containers():
    return [{"name": "db", "image": "mariadb:10.6", "image_id": CFG_OLD, "state": "running",
             "repo_digests": [f"mariadb@{IDX_OLD}"]},
            {"name": "app", "image": "img/app:latest", "image_id": CFG_OLD, "state": "running",
             "repo_digests": [f"img/app@{IDX_OLD}"]},
            {"name": "old", "image": "img/old:1", "image_id": CFG_OLD, "state": "exited"}]


@pytest.fixture
def versions(ctx, monkeypatch, tmp_path):
    fake = FakeRegistry(tags={"latest": IDX_NEW, "10.6": IDX_OLD, "10.6.30": IDX_OLD})
    monkeypatch.setattr(products, "Registry", lambda cache_dir: Registry(cache_dir, opener=fake))
    monkeypatch.setattr(eol, "_fetch", lambda url=eol.URL: json.dumps(EOL_DATA).encode())
    monkeypatch.setattr(eol, "load", lambda d, fetch=None, now=None: (eol.EolDb(EOL_DATA["result"]), ""))
    return fake


def test_refresh_creates_resolves_and_feeds_coverage(ctx, versions):
    from app.coverage import calculate_coverage_matrix

    sid = make_system(ctx)
    _inventory(ctx, sid, _containers(), os_version="20.04")
    state = products.refresh_versions(ctx)
    rows = {r["image"]: r["status"] for r in state["systems"][str(sid)]["rows"]}
    assert rows == {"mariadb:10.6": "current", "img/app:latest": "outdated"}   # gestoppte Container nicht
    with ctx.session_factory() as s:
        got = {(f.cve_id, f.target, f.severity, f.source) for f in s.scalars(select(Finding))}
        cov = calculate_coverage_matrix(s)["systems"][0]["checks"]["versionen"]
    assert got == {("VW-IMAGE-OUTDATED", "image:img/app:latest", "hoch", "registry"),
                   ("VW-EOL", "image:mariadb:10.6", "hoch", "eol"),
                   ("VW-EOL", "host", "hoch", "eol")}
    assert cov["status"] == "fund" and "1 outdated" in cov["detail"] and "2 end of life" in cov["detail"]
    # Image aktualisiert, OS aktualisiert: Funde werden behoben
    fixed = _containers()
    fixed[1]["repo_digests"] = [f"img/app@{IDX_NEW}"]
    _inventory(ctx, sid, fixed)
    products.refresh_versions(ctx)
    with ctx.session_factory() as s:
        open_ = {f.cve_id + f.target for f in s.scalars(select(Finding).where(Finding.status == "open"))}
    assert open_ == {"VW-EOLimage:mariadb:10.6"}


def test_scanner_results_never_resolve_product_findings(ctx, versions):
    from tests.test_scan_flow import run_once

    sid = make_system(ctx)
    _inventory(ctx, sid, _containers())
    products.refresh_versions(ctx)
    run_once(ctx, [(sid, [], None)])   # Scan ohne Funde
    with ctx.session_factory() as s:
        assert s.scalar(select(Finding).where(Finding.source == "registry")).status == "open"


def test_versions_check_states(ctx):
    sid = make_system(ctx)
    with ctx.session_factory() as s:
        sysrow = s.get(System, sid)
        now = time.time()
        assert products.versions_check(None, sysrow, {}, now)[0] == "offen"
        state = {"at": now - 40 * 3600, "eol_error": "", "systems": {str(sid): {"rows": [], "errors": {}, "pending": []}}}
        assert products.versions_check(state, sysrow, {}, now)[0] == "fehler"
        state["at"] = now
        state["systems"][str(sid)]["errors"] = {"x:1": "registry x: HTTP 500"}
        assert products.versions_check(state, sysrow, {}, now) == ("fehler", "1 image(s) not checkable: x:1: registry x: HTTP 500")
        state["systems"][str(sid)]["errors"] = {}
        state["eol_error"] = "endoflife.date not reachable (URLError)"
        assert products.versions_check(state, sysrow, {}, now)[0] == "fehler"


def test_refresh_endpoint_needs_admin(admin):
    env, client, h = admin
    assert client.post("/api/versions/refresh").status_code in (401, 403)
    assert client.get("/api/versions").json() == {}


def test_npm_matching_by_container_name_and_port(ctx):
    a, b = make_system(ctx, "host-b"), make_system(ctx, "host-a")
    with ctx.session_factory() as s:
        s.get(System, a).ip, s.get(System, b).ip = "10.0.0.5", "10.0.0.6"
        s.get(System, a).inventory_json = json.dumps({"containers": [
            {"name": "vaultwarden", "ports": []}, {"name": "nextcloud", "ports": [11000]}]})
        s.get(System, b).inventory_json = json.dumps({"containers": [{"name": "grafana", "ports": [3000]},
                                                                     {"name": "x", "ports": [80]},
                                                                     {"name": "y", "ports": [80]}]})
        s.commit()
        hosts = [{"domains": ["vw.example.org"], "forward_host": "vaultwarden", "forward_port": 80, "enabled": True},
                 {"domains": ["cloud.example.org"], "forward_host": "127.0.0.1", "forward_port": 11000, "enabled": True},
                 {"domains": ["g.example.org"], "forward_host": "10.0.0.6", "forward_port": 3000, "enabled": True},
                 {"domains": ["amb.example.org"], "forward_host": "10.0.0.6", "forward_port": 80, "enabled": True},
                 {"domains": ["off.example.org"], "forward_host": "grafana", "forward_port": 3000, "enabled": False}]
        exposed, unmatched = match_hosts(s, hosts, a)
    assert exposed == {a: ["nextcloud", "vaultwarden"], b: ["grafana"]}
    assert [u["domains"] for u in unmatched] == [["amb.example.org"]]


def test_npm_exposure_reaches_the_rating(ctx):
    from tests.test_scan_flow import raw, run_once

    sid = make_system(ctx)
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps({"containers": [{"name": "vw", "image": "vw:1",
                                                                         "image_id": CFG_NEW}]})
        put_setting(s, "npm.state", {"exposed": {str(sid): ["vw"]}})
        s.commit()
    run_once(ctx, [(sid, [{**raw(cvss=9.1), "target": "image:vw:1"}], None)])
    with ctx.session_factory() as s:
        f = s.scalar(select(Finding))
    assert (f.severity, f.internet_exposed) == ("kritisch", True)


def test_npm_settings_never_return_the_password(admin):
    env, client, h = admin
    assert client.put("/api/settings/npm", headers=h, json={"url": "ftp://x", "email": "a@b.c", "password": "x"}).status_code == 422
    assert client.put("/api/settings/npm", headers=h,
                      json={"url": "http://npm.lan:81", "email": "vw@example.org", "password": "NPM-GEHEIM-1"}).status_code == 200
    body = client.get("/api/settings/npm").text
    assert "NPM-GEHEIM-1" not in body and "npm.lan" in body


def test_unconfirmed_images_never_report_the_label_as_version():
    fake = FakeRegistry()
    reg = Registry(opener=fake)
    reg.budget[DOCKERHUB] = 0
    assert check("library/app:latest", set(), CFG_NEW, "amd64", "24.04", reg, {})[:2] == ("pending", "")


def test_rate_limit_is_pending_not_an_error():
    class Limited(FakeRegistry):
        def __call__(self, req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 429, "slow down", Message(), None)

    assert check("lscr.io/x/plex:latest", set(), CFG_NEW, "amd64", "", Registry(opener=Limited()), {})[0] == "pending"


def test_certificates_of_active_hosts_are_checked_and_become_findings(ctx, monkeypatch):
    from datetime import timedelta

    from app import connectors

    sid = make_system(ctx, "host-b")
    now = datetime.now(timezone.utc)
    iso = lambda d: (now + timedelta(days=d)).strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731 (Format wie NPM)
    hosts = [{"domains": ["gitlab.example.org"], "forward_host": "10.0.0.5", "forward_port": 8080, "certificate_id": 1, "enabled": True},
             {"domains": ["cloud.example.org"], "forward_host": "10.0.0.5", "forward_port": 11000, "certificate_id": 2, "enabled": True},
             {"domains": ["old.example.org"], "forward_host": "10.0.0.5", "forward_port": 1, "certificate_id": 3, "enabled": False},
             {"domains": ["vw.example.org"], "forward_host": "10.0.0.5", "forward_port": 8888, "certificate_id": 4, "enabled": True}]
    certs = [{"id": 1, "name": "gitlab", "domains": ["gitlab.example.org"], "expires_on": iso(60), "provider": "letsencrypt"},
             {"id": 2, "name": "cloud", "domains": ["cloud.example.org"], "expires_on": iso(12), "provider": "letsencrypt"},
             {"id": 3, "name": "old", "domains": ["old.example.org"], "expires_on": iso(-40), "provider": "letsencrypt"},
             {"id": 4, "name": "vw", "domains": ["vw.example.org"], "expires_on": iso(-1), "provider": "letsencrypt"}]
    monkeypatch.setattr(connectors, "fetch_npm", lambda *a: (hosts, certs))
    ctx.secrets.set("npm.password", "x" * 12)
    with ctx.session_factory() as s:
        put_setting(s, "npm.config", {"url": "http://npm.lan:81", "email": "vw@example.org", "system_id": sid})
        s.commit()
    state = connectors.refresh_npm(ctx)
    assert [c["name"] for c in state["certificates"]] == ["vw", "cloud", "gitlab"]   # abgelaufenes zuerst, altes Zertifikat nicht
    with ctx.session_factory() as s:
        got = {(f.component, f.severity, f.source) for f in s.scalars(select(Finding).where(Finding.status == "open"))}
    assert got == {("vw.example.org", "hoch", "npm"), ("cloud.example.org", "mittel", "npm")}
    certs[1]["expires_on"] = iso(89)   # erneuert
    certs[3]["expires_on"] = iso(90)
    connectors.refresh_npm(ctx)
    with ctx.session_factory() as s:
        assert s.scalar(select(Finding).where(Finding.status == "open")) is None


def test_certificate_rule():
    from app.rules import classify_certificate

    assert [classify_certificate(d) for d in (40, 19.9, 6.9, -3)] == [None, "mittel", "hoch", "hoch"]


def test_fetch_never_keeps_certificate_meta(monkeypatch):
    from app import connectors

    answers = {"/api/tokens": {"token": "t"},
               "/api/nginx/proxy-hosts": [{"domain_names": ["a.example.org"], "forward_host": "x", "forward_port": 80,
                                           "certificate_id": 7, "enabled": 1}],
               "/api/nginx/certificates": [{"id": 7, "nice_name": "a", "domain_names": ["a.example.org"], "provider": "letsencrypt",
                                            "expires_on": "2027-01-01 00:00:00",
                                            "meta": {"dns_provider_credentials": "dns_cloudflare_api_token = GEHEIM"}}]}
    monkeypatch.setattr(connectors, "_call", lambda base, path, token=None, body=None: answers[path])
    hosts, certs = connectors.fetch_npm("http://npm.lan:81", "a@b.c", "pw")
    assert hosts[0]["certificate_id"] == 7 and "GEHEIM" not in json.dumps(certs) and "meta" not in certs[0]


def test_untagged_images_name_the_containers_and_the_recreate_command():
    import json as _json

    from app.models import System
    from app.products import _untagged

    sys = System(name="host-a", inventory_json=_json.dumps({"containers": [
        {"name": "deploy-server-1", "labels": {"com.docker.compose.project.working_dir": "/srv/vw/deploy",
                                               "com.docker.compose.service": "server"}},
        {"name": "deploy-announce-1", "labels": {"com.docker.compose.project.working_dir": "/srv/vw/deploy",
                                                 "com.docker.compose.service": "announce"}}]}))
    names, detail = _untagged(sys, ["deploy-server-1", "deploy-announce-1"])
    assert names == "deploy-server-1, deploy-announce-1"
    assert detail.endswith("cd /srv/vw/deploy && docker compose up -d --force-recreate announce server")
    assert _untagged(System(name="x", inventory_json="{}"), ["plain"])[1].endswith("(a restart is not enough)")



def test_podman_fq_name_same_as_docker():
    from app.freshness import parse_ref

    assert parse_ref("docker.io/library/nginx:latest") == parse_ref("nginx:latest")
    assert parse_ref("docker.io/linuxserver/plex:1.40") == parse_ref("linuxserver/plex:1.40")
    assert parse_ref("index.docker.io/library/postgres:16")[0] == parse_ref("postgres:16")[0]


def test_localhost_image_no_version_check():
    from app.freshness import check

    class NoRegistry:
        def __getattr__(self, name):
            raise AssertionError("no registry request for localhost/ images")

    status, running, newer, detail = check("localhost/myapp:latest", [], "sha256:1", "amd64", "", NoRegistry(), {})
    assert (status, detail) == ("local", "built locally (localhost/), no version check")
