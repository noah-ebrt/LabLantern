"""Collector-API v1 (PLAN-extensions C): Geräte ohne Agent melden Pakete und Container. Nur Annahme, nie Befehle."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.collector_api import CollectorReport, MAX_BODY
from app.coverage import calculate_coverage_matrix
from app.models import System
from app.scanrun import image_sbom_path, sbom_path
from tests.test_scan_flow import ctx  # noqa: F401 (Fixture)

FIX = Path(__file__).parent / "fixtures"
EXAMPLES = sorted(FIX.glob("collector-*.json"))
SCHEMA = Path(__file__).parents[2] / "docs" / "collector-schema.json"


def example(name="openwrt"):
    return json.loads((FIX / f"collector-{name}.json").read_text())


def new_collector(admin, name="router"):
    _, client, h = admin
    r = client.post("/api/collector/systems", json={"name": name}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def post(env, token, body):
    return env.new_client().post("/api/collector/v1/report", json=body, headers={"Authorization": f"Bearer {token}"})


def system(env, sid):
    with env.app.state.ctx.session_factory() as s:
        return s.get(System, sid)


def row(env, sid, **kw):
    with env.app.state.ctx.session_factory() as s:
        m = calculate_coverage_matrix(s, **kw)
    return next(r for r in m["systems"] if r["system_id"] == sid), m


def test_schema_validates_examples():
    assert len(EXAMPLES) == 3
    schema = json.loads(SCHEMA.read_text())
    for path in EXAMPLES:
        CollectorReport.model_validate_json(path.read_text())
    # Schema-Datei und Pydantic-Modell beschreiben dieselben Felder
    model = CollectorReport.model_json_schema(by_alias=True)
    assert set(schema["properties"]) == set(model["properties"])
    assert set(schema["required"]) == set(model["required"])
    for name, ref in (("os", "OsIn"), ("packages", "PackageIn"), ("containers", "ContainerIn")):
        part = schema["$defs"][name]
        assert set(part["properties"]) == set(model["$defs"][f"Collector{ref}"]["properties"]), name
        assert set(part.get("required", [])) == set(model["$defs"][f"Collector{ref}"].get("required", [])), name


def test_token_bound_to_system(admin):
    env, _, _ = admin
    a, b = new_collector(admin, "router"), new_collector(admin, "nas")
    assert post(env, a["token"], example()).status_code == 200
    assert system(env, a["id"]).last_seen is not None
    assert system(env, b["id"]).last_seen is None
    assert post(env, "wrong", example()).status_code == 401
    # Ein Collector-Token öffnet keine Agenten-Endpunkte und umgekehrt
    r = env.new_client().post("/api/agent/poll", headers={"Authorization": f"Bearer {b['token']}"})
    assert r.status_code == 401
    # neues Token: das alte gilt nicht mehr
    _, client, h = admin
    fresh = client.post(f"/api/collector/systems/{b['id']}/token", headers=h).json()["token"]
    assert post(env, b["token"], example()).status_code == 401
    assert post(env, fresh, example()).status_code == 200


def test_revoked_collector_is_403(admin):
    env, client, h = admin
    c = new_collector(admin)
    assert client.post(f"/api/systems/{c['id']}/revoke", headers=h).status_code == 200
    assert post(env, c["token"], example()).status_code == 403


def test_limits_413_429(admin):
    env, _, _ = admin
    c = new_collector(admin)
    big = example()
    big["packages"] = [{"ecosystem": "opkg", "name": f"p{i}", "version": "1" * 300} for i in range(20_000)]
    assert len(json.dumps(big)) > MAX_BODY
    assert post(env, c["token"], big).status_code == 413
    many = example()
    many["packages"] = [{"ecosystem": "opkg", "name": f"p{i}", "version": "1"} for i in range(20_001)]
    assert post(env, c["token"], many).status_code == 422
    assert post(env, c["token"], example()).status_code == 200
    r = post(env, c["token"], example())
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_no_command_in_response(admin):
    env, _, _ = admin
    c = new_collector(admin)
    r = post(env, c["token"], example("unraid"))
    assert r.json() == {"ok": True}


def test_missing_parts_are_na(admin):
    env, _, _ = admin
    c = new_collector(admin)
    assert post(env, c["token"], example("openwrt")).status_code == 200
    assert sbom_path(env.app.state.ctx, c["id"]).is_file()   # immer eine Host-SBOM: der Worker scannt wie gewohnt
    r, m = row(env, c["id"])
    checks = r["checks"]
    assert checks["sicherheitsupdates"]["status"] == "na"
    assert checks["reboot"]["status"] == "na"
    assert checks["container"]["status"] == "na" and checks["images"]["status"] == "na"
    # opkg-Pakete kennt keine Schwachstellen-Datenbank: n/a mit Grund, nie ok
    assert checks["paket_cve"]["status"] == "na" and "opkg" in checks["paket_cve"]["detail"]
    assert m["total_checks"] == sum(c["status"] != "na" for c in checks.values())


def test_scannable_packages_get_purls(admin):
    env, _, _ = admin
    c = new_collector(admin)
    assert post(env, c["token"], example("unraid")).status_code == 200
    sbom = json.loads(sbom_path(env.app.state.ctx, c["id"]).read_text())
    purls = [x.get("purl") for x in sbom["components"] if x["type"] == "library"]
    assert purls == ["pkg:pypi/requests@2.31.0"]   # Slackware-Pakete hätten keinen Abgleich
    r, _ = row(env, c["id"])
    assert r["checks"]["paket_cve"]["status"] != "na"


def test_stale_24h_error(admin):
    env, _, _ = admin
    c = new_collector(admin)
    assert post(env, c["token"], example("unraid")).status_code == 200
    with env.app.state.ctx.session_factory() as s:
        s.get(System, c["id"]).last_seen = datetime.now(timezone.utc) - timedelta(hours=25)
        s.commit()
    r, _ = row(env, c["id"])
    assert r["checks"]["paket_cve"]["status"] == "fehler"
    assert "24 h" in r["checks"]["paket_cve"]["detail"]


def test_container_without_sbom_na_hint(admin):
    env, _, _ = admin
    ctx = env.app.state.ctx
    c = new_collector(admin)
    assert post(env, c["token"], example("synology")).status_code == 200
    has = lambda sid, iid: image_sbom_path(ctx, sid, iid).is_file()   # noqa: E731
    r, _ = row(env, c["id"], image_has_sbom=has)
    images = r["checks"]["images"]
    assert images["status"] == "na" and "install syft on the device" in images["detail"]
    assert r["checks"]["container"]["status"] == "ok"


def test_container_sbom_stored(admin):
    env, _, _ = admin
    ctx = env.app.state.ctx
    c = new_collector(admin)
    body = example("unraid")
    assert post(env, c["token"], body).status_code == 200
    iid = body["containers"][0]["image_id"]
    assert json.loads(image_sbom_path(ctx, c["id"], iid).read_text())["bomFormat"] == "CycloneDX"
    bad = example("unraid")
    bad["containers"][0]["sbom"] = {"artifacts": []}   # Syft-JSON: nur CycloneDX wird angenommen
    c2 = new_collector(admin, "nas")
    r = post(env, c2["token"], bad)
    assert r.status_code == 422 and "CycloneDX" in r.text


def test_create_requires_admin_and_unique_name(admin):
    env, client, h = admin
    new_collector(admin, "router")
    assert client.post("/api/collector/systems", json={"name": "router"}, headers=h).status_code == 409
    assert env.new_client().post("/api/collector/systems", json={"name": "x"}).status_code in (401, 403)


@pytest.mark.parametrize("name", ["openwrt", "synology", "unraid"])
def test_collector_ready_for_scan_without_poke(admin, name):
    """Nach „Scan now“ wartet der Lauf auf frische Agenten. Ein Collector lässt sich nicht anstoßen: Sein
    Report der letzten 24 h genügt, sonst hinge jeder Lauf bis zur Wartezeit."""
    from app.scanrun import _system_ready
    env, _, _ = admin
    ctx = env.app.state.ctx
    c = new_collector(admin)
    assert post(env, c["token"], example(name)).status_code == 200
    with ctx.session_factory() as s:
        assert _system_ready(ctx, s, s.get(System, c["id"]), datetime.now(timezone.utc) + timedelta(minutes=1))


def test_distro_packages_only_for_known_distros():
    """apk auf OpenWrt oder deb auf einem unbekannten System: Grype hat dafür keine Advisories. Abgleichbar zu
    melden hieße "0 Funde" statt n/a, eine stille Lücke."""
    from app.sbom import collector_purl
    pkg = {"ecosystem": "apk", "name": "busybox", "version": "1.36.1-r2"}
    assert collector_purl(pkg, "openwrt", "24.10.0") is None
    assert collector_purl(pkg, "alpine", "3.20.3") == "pkg:apk/alpine/busybox@1.36.1-r2?distro=alpine-3.20.3"
    assert collector_purl({**pkg, "ecosystem": "deb"}, "dsm", "7.2") is None
    assert collector_purl({**pkg, "ecosystem": "deb"}, "debian", "12").startswith("pkg:deb/debian/busybox@")
    assert collector_purl({**pkg, "purl": "pkg:apk/openwrt/busybox@1.36.1-r2"}, "openwrt", "24.10.0") is None
