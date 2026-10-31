"""Alarm bei starkem Rückgang der Funde, Konfiguration als JSON-Dokument, Geräteversionen in der Frühwarnung."""
import json

from app.earlywarning import _matches, inventory_products
from app.integrity import DEFAULTS, is_sharp_drop
from app.models import System, put_setting, setting
from tests.test_scan_flow import ctx, make_system, raw, run_once  # noqa: F401 (Fixture)


def many(n):
    return [raw(cve=f"CVE-2024-{1000 + i}") for i in range(n)]


def test_sharp_drop_rule():
    assert is_sharp_drop(DEFAULTS, 40, 10)
    assert not is_sharp_drop(DEFAULTS, 40, 25)                 # unter 50 %
    assert not is_sharp_drop(DEFAULTS, 10, 0)                  # kleiner Host, schwankt
    assert not is_sharp_drop({**DEFAULTS, "enabled": False}, 40, 0)


def test_sharp_drop_raises_an_immediate_alert(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, many(30), None)])
    run_once(ctx, [(sid, many(3), None)])
    subject, body = ctx.notifier.sent[-1]
    assert subject.startswith("[IMMEDIATE ALERT]") and "dropped sharply" in subject and "(30 → 3)" in subject
    assert "check the host's SBOM and the worker" in body


def test_sharp_drop_can_be_switched_off(ctx):
    with ctx.session_factory() as s:
        put_setting(s, "alerts.finding_drop", {**DEFAULTS, "enabled": False})
        s.commit()
    sid = make_system(ctx)
    run_once(ctx, [(sid, many(30), None)])
    run_once(ctx, [(sid, [], None)])
    assert "dropped sharply" not in ctx.notifier.sent[-1][0]


def test_config_document_reads_without_secrets_and_writes_through_the_endpoints(admin):
    env, client, h = admin
    url = "ntfys://ntfy.sh/geheimes-thema-123"
    assert client.post("/api/integrations/notifications", headers=h, json={"name": "Push", "url": url}).status_code == 200
    doc = client.get("/api/settings/config").json()
    assert "geheimes-thema" not in json.dumps(doc)
    assert doc["notifications"] == [{"name": "Push", "url": None, "gets": "both"}]
    assert doc["finding_drop"] == DEFAULTS

    doc["schedule"]["time"] = "04:30"
    doc["finding_drop"]["percent"] = 70
    doc["notifications"].append({"name": "Mail", "url": "mailtos://u:p@mail.example.org"})
    r = client.put("/api/settings/config", headers=h, json=doc).json()
    assert r["ok"], r
    assert r["results"]["schedule"] == r["results"]["finding_drop"] == r["results"]["notifications"] == "saved"
    assert r["results"]["timezone"] == "unchanged"
    assert client.get("/api/settings/schedule").json()["time"] == "04:30"
    assert client.get("/api/settings/finding-drop").json()["percent"] == 70
    assert [c["name"] for c in client.get("/api/integrations/notifications").json()["channels"]] == ["Push", "Mail"]

    # entfernter Kanal wird gelöscht; ungültiger Abschnitt meldet den Fehler, ohne den Wert zu wiederholen
    r = client.put("/api/settings/config", headers=h, json={
        "notifications": [{"name": "Mail", "url": None}],
        "schedule": {"enabled": True, "time": "25:99"},
        "finding_drop": {"enabled": True, "percent": 5, "min_findings": 1},
        "nonsense": {}}).json()
    assert not r["ok"]
    assert r["results"]["notifications"] == "saved"
    assert r["results"]["schedule"].startswith("error") and r["results"]["finding_drop"].startswith("error: percent")
    assert r["results"]["nonsense"] == "error: unknown section"
    assert [c["name"] for c in client.get("/api/integrations/notifications").json()["channels"]] == ["Mail"]


def test_an_old_export_still_imports_research_and_claude(admin):
    """Exporte von vor den KI-Anbietern: `research` mit `model` und ohne `verify`, `claude` mit dem einen Modell."""
    env, client, h = admin
    ctx = env.app.state.ctx
    doc = client.get("/api/settings/config").json()
    assert doc["research"] == {"enabled": True, "verify": True} and doc["claude"] == {"model": None, "api_key": None}
    r = client.put("/api/settings/config", headers=h, json={
        "research": {"enabled": False, "model": "claude-sonnet-5-5"},
        "claude": {"model": "claude-haiku-5-5", "api_key": None}}).json()
    assert r["ok"], r
    assert r["results"]["research"] == r["results"]["claude"] == "saved"
    with ctx.session_factory() as s:
        assert setting(s, "ai.tasks") == {"classify": "anthropic:claude-haiku-5-5", "research": "", "verify": ""}
        assert setting(s, "earlywarning.research") == {"enabled": False, "verify": True}   # verify bleibt wie gespeichert
    assert r["config"]["claude"]["model"] == "claude-haiku-5-5"   # der Export bleibt lesbar und rund
    again = client.put("/api/settings/config", headers=h, json=r["config"]).json()
    assert again["results"]["claude"] == "unchanged"
    # ein leeres Modell heißt „automatisch“; die Wahl für research/verify bleibt unberührt
    with ctx.session_factory() as s:
        put_setting(s, "ai.tasks", {"classify": "anthropic:claude-haiku-5-5", "research": "anthropic:claude-sonnet-5-5",
                                    "verify": ""})
        s.commit()
    r = client.put("/api/settings/config", headers=h, json={"claude": {"model": None, "api_key": None}}).json()
    assert r["results"]["claude"] == "saved"
    with ctx.session_factory() as s:
        assert setting(s, "ai.tasks") == {"classify": "", "research": "anthropic:claude-sonnet-5-5", "verify": ""}
    # eine ungültige Kennung wird abgelehnt, ohne sie zu wiederholen
    r = client.put("/api/settings/config", headers=h, json={"claude": {"model": "evil model\n", "api_key": None}}).json()
    assert r["results"]["claude"] == "error: model: invalid model id"
    r = client.put("/api/settings/config", headers=h, json={"claude": {"model": "claude-haiku-5-5\n", "api_key": None}}).json()
    assert r["results"]["claude"] == "error: model: invalid model id"   # auch kein Zeilenende am Schluss


def test_config_document_needs_a_login(env):
    assert env.client.get("/api/settings/config").status_code in (401, 403)


def test_device_versions_feed_the_early_warning(ctx):
    with ctx.session_factory() as s:
        s.add(System(name="truenas", host_type="truenas", status="connector", inventory_json=json.dumps(
            {"connector": {"version": "25.04.2.4", "apps": [{"name": "plex", "version": "1.41.0"}]}})))
        s.add(System(name="homeassistant", host_type="homeassistant", status="connector", inventory_json=json.dumps(
            {"connector": {"version": "2026.10.1", "updates": [
                {"entity_id": "update.home_assistant_core_update", "name": "Home Assistant Core", "version": "2026.10.1"},
                {"entity_id": "update.home_assistant_operating_system_update", "name": "Home Assistant Operating System",
                 "version": "16.2"}]}})))
        s.commit()
        products = {(p["system"], p["keyword"]): p for p in inventory_products(s)}
    assert products[("truenas", "truenas")]["version"] == "25.04.2.4"
    assert products[("truenas", "plex")]["target"] == "app:plex"
    assert products[("homeassistant", "home assistant")]["version"] == "2026.10.1"
    assert _matches("Home Assistant", "home assistant")
    assert _matches("Home Assistant OS", "home assistant operating system")
