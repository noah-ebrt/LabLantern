"""KI-Anbieter: Einrichtung, Wahl je Aufgabe, automatische Auflösung und /api/ai (mit Fake-Clients über die Factories)."""
import json
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from app import aiproviders
from app.aibase import AiError
from app.models import AuditLog

AKEY = "sk-ant-api03-GEHEIMER-TESTSCHLUESSEL-0123456789abcdef"
OKEY = "sk-proj-GEHEIMER-OPENAI-SCHLUESSEL-0123456789abcdef"
SECRETS = {"anthropic": ("claude.api_key", AKEY), "openai": ("openai.api_key", OKEY)}
ANTHROPIC_MODELS = ["claude-haiku-5-5", "claude-sonnet-5-5"]   # aufsteigend nach Alter
OPENAI_MODELS = ["gpt-5.2", "gpt-5.2-mini", "text-embedding-3-large"]


def sdk_error(status):
    import anthropic
    import httpx2

    resp = httpx2.Response(status, request=httpx2.Request("GET", "https://api.anthropic.com/v1/models"))
    kind = {401: anthropic.AuthenticationError}.get(status, anthropic.InternalServerError)
    return kind("x", response=resp, body={"error": {"message": "nope"}})


class FakeAnthropic:
    """Fake des anthropic-Clients (ctx.claude_factory): Modellliste, Schlüsselprüfung, Aufrufe."""

    def __init__(self, ids=ANTHROPIC_MODELS, valid=AKEY, fail=None):
        self.ids, self.valid, self.fail, self.keys, self.listed = list(ids), valid, fail, [], 0
        self.api_key = None
        self.models = SimpleNamespace(list=self._list)

    def __call__(self, key):
        self.keys.append(key)
        self.api_key = key
        return self

    def _list(self, limit=100):
        self.listed += 1
        if self.fail:
            raise sdk_error(self.fail)
        if self.api_key != self.valid:
            raise sdk_error(401)
        return [SimpleNamespace(id=i, display_name=i.title(), created_at=datetime(2026, 1 + n, 1, tzinfo=timezone.utc))
                for n, i in enumerate(self.ids)]


class FakeOpenAI:
    """Fake des openai-Clients (ctx.openai_factory(base_url, key)): ein Client je Aufruf, merkt sich Adresse und Schlüssel."""

    def __init__(self, ids=OPENAI_MODELS, fail=None):
        self.ids, self.fail, self.calls, self.listed = list(ids), fail, [], 0

    def __call__(self, base_url, key):
        self.calls.append((base_url, key))
        return SimpleNamespace(api_key=key, models=SimpleNamespace(list=self._list))

    def _list(self):
        import openai
        import httpx2

        self.listed += 1
        if self.fail:
            req = httpx2.Request("GET", "http://x/v1/models")
            raise openai.APIStatusError("x", response=httpx2.Response(self.fail, request=req),
                                        body={"error": {"message": "broken"}})
        return [SimpleNamespace(id=i, created=1_700_000_000 + n) for n, i in enumerate(self.ids)]


@pytest.fixture
def fakes(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.claude_factory, ctx.openai_factory = FakeAnthropic(), FakeOpenAI()
    return env, client, h, ctx


def put(client, h, pid, **body):
    return client.put(f"/api/ai/providers/{pid}", json=body, headers=h)


def tasks_of(client):
    return client.get("/api/ai").json()["tasks"]


def test_endpoints_require_login_and_admin(admin):
    env, client, h = admin
    anon = env.new_client()
    assert anon.get("/api/ai").status_code == 401
    assert client.put("/api/ai/providers/anthropic", json={"api_key": AKEY}).status_code == 403
    assert client.delete("/api/ai/providers/anthropic").status_code == 403
    assert client.post("/api/ai/providers/anthropic/test").status_code == 403
    assert client.post("/api/ai/providers/anthropic/refresh").status_code == 403
    assert client.put("/api/ai/tasks", json={}).status_code == 403
    # Leser (kein Admin) dürfen nur lesen: ein Fremder ohne Sitzung schon nicht
    assert anon.put("/api/ai/tasks", json={}).status_code in (401, 403)


def test_unconfigured_state(fakes):
    env, client, h, ctx = fakes
    body = client.get("/api/ai").json()
    assert [(p["id"], p["configured"], p["models"]) for p in body["providers"]] == [
        ("anthropic", False, []), ("openai", False, []), ("c1", False, [])]
    assert body["providers"][0]["key"] == {"set": False, "updated_at": None}
    assert {t: v["error"] for t, v in body["tasks"].items()} == {
        "classify": "no AI provider configured", "research": "no AI provider configured",
        "verify": "no AI provider configured"}
    assert all(v["ref"] == "" and v["resolved"] is None for v in body["tasks"].values())
    assert aiproviders.any_configured(ctx) is False and aiproviders.providers(ctx) == {}


def test_get_shape_with_all_three_providers(fakes):
    env, client, h, ctx = fakes
    put(client, h, "anthropic", api_key=AKEY)
    put(client, h, "openai", api_key=OKEY)
    put(client, h, "c1", base_url="http://10.0.0.5:11434/v1", name="Ollama")
    body = client.get("/api/ai").json()
    assert set(body) == {"providers", "tasks"}
    a, o, c = body["providers"]
    assert (a["id"], a["kind"], a["label"], a["configured"]) == ("anthropic", "anthropic", "Anthropic", True)
    assert a["key"]["set"] is True and a["last_used"] is None and "display_url" not in a
    assert a["models"] == [{"id": "claude-sonnet-5-5", "name": "Claude-Sonnet-5-5", "web": True},
                           {"id": "claude-haiku-5-5", "name": "Claude-Haiku-5-5", "web": True}]
    assert [(m["id"], m["web"]) for m in o["models"]] == [("gpt-5.2-mini", True), ("gpt-5.2", True)]
    assert (c["kind"], c["label"], c["display_url"]) == ("compat", "Ollama", "http://10.0.0.5:11434/v1")
    assert c["key"] == {"set": False, "updated_at": None}
    assert body["tasks"]["classify"] == {"ref": "", "resolved": "anthropic:claude-haiku-5-5", "error": None}


def test_automatic_prefers_anthropic(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    put(client, h, "anthropic", api_key=AKEY)
    t = tasks_of(client)
    assert t["classify"]["resolved"] == "anthropic:claude-haiku-5-5"
    assert t["research"]["resolved"] == t["verify"]["resolved"] == "anthropic:claude-sonnet-5-5"
    provider, model = aiproviders.resolve(ctx, "classify")
    assert (provider.pid, model) == ("anthropic", "claude-haiku-5-5")


def test_automatic_uses_openai_without_anthropic(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    t = tasks_of(client)
    assert t["classify"]["resolved"] == "openai:gpt-5.2-mini"
    assert t["research"]["resolved"] == t["verify"]["resolved"] == "openai:gpt-5.2"


def test_openai_without_a_matching_model_has_no_automatic_choice(fakes):
    env, client, h, ctx = fakes
    ctx.openai_factory = FakeOpenAI(ids=["o3"])
    put(client, h, "openai", api_key=OKEY)
    t = tasks_of(client)
    assert t["classify"]["error"] == t["research"]["error"] == "choose a model (no automatic choice for this provider)"


def test_only_compat_needs_explicit_classify_and_has_no_web_tasks(fakes):
    env, client, h, ctx = fakes
    ctx.openai_factory = FakeOpenAI(ids=["llama3.2:3b", "qwen3.8:27b"])
    put(client, h, "c1", base_url="http://10.0.0.5:11434/v1")
    t = tasks_of(client)
    assert t["classify"]["error"] == "choose a model (no automatic choice for this provider)"
    assert t["research"]["error"] == t["verify"]["error"] == "needs a provider with web search"
    assert client.put("/api/ai/tasks", headers=h, json={"classify": "c1:llama3.2:3b"}).status_code == 200
    assert tasks_of(client)["classify"] == {"ref": "c1:llama3.2:3b", "resolved": "c1:llama3.2:3b", "error": None}


def test_ollama_model_id_with_colon_resolves(fakes):
    env, client, h, ctx = fakes
    ctx.openai_factory = FakeOpenAI(ids=["qwen3.8:27b"])
    put(client, h, "c1", base_url="http://10.0.0.5:11434/v1", name="Ollama")
    assert client.put("/api/ai/tasks", headers=h, json={"classify": "c1:qwen3.8:27b"}).status_code == 200
    provider, model = aiproviders.resolve(ctx, "classify")
    assert (provider.pid, provider.label, model) == ("c1", "Ollama", "qwen3.8:27b")


def test_web_task_rejects_compat_and_non_web_models(fakes):
    env, client, h, ctx = fakes
    ctx.claude_factory = FakeAnthropic(ids=["claude-3-haiku-20240307", "claude-sonnet-5-5"])
    ctx.openai_factory = FakeOpenAI(ids=["gpt-5.2", "gpt-5-nano"])
    put(client, h, "anthropic", api_key=AKEY)
    put(client, h, "openai", api_key=OKEY)
    put(client, h, "c1", base_url="http://10.0.0.5:11434/v1")
    ok = {"classify": "", "research": "anthropic:claude-sonnet-5-5", "verify": "openai:gpt-5.2"}
    assert client.put("/api/ai/tasks", headers=h, json=ok).status_code == 200
    for task, ref in [("research", "c1:whatever"), ("verify", "anthropic:claude-3-haiku-20240307"),
                      ("research", "openai:gpt-5-nano")]:
        r = client.put("/api/ai/tasks", headers=h, json={**ok, task: ref})
        assert r.status_code == 422, (task, ref)
    # Klassifizieren darf alles: auch ein Modell ohne Websuche und der eigene Endpunkt
    assert client.put("/api/ai/tasks", headers=h, json={**ok, "classify": "anthropic:claude-3-haiku-20240307"}).status_code == 200
    assert tasks_of(client)["research"]["ref"] == "anthropic:claude-sonnet-5-5"   # die 422er haben nichts verändert


def test_tasks_reject_unconfigured_and_unknown_models(fakes):
    env, client, h, ctx = fakes
    put(client, h, "anthropic", api_key=AKEY)
    for ref in ("openai:gpt-5.2", "anthropic:claude-nope-1", "bogus:x", "anthropic:", "anthropic"):
        assert client.put("/api/ai/tasks", headers=h, json={"classify": ref}).status_code == 422, ref


def test_unreachable_provider_accepts_any_sane_model_id(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    ctx.openai_factory = FakeOpenAI(fail=500)
    assert client.put("/api/ai/tasks", headers=h, json={"classify": "openai:gpt-9-mini"}).status_code == 200
    assert client.put("/api/ai/tasks", headers=h, json={"research": "openai:gpt-5.9"}).status_code == 200
    assert client.put("/api/ai/tasks", headers=h, json={"research": "openai:o1-mini"}).status_code == 422   # kein Websuch-Modell
    assert client.put("/api/ai/tasks", headers=h, json={"classify": "openai:" + "x" * 201}).status_code == 422
    assert client.put("/api/ai/tasks", headers=h, json={"classify": "openai:gpt\x00"}).status_code == 422


def test_removed_provider_task_reports_error(fakes):
    env, client, h, ctx = fakes
    put(client, h, "anthropic", api_key=AKEY)
    put(client, h, "openai", api_key=OKEY)
    assert client.put("/api/ai/tasks", headers=h, json={"classify": "openai:gpt-5.2-mini", "research": "", "verify": ""}).status_code == 200
    assert client.delete("/api/ai/providers/openai", headers=h).status_code == 200
    t = tasks_of(client)
    assert t["classify"] == {"ref": "openai:gpt-5.2-mini", "resolved": None, "error": "no model — provider removed"}
    assert t["research"]["resolved"] == "anthropic:claude-sonnet-5-5"   # Automatisch bleibt unberührt
    with pytest.raises(AiError, match="no model — provider removed"):
        aiproviders.resolve(ctx, "classify")


def test_delete_removes_secrets_cache_and_last_used_but_keeps_task_refs(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    client.get("/api/ai")
    provider, model = aiproviders.resolve(ctx, "classify")
    aiproviders.record_use(ctx, provider, "classify", model, True)
    client.put("/api/ai/tasks", headers=h, json={"classify": "openai:gpt-5.2-mini"})
    client.delete("/api/ai/providers/openai", headers=h)
    assert ctx.secrets.get("openai.api_key") is None
    with ctx.session_factory() as s:
        keys = {r[0] for r in s.execute(text("select key from settings"))}
    assert not {"ai.models.openai", "ai.last_used.openai"} & keys and "ai.tasks" in keys
    assert client.get("/api/ai").json()["providers"][1]["last_used"] is None


def test_record_use(fakes):
    env, client, h, ctx = fakes
    put(client, h, "anthropic", api_key=AKEY)
    provider, model = aiproviders.resolve(ctx, "classify")
    aiproviders.record_use(ctx, provider, "classify", model, False, "Anthropic: boom (HTTP 500)")
    last = client.get("/api/ai").json()["providers"][0]["last_used"]
    assert {k: last[k] for k in ("task", "model", "ok", "error")} == {
        "task": "classify", "model": "claude-haiku-5-5", "ok": False, "error": "Anthropic: boom (HTTP 500)"}
    assert last["at"]
    aiproviders.record_use(ctx, provider, "research", model, True)
    assert "error" not in client.get("/api/ai").json()["providers"][0]["last_used"]


def test_models_are_cached_for_24h_and_refresh_forces_a_reload(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    client.get("/api/ai"); client.get("/api/ai")
    assert ctx.openai_factory.listed == 1
    r = client.post("/api/ai/providers/openai/refresh", headers=h)
    assert r.status_code == 200 and [m["id"] for m in r.json()["models"]] == ["gpt-5.2-mini", "gpt-5.2"]
    assert ctx.openai_factory.listed == 2


def test_failed_refresh_keeps_the_old_list(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    client.get("/api/ai")
    ctx.openai_factory.fail = 500
    r = client.post("/api/ai/providers/openai/refresh", headers=h)
    assert [m["id"] for m in r.json()["models"]] == ["gpt-5.2-mini", "gpt-5.2"]


def test_anthropic_list_is_filtered_to_claude_ids(fakes):
    env, client, h, ctx = fakes
    ctx.claude_factory = FakeAnthropic(ids=["claude-haiku-5-5", "not a model", "claude-opus-5-5"])
    put(client, h, "anthropic", api_key=AKEY)
    assert [m["id"] for m in client.get("/api/ai").json()["providers"][0]["models"]] == ["claude-opus-5-5", "claude-haiku-5-5"]


def test_refresh_and_test_need_a_configured_provider(fakes):
    env, client, h, ctx = fakes
    assert client.post("/api/ai/providers/openai/test", headers=h).status_code == 409
    assert client.post("/api/ai/providers/openai/refresh", headers=h).status_code == 409
    assert client.post("/api/ai/providers/nope/test", headers=h).status_code == 404
    assert put(client, h, "nope", api_key=OKEY).status_code == 404
    assert client.delete("/api/ai/providers/nope", headers=h).status_code == 404


def test_test_button_reports_ok_and_a_wrong_key_without_echoing_it(fakes):
    env, client, h, ctx = fakes
    put(client, h, "anthropic", api_key=AKEY)
    assert client.post("/api/ai/providers/anthropic/test", headers=h).json() == {"ok": True}
    wrong = "sk-ant-api03-FALSCH-" + "y" * 30
    put(client, h, "anthropic", api_key=wrong)
    body = client.post("/api/ai/providers/anthropic/test", headers=h).json()
    assert body["ok"] is False and "401" in body["error"] and wrong not in json.dumps(body)


def test_test_button_reports_server_errors_of_openai(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    ctx.openai_factory.fail = 500
    body = client.post("/api/ai/providers/openai/test", headers=h).json()
    assert body == {"ok": False, "error": "OpenAI: broken (HTTP 500)"}


@pytest.mark.parametrize("pid", ["anthropic", "openai"])
def test_save_stores_the_key_encrypted_and_never_returns_it(fakes, pid):
    env, client, h, ctx = fakes
    name, key = SECRETS[pid]
    r = put(client, h, pid, api_key=key)
    assert r.status_code == 200 and key not in r.text
    got = client.get("/api/ai")
    row = next(p for p in got.json()["providers"] if p["id"] == pid)
    assert row["configured"] is True and row["key"]["set"] is True and key not in got.text
    assert ctx.secrets.get(name) == key


@pytest.mark.parametrize("pid,bad", [
    ("anthropic", ""), ("anthropic", "kurz"), ("anthropic", "mit leerzeichen " + "x" * 30),
    ("anthropic", "x" * 500), ("anthropic", "zeilen\numbruch" + "x" * 30),
    ("openai", ""), ("openai", "kurz"), ("openai", "sk-" + "x" * 5), ("openai", "ant-" + "x" * 30),
    ("openai", "sk-mit leerzeichen" + "x" * 30), ("openai", "sk-" + "x" * 400)])
def test_malformed_keys_are_rejected(fakes, pid, bad):
    env, client, h, ctx = fakes
    assert put(client, h, pid, api_key=bad).status_code == 422
    assert ctx.secrets.get(SECRETS[pid][0]) is None


def test_first_save_needs_a_key_but_a_later_save_may_omit_it(fakes):
    env, client, h, ctx = fakes
    assert put(client, h, "anthropic").status_code == 422
    assert put(client, h, "anthropic", api_key=AKEY).status_code == 200
    assert put(client, h, "anthropic").status_code == 200
    assert ctx.secrets.get("claude.api_key") == AKEY


@pytest.mark.parametrize("pid", ["anthropic", "openai"])
def test_validation_errors_never_echo_the_submitted_secret(fakes, pid):
    env, client, h, ctx = fakes
    r = put(client, h, pid, api_key="mit leerzeichen GEHEIMER-SCHLUESSEL-TEIL " + "x" * 30)
    assert r.status_code == 422 and "GEHEIMER-SCHLUESSEL-TEIL" not in r.text
    assert r.json()["detail"][0]["loc"][-1] == "api_key"          # Feldname und Grund bleiben sichtbar
    r = put(client, h, pid, api_key="GEHEIMER-SCHLUESSEL-TEIL" + "x" * 700)   # zu lang für das Feld selbst
    assert r.status_code == 422 and "GEHEIMER-SCHLUESSEL-TEIL" not in r.text


@pytest.mark.parametrize("pid", ["anthropic", "openai"])
def test_key_is_nowhere_readable_after_all_operations(fakes, caplog, pid):
    """Abnahme-Kriterium wie beim SMTP-Passwort: nicht in API, Datenbank, Dateien, Logs, Audit-Log."""
    env, client, h, ctx = fakes
    name, key = SECRETS[pid]
    second = "sk-proj-ZWEITER-" + "z" * 30 if pid == "openai" else "sk-ant-api03-ZWEITER-" + "z" * 30
    with caplog.at_level(logging.DEBUG):
        put(client, h, pid, api_key=key)
        client.post(f"/api/ai/providers/{pid}/test", headers=h)
        put(client, h, pid, api_key=second)
        client.post(f"/api/ai/providers/{pid}/test", headers=h)
        client.post(f"/api/ai/providers/{pid}/refresh", headers=h)
        put(client, h, pid, api_key=key)
        seen = [client.get(p).text for p in ("/api/state", "/api/overview", "/api/ai")]
        with ctx.session_factory() as s:
            s.execute(text("PRAGMA wal_checkpoint(PASSIVE)"))
            seen.append("\n".join(s.connection().connection.iterdump()))
            seen.append(repr([(a.actor, a.action, a.detail) for a in s.scalars(select(AuditLog))]))
            actions = [a.action for a in s.scalars(select(AuditLog))]
        for f in env.data_dir.rglob("*"):
            if f.is_file() and f.name != "master.key":
                seen.append(f.read_bytes().decode("latin-1"))
        seen.append(caplog.text)
    blob = "\n".join(seen)
    assert key not in blob and "ZWEITER" not in blob
    assert {"ai.provider.saved", "ai.provider.tested"} <= set(actions)


def test_custom_url_is_shown_cleaned_and_never_echoed(fakes, caplog):
    env, client, h, ctx = fakes
    raw = "http://u:pw@10.0.0.5:11434/v1?token=x"
    with caplog.at_level(logging.DEBUG):
        r = put(client, h, "c1", base_url=raw, api_key="ollama-key-GEHEIM", name="Ollama")
        assert r.status_code == 200
        got = client.get("/api/ai")
        row = got.json()["providers"][2]
        assert row["display_url"] == "http://10.0.0.5:11434/v1" and row["label"] == "Ollama"
        assert row["key"]["set"] is True
        client.post("/api/ai/providers/c1/test", headers=h)
        client.post("/api/ai/providers/c1/refresh", headers=h)
        bad = put(client, h, "c1", base_url="ftp://u:pw@host/?token=x")
        seen = [r.text, got.text, bad.text, caplog.text]
        with ctx.session_factory() as s:
            seen.append("\n".join(s.connection().connection.iterdump()))
            seen.append(repr([(a.actor, a.action, a.detail) for a in s.scalars(select(AuditLog))]))
    blob = "\n".join(seen)
    for secret in ("pw", "token=x", "ollama-key-GEHEIM"):
        # "pw" kommt in anderen Wörtern vor: nur die Zugangsform zählt
        needle = "u:pw@" if secret == "pw" else secret
        assert needle not in blob, needle
    assert ctx.secrets.get("compat.c1.url") == raw   # die volle Adresse liegt nur verschlüsselt vor
    assert ctx.openai_factory.calls[-1] == (raw, "ollama-key-GEHEIM")


@pytest.mark.parametrize("bad", ["", "ftp://host/v1", "host:11434/v1", "http:///v1", "http://", "javascript:alert(1)",
                                 "http://host:99999/v1", "http://[::1/v1", "http://host/" + "x" * 500])
def test_compat_url_must_be_http_with_a_host(fakes, bad):
    env, client, h, ctx = fakes
    assert put(client, h, "c1", base_url=bad).status_code == 422
    assert client.get("/api/ai").json()["providers"][2]["configured"] is False


def test_compat_first_save_needs_a_url_and_later_saves_keep_what_is_omitted(fakes):
    env, client, h, ctx = fakes
    assert put(client, h, "c1", name="Ollama").status_code == 422
    assert put(client, h, "c1", base_url="https://llm.example.org:8443/v1", api_key="k1" * 5).status_code == 200
    row = client.get("/api/ai").json()["providers"][2]
    assert row["label"] == "llm.example.org" and row["display_url"] == "https://llm.example.org:8443/v1"   # Name = Host
    assert put(client, h, "c1", name="Mein LLM").status_code == 200
    row = client.get("/api/ai").json()["providers"][2]
    assert row["label"] == "Mein LLM" and row["display_url"] == "https://llm.example.org:8443/v1" and row["key"]["set"]
    assert put(client, h, "c1", api_key="").status_code == 200   # leer = Schlüssel entfernen
    assert client.get("/api/ai").json()["providers"][2]["key"]["set"] is False
    assert put(client, h, "c1", name="x" * 61).status_code == 422
    assert put(client, h, "c1", name="a\nb").status_code == 422


def test_saving_a_new_key_reloads_the_model_list(fakes):
    env, client, h, ctx = fakes
    put(client, h, "openai", api_key=OKEY)
    client.get("/api/ai")
    put(client, h, "openai", api_key="sk-" + "n" * 30)
    client.get("/api/ai")
    assert ctx.openai_factory.listed == 2
    assert ctx.openai_factory.calls[-1][1] == "sk-" + "n" * 30


def test_writes_are_audited_without_secrets(fakes):
    env, client, h, ctx = fakes
    put(client, h, "anthropic", api_key=AKEY)
    client.put("/api/ai/tasks", headers=h, json={"classify": "anthropic:claude-haiku-5-5"})
    client.delete("/api/ai/providers/anthropic", headers=h)
    with ctx.session_factory() as s:
        rows = [(a.action, a.detail) for a in s.scalars(select(AuditLog)) if a.action.startswith("ai.")]
    assert [a for a, _ in rows] == ["ai.provider.saved", "ai.tasks", "ai.provider.removed"]
    assert "classify=anthropic:claude-haiku-5-5" in rows[1][1] and AKEY not in repr(rows)


def test_configdoc_writes_the_claude_key_through_the_new_route(fakes):
    env, client, h, ctx = fakes
    doc = client.get("/api/settings/config").json()
    assert client.put("/api/settings/config", headers=h, json=doc).status_code == 200   # unverändert: nichts zu tun
    doc["claude"] = {"model": None, "api_key": AKEY}
    r = client.put("/api/settings/config", headers=h, json=doc)
    assert r.status_code == 200 and ctx.secrets.get("claude.api_key") == AKEY
