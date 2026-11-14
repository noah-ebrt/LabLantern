"""Anthropic-Adapter und die gemeinsame Fehlerkurzfassung. Einrichtung, Schlüsselgeheimnis und /api/ai: test_aiproviders.py."""
from app.aibase import short_error


def test_usage_limit_message_is_passed_through():
    body = {"error": {"type": "invalid_request_error", "message": "You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC."}}
    msg = short_error("Anthropic", 400, body, secret=None)
    assert msg == "Anthropic: You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC. (HTTP 400)"


def test_error_text_is_truncated_and_scrubbed():
    key = "sk-ant-api03-SECRET-0123456789abcdef"
    msg = short_error("OpenAI", 401, {"error": {"message": f"bad key {key} " + "x" * 600}}, secret=key)
    assert key not in msg and len(msg) <= 340 and msg.endswith("(HTTP 401)")


def test_anthropic_provider_delegates_ask_tool():
    from app import claude
    from tests.test_earlywarning import FACTS, Claude

    tool = {"name": "report", "description": "x", "input_schema": {"type": "object", "properties": {}}}
    fake = Claude()
    provider = claude.AnthropicProvider(fake)
    assert (provider.pid, provider.label, provider.web_search) == ("anthropic", "Anthropic", True)
    result = provider.ask_tool("claude-sonnet-5-5", "sys", "text", tool)
    assert result == claude.ask_tool(Claude(), "claude-sonnet-5-5", "sys", "text", tool)
    assert result[0] == FACTS


def test_anthropic_web_allow_list():
    from app.claude import anthropic_web

    assert anthropic_web("claude-sonnet-5-5") and anthropic_web("claude-haiku-5-5")
    assert anthropic_web("claude-opus-4-8") and anthropic_web("claude-haiku-4-5-20251001")
    assert not anthropic_web("claude-3-haiku-20240307")


def _research_fake(step):
    """Fake-Client: `step(params, asked)` liefert (stop_reason, Blöcke); asked = der Bericht wurde verlangt."""
    from types import SimpleNamespace

    calls = []

    def create(**params):
        calls.append(params)
        ask = params["messages"][-1]["content"]
        stop, content = step(params, isinstance(ask, str) and ask.startswith("Now report"))
        return SimpleNamespace(id="m", model="x", stop_reason=stop, content=content, usage=None)

    api = SimpleNamespace(create=create)
    return SimpleNamespace(messages=api, beta=SimpleNamespace(messages=api)), calls


TOOL = {"name": "report", "description": "x", "input_schema": {"type": "object", "properties": {}}}


def _report():
    from types import SimpleNamespace

    return SimpleNamespace(type="tool_use", name="report", id="tu_1", input={"advisories": []})


def test_research_caps_searches_over_the_whole_run_and_caches():
    """`max_uses` gilt je Anfrage: Fortsetzungen (pause_turn) bekommen nur den Rest, danach geht es zum Bericht."""
    from types import SimpleNamespace

    from app import claude

    def step(params, asked):   # Suchschritt: drei Suchen je Runde, immer pause_turn
        return ("tool_use", [_report()]) if asked else ("pause_turn", [SimpleNamespace(type="server_tool_use")] * 3)

    fake, calls = _research_fake(step)
    _, archive = claude.research(fake, "claude-haiku-5-5", "sys", "text", TOOL, max_searches=7)
    uses = [c["tools"][0]["max_uses"] for c in calls]
    assert uses == [7, 4, 1, 1] and archive["searches"] == 9   # 3 + 3 + 3, dann Schluss; der Bericht sucht nicht mehr
    assert all(c["cache_control"] == {"type": "ephemeral"} for c in calls)


def test_research_report_step_keeps_the_tool_list_so_it_reads_the_cache():
    """Werkzeuge stehen am Anfang des Cache-Präfixes: eine andere Liste im Berichtsschritt kostete den ganzen Verlauf
    noch einmal zum Schreibpreis (gemessen: cache_read 0 in jedem Bericht)."""
    from types import SimpleNamespace

    from app import claude

    def step(params, asked):
        return ("tool_use", [_report()]) if asked else (
            "end_turn", [SimpleNamespace(type="server_tool_use"), SimpleNamespace(type="text", text="notes")])

    fake, calls = _research_fake(step)
    data, archive = claude.research(fake, "claude-sonnet-5-5", "sys", "text", TOOL, max_searches=4)
    assert len(calls) == 2 and calls[0]["tools"] == calls[1]["tools"] and calls[0]["system"] == calls[1]["system"]
    assert [t.get("name") for t in calls[0]["tools"]] == ["web_search", "report"] and calls[0]["tools"][1]["strict"] is True
    assert calls[1]["messages"][:2] == [calls[0]["messages"][0], {"role": "assistant", "content": calls[1]["messages"][1]["content"]}]
    assert "tool_choice" not in calls[1]   # würde den Cache der Nachrichten ebenfalls verwerfen
    assert data == {"advisories": []} and archive["searches"] == 1


def test_research_rejects_a_report_without_a_search_once_and_takes_an_early_report():
    from types import SimpleNamespace

    from app import claude

    def lazy(params, asked):   # meldet sofort; nach der Zurückweisung sucht es und meldet im selben Zug
        if len(params["messages"]) == 1:
            return "tool_use", [_report()]
        return "tool_use", [SimpleNamespace(type="server_tool_use"), _report()]

    fake, calls = _research_fake(lazy)
    _, archive = claude.research(fake, "claude-sonnet-5-5", "sys", "text", TOOL, max_searches=4)
    nudge = calls[1]["messages"][-1]["content"][0]
    assert len(calls) == 2 and archive["searches"] == 1   # kein eigener Berichtsschritt mehr nötig
    assert (nudge["type"], nudge["tool_use_id"], nudge["is_error"]) == ("tool_result", "tu_1", True)

    fake, calls = _research_fake(lambda params, asked: ("tool_use", [_report()]))   # sucht auch danach nicht
    _, archive = claude.research(fake, "claude-sonnet-5-5", "sys", "text", TOOL, max_searches=4)
    assert len(calls) == 2 and archive["searches"] == 0
