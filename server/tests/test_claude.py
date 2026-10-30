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
