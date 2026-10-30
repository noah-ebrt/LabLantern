"""OpenAI-Adapter: Werkzeug-Aufruf, Modellliste, Recherche und der Rückfall für eigene Endpunkte (mit Fake-Client)."""
import json
from types import SimpleNamespace

import httpx2
import openai
import pytest

from app.aibase import AiError
from app.openai_client import OPENAI_BASE, OpenAIProvider, chat_model, make_openai_client, openai_web

KEY = "sk-proj-test-0123456789abcdefghij"
TOOL = {"name": "report_advisory", "description": "facts",
        "input_schema": {"type": "object", "additionalProperties": False, "required": ["products"],
                         "properties": {"products": {"type": "array", "items": {"type": "string"}}}}}


def sdk_error(cls, status, body):
    req = httpx2.Request("POST", "https://api.example.test/v1/x")
    return cls("boom", response=httpx2.Response(status, request=req), body=body)


def chat_reply(content=None, args=None, name="report_advisory"):
    calls = [SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(args)))] if args is not None else None
    msg = SimpleNamespace(content=content, tool_calls=calls, refusal=None)
    return SimpleNamespace(id="chatcmpl-1", model="gpt-5.2", usage=None,
                           choices=[SimpleNamespace(message=msg, finish_reason="stop")])


class Client:
    """Fake des openai-Clients: zeichnet Aufrufe auf, antwortet der Reihe nach (Ausnahmen werden geworfen)."""

    def __init__(self, chat=(), responses=(), models=()):
        self.api_key = KEY
        self.calls, self._chat, self._resp = [], list(chat), list(responses)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **p: self._next(self._chat, p)))
        self.responses = SimpleNamespace(create=lambda **p: self._next(self._resp, p))
        self.models = SimpleNamespace(list=lambda: list(models))

    def _next(self, queue, params):
        self.calls.append(params)
        r = queue.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_openai_ask_tool_returns_function_arguments():
    c = Client(chat=[chat_reply(args={"products": ["gitlab"]})])
    args, archive = OpenAIProvider(c, "openai", "OpenAI", False).ask_tool("gpt-5.2", "sys", "text", TOOL)
    assert args == {"products": ["gitlab"]}
    p = c.calls[0]
    assert p["tool_choice"] == {"type": "function", "function": {"name": "report_advisory"}}
    fn = p["tools"][0]["function"]
    assert fn["parameters"] == TOOL["input_schema"] and fn["strict"] is True
    assert [m["role"] for m in p["messages"]] == ["system", "user"]
    assert set(archive) == {"id", "model", "stop_reason", "usage"} and archive["stop_reason"] == "stop"


def test_compat_tool_call_is_not_strict_and_keeps_model_id():
    c = Client(chat=[chat_reply(args={"products": []})])
    OpenAIProvider(c, "c1", "Ollama", True).ask_tool("qwen3.8:27b", "sys", "text", TOOL)
    assert c.calls[0]["model"] == "qwen3.8:27b" and "strict" not in c.calls[0]["tools"][0]["function"]


def test_openai_list_models_filters_non_chat():
    ids = [("gpt-5.2-mini", 20), ("text-embedding-3-large", 50), ("gpt-4o-audio-preview", 40), ("dall-e-3", 30),
           ("gpt-5.2", 10), ("gpt-5-pro", 60), ("gpt-5-codex", 70)]
    models = [SimpleNamespace(id=i, created=t) for i, t in ids]
    got = OpenAIProvider(Client(models=models), "openai", "OpenAI", False).list_models()
    assert [m["id"] for m in got] == ["gpt-5.2-mini", "gpt-5.2"]   # neueste zuerst
    assert got[0]["name"] == "gpt-5.2-mini" and got[0]["created_at"].startswith("1970-01-01T00:00:20")
    allm = OpenAIProvider(Client(models=models), "c1", "Ollama", True).list_models()
    assert len(allm) == 7 and allm[0]["id"] == "gpt-5-codex"   # eigener Endpunkt: nichts wird gefiltert


def test_openai_web_allow_list():
    assert openai_web("gpt-5.2") and openai_web("o3") and openai_web("gpt-4.1")
    assert not openai_web("o4-mini") and not openai_web("gpt-4.1-nano") and not openai_web("gpt-3.5-turbo") and not openai_web("qwen3.8:27b")
    assert chat_model("o3-mini") and not chat_model("gpt-4o-search-preview") and not chat_model("whisper-1")


def responses(rid, output):
    return SimpleNamespace(id=rid, model="gpt-5.2", status="completed", output=output, usage=None)


def test_openai_research_counts_searches_and_sources():
    cite = lambda u: SimpleNamespace(type="url_citation", url=u)  # noqa: E731
    first = responses("resp_0", [
        SimpleNamespace(type="web_search_call"), SimpleNamespace(type="web_search_call"),
        SimpleNamespace(type="message", content=[SimpleNamespace(type="output_text", text="notes", annotations=[
            cite("https://a.example/1"), cite("https://a.example/1"), cite("https://b.example/2")])])])
    second = responses("resp_1", [SimpleNamespace(type="function_call", name="report_advisory",
                                                  arguments='{"products": ["x"]}')])
    c = Client(responses=[first, second])
    args, archive = OpenAIProvider(c, "openai", "OpenAI", False).research("gpt-5.2", "sys", "text", TOOL, 7)
    assert args == {"products": ["x"]}
    assert archive["searches"] == 2 and archive["sources"] == ["https://a.example/1", "https://b.example/2"]
    assert archive["id"] == "resp_1" and archive["usage"] == [None, None]
    assert set(archive) == {"id", "model", "stop_reason", "searches", "usage", "sources"}
    one, two = c.calls
    assert one["tools"] == [{"type": "web_search"}] and one["input"] == "text" and one["max_tool_calls"] == 7
    assert two["previous_response_id"] == "resp_0" and two["tool_choice"] == {"type": "function", "name": "report_advisory"}
    assert two["tools"][0]["type"] == "function" and two["tools"][0]["parameters"] == TOOL["input_schema"]


def test_compat_research_is_ai_error():
    p = OpenAIProvider(Client(), "c1", "Ollama", True)
    assert p.web_search is False
    with pytest.raises(AiError, match="Ollama: no web search"):
        p.research("m", "s", "t", TOOL)


def test_compat_falls_back_to_json_when_tools_unsupported():
    c = Client(chat=[sdk_error(openai.BadRequestError, 400, {"message": "tools not supported"}),
                     chat_reply(content='Sure: {"products": []} done')])
    args, archive = OpenAIProvider(c, "c1", "Ollama", True).ask_tool("llama3:8b", "sys", "text", TOOL)
    assert args == {"products": []} and archive["id"] == "chatcmpl-1"
    retry = c.calls[1]
    assert retry["response_format"] == {"type": "json_object"} and "tools" not in retry
    assert "Answer with one JSON object matching this schema" in retry["messages"][0]["content"]


def test_compat_falls_back_to_json_when_answer_has_no_tool_call():
    c = Client(chat=[chat_reply(content="no tool"), chat_reply(content='{"products": ["a"]}')])
    assert OpenAIProvider(c, "c1", "LM Studio", True).ask_tool("m", "s", "t", TOOL)[0] == {"products": ["a"]}


def test_compat_invalid_json_is_ai_error():
    c = Client(chat=[chat_reply(content="nothing"), chat_reply(content="I cannot answer {broken")])
    with pytest.raises(AiError, match="Ollama: answer is not valid JSON"):
        OpenAIProvider(c, "c1", "Ollama", True).ask_tool("m", "s", "t", TOOL)


def test_openai_bad_request_is_not_swallowed():
    c = Client(chat=[sdk_error(openai.BadRequestError, 400, {"message": "bad schema"})])
    with pytest.raises(AiError, match=r"OpenAI: bad schema \(HTTP 400\)"):
        OpenAIProvider(c, "openai", "OpenAI", False).ask_tool("m", "s", "t", TOOL)
    assert len(c.calls) == 1


def test_openai_error_shows_provider_message_without_key():
    body = {"message": f"Incorrect API key provided: {KEY}.", "type": "invalid_request_error"}
    c = Client(chat=[sdk_error(openai.AuthenticationError, 401, body)])
    with pytest.raises(AiError) as e:
        OpenAIProvider(c, "openai", "OpenAI", False).ask_tool("m", "s", "t", TOOL)
    assert KEY not in str(e.value) and str(e.value).startswith("OpenAI: Incorrect API key provided: ***")
    assert str(e.value).endswith("(HTTP 401)")


def test_connection_error_and_check():
    req = httpx2.Request("GET", "https://api.example.test/v1/models")
    c = Client()
    c.models = SimpleNamespace(list=lambda: (_ for _ in ()).throw(openai.APIConnectionError(request=req)))
    assert OpenAIProvider(c, "c1", "Ollama", True).check() == {"ok": False, "error": "Ollama: API unreachable"}
    assert OpenAIProvider(Client(models=[]), "openai", "OpenAI", False).check() == {"ok": True}


def test_make_client_uses_factory_and_never_follows_redirects():
    seen = []
    got = make_openai_client("http://ollama:11434/v1", None, lambda url, key: seen.append((url, key)) or "client")
    assert got == "client" and seen == [("http://ollama:11434/v1", "none")]
    real = make_openai_client(OPENAI_BASE, KEY)
    assert str(real.base_url).startswith(OPENAI_BASE) and real.max_retries == 2
    assert real._client.follow_redirects is False


def test_empty_choices_never_raises_index_error():
    empty = SimpleNamespace(id="c", model="m", usage=None, choices=[])
    # OpenAI: kein Werkzeugaufruf -> AiError
    with pytest.raises(AiError, match="OpenAI: answer without the expected tool call"):
        OpenAIProvider(Client(chat=[empty]), "openai", "OpenAI", False).ask_tool("m", "s", "t", TOOL)
    # eigener Endpunkt: erst JSON-Rückfall; liefert auch der nichts, ist es ein AiError
    c = Client(chat=[empty, empty])
    with pytest.raises(AiError, match="Ollama: answer is not valid JSON"):
        OpenAIProvider(c, "c1", "Ollama", True).ask_tool("m", "s", "t", TOOL)
    assert len(c.calls) == 2
    # leere Auswahl im ersten, gültige Antwort im zweiten Aufruf
    c = Client(chat=[empty, chat_reply(content='{"products": ["a"]}')])
    args, archive = OpenAIProvider(c, "c1", "Ollama", True).ask_tool("m", "s", "t", TOOL)
    assert args == {"products": ["a"]} and archive["stop_reason"] == "stop"
