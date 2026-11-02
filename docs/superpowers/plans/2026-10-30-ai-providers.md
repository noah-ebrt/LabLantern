# AI Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every vulnwatch installation chooses its AI vendor (Anthropic, OpenAI, or an OpenAI-compatible endpoint such as Ollama) and a model for each of the three AI tasks.

**Architecture:** A small provider interface (`check`, `list_models`, `ask_tool`, `research`) with two adapters: the existing Anthropic code in `claude.py`, and a new `openai_client.py` serving both OpenAI and OpenAI-compatible endpoints. A new `aiproviders.py` owns provider config, per-task model choice, automatic resolution, migration and the `/api/ai` router. `earlywarning.py` asks it for `(provider, model)` per task instead of building an Anthropic client itself.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, `anthropic` SDK, `openai` SDK (new), pytest; Vue 3 + vitest.

**Spec:** `docs/superpowers/specs/2026-10-30-ai-providers-design.md`

## Global Constraints

- No automatic fallback to another provider. A failed task records the error, and classification marks items `unklar`.
- "Configured" = key (or URL) stored. Never derived from the result of the last call.
- Keys and the custom base URL never appear in logs, alerts, audit text, API responses or error messages.
- Upgrade without action: `claude.api_key`, `claude.model`, `earlywarning.research.{enabled,model}` carry over with unchanged behaviour.
- Research/Verify only accept models on the web-search allow-list. Custom endpoints are never offered there.
- Provider error text = provider's own message, ≤ 300 chars, key scrubbed. Format: `<Provider>: <message> (HTTP <code>)`.
- Every write is admin-only and audited (provider id + model, never key/URL).
- Prompts, tool schemas, `validate`, `validate_research` and `apply` stay unchanged.
- Dependencies are hash-pinned: `uv pip compile requirements.in --generate-hashes --exclude-newer 2026-10-21T00:00:00Z --python-version 3.12 -o requirements.txt` (and the same for `requirements-dev`). uv is not installed on the master host, so run it via `docker run --rm -v "$PWD":/w -w /w ghcr.io/astral-sh/uv:0.9.5 pip compile …`.
- Server tests: `cd server && CI=true .venv/bin/pytest -q < /dev/null`. Web tests: `cd web && CI=true npm test < /dev/null`.
- Code comments and docstrings in German, like the surrounding code. UI copy and errors in English.

## Review Focus

1. **A task's provider runs out of budget (the real-world case).** The task shows the provider's message and the other provider is not used. Test in Task 5: `test_failed_provider_is_not_replaced_by_another`.
2. **Ollama model answers without a tool call / with prose around the JSON.** JSON fallback parses it, or it becomes an `unklar` item. It must never crash the pass. Test in Task 3: `test_compat_falls_back_to_json_when_tools_unsupported`, `test_compat_invalid_json_is_ai_error`.
3. **Ollama/endpoint unreachable (PC asleep, IP changed).** Classification items become `unklar` with "… unreachable", the pass finishes, research/verify are unaffected. Test in Task 5: `test_unreachable_compat_endpoint_marks_items_unklar`.
4. **Provider removed while tasks still point at it.** The task shows "no model — provider removed", no exception. Test in Task 4: `test_removed_provider_task_reports_error`.
5. **Custom URL with credentials (`http://user:pw@host/v1?token=x`).** Stored, but shown only as `http://host/v1`, and absent from audit log and errors. Test in Task 4: `test_custom_url_is_shown_cleaned_and_never_echoed`.

---

### Task 1: Provider-neutral errors with the provider's message

**Files:**
- Create: `server/app/aibase.py`
- Modify: `server/app/claude.py` (`ClaudeError`, `_call`)
- Test: `server/tests/test_claude.py`

**Interfaces:**
- Produces: `aibase.AiError(Exception)`; `aibase.short_error(provider: str, status: int | None, body, secret: str | None) -> str`; `claude.ClaudeError = AiError` (alias, existing imports keep working).

- [ ] **Step 1: Write the failing tests**

```python
def test_usage_limit_message_is_passed_through():
    body = {"error": {"type": "invalid_request_error", "message": "You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC."}}
    msg = short_error("Anthropic", 400, body, secret=None)
    assert msg == "Anthropic: You have reached your specified workspace API usage limits. You will regain access on 2026-11-01 at 00:00 UTC. (HTTP 400)"

def test_error_text_is_truncated_and_scrubbed():
    key = "sk-ant-api03-SECRET-0123456789abcdef"
    msg = short_error("OpenAI", 401, {"error": {"message": f"bad key {key} " + "x" * 600}}, secret=key)
    assert key not in msg and len(msg) <= 340 and msg.endswith("(HTTP 401)")
```

- [ ] **Step 2: Run, expect FAIL** (`ImportError: short_error`): `cd server && CI=true .venv/bin/pytest tests/test_claude.py -q < /dev/null`
- [ ] **Step 3: Implement** `aibase.py`. `short_error` reads `body["error"]["message"]` (dict) or `str(body)` and falls back to "request failed". It replaces `secret` with `***`, collapses whitespace and cuts the message to 300 chars. In `claude._call` keep the 401/403/429 wording, but build the generic `APIStatusError` case with `short_error("Anthropic", e.status_code, e.body, key)`. The client's key comes from `client.api_key`, and `_call` gets the client passed in. Unreachable stays `"Anthropic: API unreachable"`.
- [ ] **Step 4: Run, expect PASS** (whole `test_claude.py`, existing tests updated only where they assert the old "Claude API" prefix)
- [ ] **Step 5: Commit** `feat(ai): show the provider's own error message`

### Task 2: Provider interface and Anthropic adapter

**Files:**
- Modify: `server/app/aibase.py`, `server/app/claude.py`
- Test: `server/tests/test_claude.py`

**Interfaces:**
- Consumes: `AiError`.
- Produces in `aibase.py`:
  ```python
  class Provider(Protocol):
      pid: str            # "anthropic" | "openai" | "c1"
      label: str          # "Anthropic" | "OpenAI" | display name of the endpoint
      web_search: bool    # provider type can web-search at all
      def check(self) -> dict: ...                       # {"ok": bool, "error"?: str}
      def list_models(self) -> list[dict]: ...           # [{"id","name","created_at"}], newest first
      def ask_tool(self, model: str, system: str, text: str, tool: dict) -> tuple[dict, dict]: ...
      def research(self, model: str, system: str, text: str, tool: dict, max_searches: int = 15) -> tuple[dict, dict]: ...
  ```
  and in `claude.py`: `class AnthropicProvider` (pid `"anthropic"`, label `"Anthropic"`, `web_search=True`, ctor `(client)`), whose methods delegate to the existing module functions. Also `ANTHROPIC_WEB = ("claude-opus-4", "claude-sonnet-4", "claude-haiku-4-5", "claude-opus-5", "claude-sonnet-5", "claude-haiku-5", "claude-fable")` and `anthropic_web(model_id: str) -> bool` (prefix match).

- [ ] **Step 1: Failing tests** `test_anthropic_provider_delegates_ask_tool` (fake client from `test_earlywarning.Claude`, result equals `ask_tool(...)`), and `test_anthropic_web_allow_list` (`anthropic_web("claude-sonnet-5-5")`, `anthropic_web("claude-haiku-5-5")` are True; `anthropic_web("claude-3-haiku-20240307")` is False).
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement** (no behaviour change for existing callers)
- [ ] **Step 4: Run whole server suite, expect PASS**
- [ ] **Step 5: Commit** `refactor(ai): provider interface with the Anthropic adapter`

### Task 3: OpenAI and OpenAI-compatible adapter

**Files:**
- Create: `server/app/openai_client.py`
- Modify: `server/requirements.in`, `server/requirements-dev.in`, `server/requirements*.txt` (recompiled), `server/app/context.py` (`openai_factory: Optional[Callable[[str, str], object]] = None`, args `(base_url, key)`)
- Test: `server/tests/test_openai_client.py`

**Interfaces:**
- Consumes: `Provider`, `AiError`, `short_error`.
- Produces: `class OpenAIProvider` with ctor `(client, pid: str, label: str, compat: bool)`. `web_search = not compat`. `make_openai_client(base_url: str, key: str | None, factory=None)` returns `openai.OpenAI(api_key=key or "none", base_url=base_url, timeout=120.0, max_retries=2)`; httpx does not follow redirects by default, and that must stay so. Also `OPENAI_BASE = "https://api.openai.com/v1"`, `openai_web(model_id) -> bool` and `chat_model(model_id) -> bool`.

Behaviour:
- `list_models`: `client.models.list()`, mapped to `{"id","name": id,"created_at": iso(created)}`, newest first. For `compat=False` keep only `chat_model` ids: prefix `gpt-`, `o1`, `o3`, `o4`, `chatgpt-`, and none of `audio, realtime, transcribe, tts, image, embedding, search, instruct, moderation`. For compat keep all ids (Ollama lists only chat models).
- `openai_web`: prefix in `("gpt-4o", "gpt-4.1", "gpt-5", "o3", "o4-mini")` and no `nano`. Check the list against the current OpenAI docs for the Responses `web_search` tool, and adjust the list, not the mechanism.
- `ask_tool`: Chat Completions with one function tool (`parameters` = `tool["input_schema"]`, `strict: True` only when `compat=False`) and `tool_choice` forcing that function, then parse `tool_calls[0].function.arguments` as JSON. For `compat=True`, if the endpoint rejects tools (`BadRequestError`) or the answer has no tool call, repeat once with `response_format={"type": "json_object"}`. Append the schema to the system prompt ("Answer with one JSON object matching this schema: …"), take the first `{…}` block of the text, and parse it. Unparseable → `AiError("<label>: answer is not valid JSON")`. The archive dict uses the same keys as Anthropic: `id, model, stop_reason, usage`.
- `research` (OpenAI only, compat raises `AiError("<label>: no web search")`): two Responses calls, mirroring `claude.research`. (1) `tools=[{"type": "web_search"}]`, input = text. (2) `previous_response_id` + the report instruction + one function tool, with `tool_choice` forcing it. `searches` = count of `web_search_call` output items, and `sources` = `url_citation` annotation URLs (deduplicated, at most 50). `usage` is a list of both usages.
- SDK errors → `short_error(label, status, body, key)`. Connection errors → `"<label>: API unreachable"`.

- [ ] **Step 1: Failing tests** use a fake client like `test_earlywarning.Claude`, injected via the ctor, with `SimpleNamespace` responses:
  - `test_openai_ask_tool_returns_function_arguments`, which asserts the parsed dict and that `tool_choice` names the function
  - `test_openai_list_models_filters_non_chat` (input `gpt-5.2, gpt-5.2-mini, text-embedding-3-large, gpt-4o-audio-preview, dall-e-3` → `["gpt-5.2", "gpt-5.2-mini"]`, newest first by `created`)
  - `test_openai_web_allow_list` (`gpt-5.2` True, `gpt-4.1-nano` False)
  - `test_openai_research_counts_searches_and_sources`
  - `test_compat_research_is_ai_error`
  - `test_compat_falls_back_to_json_when_tools_unsupported` (first call raises `openai.BadRequestError`; second returns content `'Sure: {"products": []} done'` → `{"products": []}`)
  - `test_compat_invalid_json_is_ai_error`
  - `test_openai_error_shows_provider_message_without_key`
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Add `openai` to both `.in` files, recompile with the command from Global Constraints, install with `.venv/bin/pip install -r requirements-dev.txt`, and implement**
- [ ] **Step 4: Run, expect PASS**
- [ ] **Step 5: Commit** `feat(ai): OpenAI and OpenAI-compatible provider`

### Task 4: Provider config, per-task choice, resolution and `/api/ai`

**Files:**
- Create: `server/app/aiproviders.py`
- Modify: `server/app/integrations.py` (remove the `/claude*` routes and their helpers once nothing imports them), `server/app/main.py` (mount router)
- Test: `server/tests/test_aiproviders.py` (move the still-relevant cases from `test_claude.py`: login/admin, key encrypted and never returned, malformed keys rejected, key nowhere readable, validation never echoes the secret)

**Interfaces:**
- Consumes: `AnthropicProvider`, `anthropic_web`, `OpenAIProvider`, `make_openai_client`, `openai_web`, `AiError`.
- Produces:
  - Secrets: `claude.api_key` (name unchanged), `openai.api_key`, `compat.c1.url`, `compat.c1.api_key`.
  - Settings: `ai.compat` = `[{"id": "c1", "name": str, "display_url": str}]`; `ai.tasks` = `{"classify": ref, "research": ref, "verify": ref}` where `ref` is `""` (Automatic) or `"<pid>:<model>"`, split at the **first** `:` (Ollama ids contain `:`); `ai.models.<pid>` = `{"at", "items"}` (24 h cache); `ai.last_used.<pid>` = `{"at", "task", "model", "ok", "error"?}`.
  - `TASKS = ("classify", "research", "verify")`; `WEB_TASKS = ("research", "verify")`.
  - `providers(ctx) -> dict[str, Provider]`, only configured ones, ordered anthropic, openai, c1.
  - `models_for(ctx, pid, refresh=False) -> list[dict]`. Each item gains `"web": bool`.
  - `resolve(ctx, task) -> tuple[Provider, str]`. Raises `AiError` with exactly these texts: `"no model — provider removed"`, `"needs a provider with web search"` (web task, no web-capable provider configured), `"choose a model (no automatic choice for this provider)"`, `"no AI provider configured"`.
  - `record_use(ctx, provider, task, model, ok, error=None) -> None`
  - `any_configured(ctx) -> bool`
  - `build_ai_router(ctx, guards) -> APIRouter`, prefix `/api/ai`

Automatic resolution (Anthropic first, then OpenAI). Classify: `latest_haiku`, else newest OpenAI id containing `-mini`. Research/Verify: `latest_sonnet`, else newest OpenAI id matching `^gpt-\d+(\.\d+)?$`. A custom endpoint alone has no automatic choice.

Routes (admin for writes, session for reads, each write audited as `ai.provider.saved|removed|tested` / `ai.tasks`):
- `GET /api/ai` → `{"providers": [{"id","kind","label","configured","key": meta,"display_url"?, "last_used","models": [{"id","name","web"}]}], "tasks": {task: {"ref", "resolved": "<pid>:<model>" | null, "error": str | null}}}`
- `PUT /api/ai/providers/{pid}`, where pid ∈ `anthropic|openai|c1`. Body `{"api_key"?, "base_url"?, "name"?}`. Anthropic key `^[^\s]{20,400}$`. OpenAI key `^sk-[A-Za-z0-9_-]{20,300}$`. c1: `base_url` is required on the first save, scheme http/https with a host, ≤ 500 chars. The key is optional, `name` ≤ 60 chars and defaults to the host.
- `DELETE /api/ai/providers/{pid}` (removes secrets, cache and last_used; task refs stay)
- `POST /api/ai/providers/{pid}/test` → `{"ok", "error"?}`
- `POST /api/ai/providers/{pid}/refresh` → models
- `PUT /api/ai/tasks` body `{classify, research, verify}`. 422 if a ref's pid isn't configured, if the model isn't in that provider's list (if the list is empty because the provider is unreachable, accept any id ≤ 200 chars without control chars), or if a web task gets a non-`web` model.

- [ ] **Step 1: Failing tests**:
  - `test_unconfigured_state`: GET shows 3 providers not configured, and every task error is `"no AI provider configured"`
  - `test_automatic_prefers_anthropic` (both keys set, fake model lists → classify `anthropic:claude-haiku-5-5`, research `anthropic:claude-sonnet-5-5`)
  - `test_automatic_uses_openai_without_anthropic` (→ classify `openai:gpt-5.2-mini`, research `openai:gpt-5.2`)
  - `test_only_compat_needs_explicit_classify_and_has_no_web_tasks`
  - `test_ollama_model_id_with_colon_resolves` (`"c1:qwen3.8:27b"` → model `qwen3.8:27b`)
  - `test_web_task_rejects_compat_and_non_web_models` (422)
  - `test_removed_provider_task_reports_error`
  - `test_custom_url_is_shown_cleaned_and_never_echoed` (save `http://u:pw@10.0.0.5:11434/v1?token=x`; GET shows `http://10.0.0.5:11434/v1`; `pw` and `token=x` appear in no response, audit row or log)
  - the moved key-secrecy tests, run for anthropic and openai
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement.** Model caching and the "keep the old list on error" rule work like `integrations.available_models`, per pid.
- [ ] **Step 4: Run whole server suite, expect PASS**
- [ ] **Step 5: Commit** `feat(ai): providers, per-task models and /api/ai`

### Task 5: Early warning runs each task on its own provider

**Files:**
- Modify: `server/app/earlywarning.py` (`ask_claude` → `ask_ai(provider, model, item)`, `verify`, `run_research`, `run_pass`, `research_config`, `ResearchIn`, `write_research`, `refresh`, the three `ai_configured` spots)
- Test: `server/tests/test_earlywarning.py`

**Interfaces:**
- Consumes: `resolve`, `record_use`, `any_configured`, `Provider.ask_tool/research`.
- Produces: `research_config(s) -> {"enabled": bool, "verify": bool}` (defaults True/True). `PUT /api/early-warnings/research` body `{"enabled": bool, "verify": bool}`. The model field is gone, and an old client sending `model` gets it ignored.

Behaviour:
- `run_pass` resolves classify once. On `AiError` every pending item becomes `unklar` with `detail = f"The AI provider could not read the advisory ({e}); ask again"`. Research runs when due, `enabled`, and `resolve(ctx, "research")` succeeds; otherwise the state stores the resolve error. Verify runs when `verify` is set and `resolve(ctx, "verify")` succeeds. Each task calls `record_use` after its calls.
- `refresh?research=true` without a resolvable research model → 409 `"Web research needs a provider with web search (Settings → AI)"`.
- `ai_configured` = `any_configured(ctx)`.

- [ ] **Step 1: Failing tests** (adapt `use()` to also set `ai.tasks`):
  - `test_each_task_uses_its_own_provider` (classify on fake OpenAI, research on fake Anthropic; assert which fake got which call)
  - `test_failed_provider_is_not_replaced_by_another` (classify ref on Anthropic returning 400 with the usage-limit body, OpenAI configured too → items `unklar` with the usage-limit text, zero OpenAI calls)
  - `test_unreachable_compat_endpoint_marks_items_unklar`
  - `test_verify_has_its_own_switch` (`enabled=False, verify=True` → no research call, verify runs)
  - `test_research_without_web_provider_records_reason`
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run whole server suite, expect PASS**
- [ ] **Step 5: Commit** `feat(earlywarning): each AI task on its own provider and model`

### Task 6: Migration of existing settings

**Files:**
- Modify: `server/app/aiproviders.py` (`migrate_ai_settings(s) -> bool`), `server/app/main.py` (call it once at startup, after `init_db`)
- Test: `server/tests/test_migrate.py`

Rules (only when `ai.tasks` is absent; returns True if it migrated):
- `classify` = `"anthropic:" + claude.model` if set, else `""`.
- `research` = `verify` = `"anthropic:" + earlywarning.research.model` if set, else `""`.
- `earlywarning.research` = `{"enabled": old.enabled (default True), "verify": old.enabled (default True)}`.
- `ai.models` → `ai.models.anthropic`; `ai.last_used` → `ai.last_used.anthropic` (adding `"task": "classify"`). Delete the old keys.

- [ ] **Step 1: Failing tests**:
  - `test_migration_keeps_choices` (old `claude.model="claude-haiku-5-5"`, research `{enabled: False, model: "claude-sonnet-5-5"}` → refs as above, `verify` False)
  - `test_migration_without_old_choices_means_automatic`
  - `test_migration_is_idempotent` (second call returns False and changes nothing)
- [ ] **Step 2: Run, expect FAIL**
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run whole server suite, expect PASS**
- [ ] **Step 5: Commit** `feat(ai): migrate the Anthropic-only settings`

### Task 7: Settings UI "AI providers" and Early warnings switches

**Files:**
- Create: `web/src/components/AiSettings.vue` (replaces `ClaudeSettings.vue`, which gets deleted)
- Modify: `web/src/views/SettingsView.vue:4,40`, `web/src/views/EarlyWarningsView.vue` (remove the model `<select>` at ~211; add a "Check high hits with the vendor" checkbox bound to `research.verify`; adjust the `research` ref and PUT body)
- Test: `web/tests/AiSettings.test.js` (follow `NotificationSettings.test.js`)

Layout (reuse the existing card, field and button classes of `ClaudeSettings.vue`):
- Card title "AI providers", subtitle "Choose which vendor and model vulnwatch uses for each AI task."
- Three provider blocks (Anthropic, OpenAI, "OpenAI-compatible (Ollama, LM Studio, OpenRouter …)"), each with a key field (stored/replace pattern), Test, Remove, Refresh list, and "last used … with <model> (<task>) — ok / failed: <error>". The compatible block adds a Name field and a Base URL field (placeholder `http://192.168.1.10:11434/v1`), and its key field is labelled "API key (optional)".
- "Models per task": three `<select>`s labelled "Classify feed advisories", "Web research", "Check high hits with the vendor". Options: "Automatic — currently <resolved>" first (or "Automatic — not available" when resolution fails), then `<optgroup label="<provider label>">` per configured provider with its models. Web tasks list only `web: true` models. Below each select, show the task's `error` in the danger style. One "Save models" button → `PUT /api/ai/tasks`.

- [ ] **Step 1: Failing tests**:
  - `renders resolved automatic model per task`
  - `web tasks do not offer compat or non-web models`
  - `shows task error from the API`
  - `saving sends refs with ollama ids containing colons unchanged`
- [ ] **Step 2: Run, expect FAIL**: `cd web && CI=true npm test < /dev/null`
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run tests and `CI=true npm run build < /dev/null`, expect PASS**
- [ ] **Step 5: Commit** `feat(web): AI providers settings and per-task models`

### Task 8: Real Ollama check, deploy, docs

**Files:**
- Modify: `README.md` / `docs/` sections that mention the Claude API key (search `grep -rn "Claude" README.md docs/ --include=*.md`)

- [ ] **Step 1: Real classify against Ollama.** Use `http://192.0.2.99:11434/v1` with model `qwen3.8:27b` (Noah's home PC; ask Noah to start Ollama first and check `curl -s http://192.0.2.99:11434/v1/models` from the master host). Run a short script with `server/.venv/bin/python` that builds an `OpenAIProvider(compat=True)` and calls `earlywarning.ask_ai` on one realistic advisory (e.g. a recent OpenSSH advisory text). Expected: it returns without `AiError`, and `validate` accepts it. If the first answer fails, tune only the JSON-fallback instruction, then re-run Task 3's tests.
- [ ] **Step 2: Update docs**: the provider choice, Ollama setup (`OLLAMA_HOST=0.0.0.0:11434`, firewall private network only), and that research/verify need Anthropic or OpenAI.
- [ ] **Step 3: Full test run**: server suite and web suite, both PASS.
- [ ] **Step 4: Commit** `docs: AI provider choice and Ollama setup`
- [ ] **Step 5: Deploy** (no worker change): check no run is active, then `cd deploy && docker compose build server && docker compose up -d --no-deps --force-recreate server announce`. Open Settings → AI providers. Anthropic shows the migrated key and today's models, and the classify task shows the usage-limit error until 2026-11-01. Add the Ollama endpoint, set Classify to `c1:qwen3.8:27b`, and click "Check now" in Early warnings. Expected: pending items are classified by Ollama.
