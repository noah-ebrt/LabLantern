# AI providers: free choice of vendor and model per task

Date: 2026-10-30 · Status: draft for review

## Why

vulnwatch is released publicly. Today every AI feature is hard-wired to Anthropic: one API key, Haiku for
classification, and a Sonnet model, invisible on the settings page, for web research and vendor checks. Each
installation should be able to use the vendor it already trusts or pays for, including a model running
locally with no cloud at all. The trigger was the Anthropic spend limit running out on the master host (Sonnet research used
up the budget, so Haiku classification failed too, shown only as "Claude API HTTP 400"). That incident also shows two
smaller problems this work fixes: users can't see which model costs money, and provider errors get swallowed.

## Goals

- Any combination of providers is possible. The three AI tasks each have their own model choice:
  1. **Classify** feed advisories (`ask_tool`, frequent, no web search). Today: `resolve_model` → latest Haiku.
  2. **Research**: web research for new reports about products in use (`run_research`, web search). Today: latest Sonnet.
  3. **Verify**: check "hoch" hits against the vendor advisory before alerting (`verify`, web search). Today: latest Sonnet.
- Supported provider types:
  - **Anthropic** (existing; Messages API + `web_search` server tool).
  - **OpenAI** (Responses API + built-in `web_search` tool).
  - **OpenAI-compatible (custom base URL)**: covers **Ollama** with any pulled open model (Llama, Qwen, Mistral,
    Gemma …) at `http://<host>:11434/v1`, plus LM Studio, vLLM, OpenRouter, Mistral, Groq and Gemini's
    OpenAI endpoint. Key optional (Ollama needs none). Ollama support must be tested explicitly.
- Every provider error shows the provider's own message (e.g. "You have reached your specified workspace API
  usage limits … 2026-11-01"), cut to a sane length, never containing the key.
- Existing installations keep working with no action: the stored Anthropic key, the chosen classify model and the
  research model/enabled setting carry over unchanged.

## Non-goals

- No automatic fallback to another provider when one fails. Failing over would silently spend money with a vendor
  the user didn't pick for that task. A failed task records the error, and classification marks items "unklar" as today.
- No dedicated integrations for Gemini, Mistral etc. beyond the OpenAI-compatible type.
- No cost tracking or budget enforcement in vulnwatch (the providers' own limits do that).
- No change to prompts, tool schemas, `validate`/`validate_research` or how results are applied.

## Anti-goals (would count as failure even if it works)

- A key, or a custom URL containing credentials, appearing in logs, alerts, audit text, API responses or error messages.
- An upgrade that leaves an existing install with AI off or silently on a different model.
- Research/verify running on a model that cannot search the web and returning made-up "findings".

## Behaviour

### Settings → "AI providers" (replaces the "Claude AI Integration" card)

- One block per provider type: Anthropic, OpenAI, OpenAI-compatible. Each has the same pattern as today: key stored
  encrypted and never shown again, "Test", "Remove", fetched model list (cached 24 h, "Refresh list"), and
  "last used <time> with <model> (ok/failed: <reason>)".
- OpenAI-compatible additionally has a **base URL** and a display **name** (e.g. "Ollama on the master host"). The key is
  optional. One custom endpoint is enough for v1 (*my call*: a list of several is a later extension; keep the data
  shape a list so it can grow).
- Below the providers: **"Models per task"**, three dropdowns (Classify, Research, Verify). Options are grouped by
  provider and list only providers with a working configuration. Each dropdown also has an **"Automatic"** entry:
  - Classify: newest small model of the provider that is configured (Anthropic Haiku, otherwise the OpenAI "mini"
    tier). With only a custom endpoint configured, there is no automatic choice and the user must pick a model.
  - Research / Verify: newest mid-tier model with web search (Anthropic Sonnet, otherwise OpenAI's current
    general model).
  - If several providers are configured, Automatic prefers Anthropic (keeps today's behaviour). *My call.*
  - The page always shows what "Automatic" currently resolves to, as today ("currently claude-haiku-5-5").
- Research and Verify only offer models that can web-search: Anthropic and OpenAI. Custom endpoints are not
  offered there. If no web-capable provider is configured, these two tasks show "off — needs a provider with
  web search" and are skipped. Classification keeps working (fully offline with Ollama).
- The research **on/off** toggle stays where it is today (Early warnings). Only its model picker moves to the
  "Models per task" block, so all model choices live in one place. Today that one toggle also gates Verify.
  *My call:* Verify gets its own on/off switch. Both switches are migrated from today's `enabled`, so behaviour is
  unchanged after the upgrade. A user can then cut research spend and keep the vendor check, or the other way round.
- "Configured" means **key (or URL) stored**, never "last call succeeded". The dropdown options and the
  Automatic resolution depend only on stored configuration. A provider that fails (budget, outage) stays selected
  and keeps failing visibly. It is never dropped in favour of another one, which would be the forbidden failover.
  A chosen model is only reset if its provider is removed. The task then shows "no model — provider removed".
- **Web-search capability is per model, not per provider.** Research/Verify only offer models on an allow-list of
  model families known to support the provider's web search tool (Anthropic: extend the existing
  `WEB_SEARCH_DYNAMIC`-style list in `claude.py`; OpenAI: the families documented for the Responses `web_search`
  tool). Unknown new models of a family match by prefix. *My call:* no runtime "zero searches = error" rule,
  because a verify call may legitimately need no search.
- The custom base URL is shown back **cleaned up** (scheme, host, port, path, with no user-info or query string) so the
  admin can recognise it. Changing it means entering the full URL again, like a key. "Test" and "last used" name
  the endpoint by its display name.
- Admin-only for every write, as today. Every change is written to the audit log (provider + model, never the key/URL secret).

### Errors

- Each provider adapter turns SDK/HTTP errors into one short sentence including the provider's message, e.g.
  `Anthropic: usage limit reached — You will regain access on 2026-11-01 at 00:00 UTC (HTTP 400)`. Messages are
  truncated (~300 chars), and any echo of the key is scrubbed.
- Item texts become provider-neutral: "The AI provider could not read the advisory (…); ask again", not "Claude …".

### Migration (on startup, idempotent)

- `claude.api_key` secret → Anthropic provider key (can stay under the same secret name, builder's choice, but must
  not require re-entry).
- `claude.model` → Classify model choice ("" = Automatic).
- `earlywarning.research.model` → Research **and** Verify model choice (today both use it); `enabled` stays.
- Old endpoints `/api/integrations/claude*` may be removed once the web UI no longer uses them (same deploy); no
  external clients depend on them.

## Constraints

- Python server (FastAPI, SQLAlchemy, settings in the `settings` table via `setting`/`put_setting`, secrets via
  `SecretStore`). Dependencies are hash-pinned with pip-compile (`server/requirements.in` → `requirements.txt`).
  Adding the `openai` SDK is fine if it's compiled in the same way. Plain `httpx` is acceptable too (builder's call).
- Tests run with fakes (`ctx.claude_factory`, `anthropic_base_url`), not real APIs. The new adapters need the same
  injectability. `VULNWATCH_ANTHROPIC_BASE_URL` keeps working.
- Custom base URL: any `http(s)` URL is allowed (LAN/localhost is the point). Admin-only. Store it as a secret
  (it may contain credentials). Never put it in alerts or logs. No redirects to other hosts.
- Structured output: today the model answers by calling a tool (`TOOL`, `RESEARCH_TOOL`). OpenAI and compatible
  endpoints use function calling with the same JSON schema. Many open models in Ollama handle tool calls poorly, so the
  compatible adapter must fall back to JSON-only output (`response_format`/`format: json` + schema in the prompt) and
  still pass `validate`. An invalid answer is a normal task error, not a crash.
- Research/verify return an archive with `searches`, `sources` and `usage` (stored in `ai_json` and in the research
  state). The OpenAI adapter must fill these from the Responses API (web_search calls, `url_citation` annotations, token usage).
- Web UI is Vue (`web/src/components/ClaudeSettings.vue`, `views/SettingsView.vue`, `views/EarlyWarningsView.vue`).
  Light and dark mode are both supported.

## Left to the builder

- Module layout (e.g. a provider interface with `list_models`, `check`, `ask_tool`, `research` and three adapters).
- Exact setting keys and API routes, as long as migration and the audit-log rule hold.
- How "newest mid-tier / small model" is detected per provider (name patterns + `created` date, like today).
- Whether the model dropdown shows only chat-capable models (filter embeddings/audio/image models out for OpenAI).
- Exact UI layout within the existing settings style.
