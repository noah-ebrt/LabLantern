# vulnwatch master: internals

How the master (server, worker, proxy, mDNS announcer) is built and how each flow works. Use it to check
changes against the design. The threat model is in [SECURITY.md](../SECURITY.md); the agent side is in
[agent/docs/INTERNALS.md](../agent/docs/INTERNALS.md).

State: phase 2 plus rework v4 (2026-10-25).

---

## 1. Containers (`deploy/compose.yaml`)

```
 LAN ── https://<BIND_IP>:8443 ──► proxy (Caddy)
                                     │  TLS with its own internal CA (on-demand, only for VULNWATCH_HOSTNAMES)
                                     │  blocks /api/worker/* and /api/internal/* from outside
                                     ▼
                                   server :8000 (FastAPI + Vue build, plain HTTP inside the compose network)
                                     ▲   volumes: data (SQLite, SBOMs, releases), keys (master.key), worker_auth (rw)
                                     │
                    worker ──────────┘  HTTP + worker token; NO data/keys volumes; Grype + canary files
 announce (host network) ── mDNS _vulnwatch._tcp → BIND_IP:8443 (no volumes, no rights)
```

| Service | Image | Rights | Talks to |
|---|---|---|---|
| `proxy` | `caddy@sha256:…` | read-only, `cap_drop: ALL` + `NET_BIND_SERVICE` | LAN ↔ server; `:8081` (internal only) serves `ca.crt` to the server |
| `server` | `deploy/Dockerfile` | uid 10001, read-only root fs, `cap_drop: ALL`, `no-new-privileges` | DB, master key, agent releases (read-only), Apprise targets, AI provider APIs (Anthropic, OpenAI, custom endpoint) |
| `worker` | `deploy/Dockerfile.worker` | same | server API (`/api/worker/*`), Grype DB download |
| `announce` | server image, `python -m app.announce` | host network (multicast), nothing mounted | LAN multicast |

The server never terminates TLS in this setup (`VULNWATCH_PLAIN_HTTP=1`). Without the proxy it can run
standalone with its own CA from `pki.py`, but the compose file doesn't use that mode.

## 2. Request pipeline

1. **Caddy** terminates TLS, replaces `X-Forwarded-For` with the real client IP, enforces a 64 MB body limit,
   and returns 404 for internal paths.
2. **uvicorn** (`__main__.py`) runs with `proxy_headers=True` and `forwarded_allow_ips=$VULNWATCH_TRUSTED_PROXY`.
   That is the proxy's fixed address on the separate network `edge`, which only the proxy and the server join.
   Anything else that reaches `server:8000` directly (worker, Docker host) can't fake its IP.
3. **Middleware `security_headers`** (`main.py`): rejects `/api/agent/*` requests whose `Content-Length` exceeds
   `max_agent_body`, then adds `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, HSTS, a CSP
   (`default-src 'self'`) and `Cache-Control: no-store` for `/api/*`.
4. **Router** under `/api`. Anything else is the SPA (`_serve_spa`; resolved paths must stay inside `web/`).
5. **Guards** (`guards.py`), used as FastAPI dependencies:
   - `require_session`: valid `vw_session` cookie. The cookie value is a random token; the DB stores only its
     SHA-256. It expires after 12 h.
   - `require_csrf`: `require_session` + header `X-CSRF-Token` equal to the session's CSRF token
     (constant-time compare).
   - `require_admin`: `require_csrf` + role `admin` (currently the only role).

   GET endpoints use `require_session`; every state-changing endpoint uses `require_admin`.

Agent and worker endpoints don't use cookies. They authenticate with a bearer token (§5, §7).

## 3. Module map (`server/app/`)

| Module | Purpose |
|---|---|
| `__main__.py` | start uvicorn (plain HTTP behind the proxy, or own TLS) |
| `main.py` | `create_app`: DB, master key, context, scheduler, routers, middleware, SPA |
| `config.py` | `Settings` from env (`VULNWATCH_*`) |
| `context.py` | `Context`: settings, DB session factory, secret store, rate limiters, clock, notifier, audit helper |
| `db.py`, `models.py`, `migrate.py` | SQLAlchemy + SQLite (WAL, foreign keys); additive column migrations |
| `auth.py` | argon2 passwords, tokens, constant-time compare, TOTP (±1 step), `RateLimiter` (in memory) |
| `guards.py` | session / CSRF / admin dependencies |
| `api.py` | `/state`, setup (token → TOTP → admin), login (password + TOTP), logout |
| `passkeys.py` | WebAuthn: register, login (password + passkey), signed trust list, **prepare/confirm signed agent commands**, passkey-confirmed pairing approval |
| `secrets_store.py` | AES-256-GCM envelope encryption (§6) |
| `pki.py`, `trust.py` | own CA for standalone mode; `ca_fingerprint()` = SHA-256 of the root cert the agents pin (from Caddy's `:8081`) |
| `agent_api.py` | enrollment token + install commands; systems list/approve/revoke/delete; agent enroll, poll, report, image SBOM upload, downloads |
| `pairing.py` | `/agent/pair` (unauthenticated, rate-limited), status/collect, list/reject; pairing code |
| `commands.py` | unsigned commands (`report_now`, `query`), agent long-poll `/agent/commands/next`, results |
| `sbom.py` | build CycloneDX from the agent's package list (PURLs with distro and upstream qualifiers) |
| `scanrun.py` | scan lifecycle: collect → job → worker result → findings; image SBOM paths |
| `worker_api.py` | `/api/worker/*` (bearer worker token): claim, download SBOMs, post result/failure |
| `worker.py`, `scanner.py`, `canary.py`, `rules.py` | run **in the worker**: Grype, DB freshness gate, log4j canary, severity rules (the server also uses `rules.py`) |
| `coverage.py`, `overview.py`, `report.py` | coverage matrix, traffic light, run report text |
| `runs_api.py` | findings list/accept, runs list/detail/trigger |
| `schedule.py` | APScheduler: daily run, 60 s maintenance, hourly release sync; schedule settings API |
| `releases.py` | take the signed agent releases from `agent-sign`, verify, and serve them |
| `integrations.py`, `notify.py`, `mail.py` | Apprise channels (mail + push), legacy SMTP |
| `aiproviders.py` | AI providers: keys and custom endpoint (stored as secrets), model per task, automatic choice, `/api/ai` |
| `aibase.py`, `claude.py`, `openai_client.py` | the common provider interface and error type (`aibase.py`); Anthropic and OpenAI/OpenAI-compatible adapters |
| `events.py` | Server-Sent Events: topic names only, published from DB commit hooks |
| `internal.py` | `/api/internal/tls-allowed` for Caddy's `on_demand_tls ask` |
| `announce.py` | mDNS announcement (separate container) |

## 4. Data model (SQLite, `data/vulnwatch.db`)

| Table | Key columns | Notes |
|---|---|---|
| `users` | username, argon2 `password_hash`, `totp_last_step` | TOTP secret lives in the secret store as `totp.<id>` |
| `sessions` | `token_hash` (SHA-256), `csrf_token`, `expires_at` | |
| `passkeys` | `credential_id`, COSE `public_key`, `sign_count` | ES256 only |
| `secrets` | `name`, `wrapped_dek`, `ciphertext` | §6 |
| `settings` | key → JSON | schedule, release source/current, `passkeys.trust`, `refresh.requested`, … |
| `audit_log` | ts, actor, action, detail | |
| `systems` | name (unique), status `pending/active/revoked`, `agent_token_hash`, `inventory_json`, `last_contact` | SBOM file `data/sboms/<id>.json` |
| `enrollment_tokens` | `token_hash`, `expires_at` (1 h) | single use |
| `pairings` | hostname, code (empty until reveal), `secret_hash` (= commitment), `nonce`, status `committed/pending/approved/collected/rejected/expired` | token for collection is in the secret store as `pairing.<id>` |
| `agent_commands` | system, type, `params_json` (incl. `envelope` + `assertion` for signed ones), status | |
| `system_image_sboms` | (`system_id`, `image_id`), error | file `data/images/<system>/<sha>.json`; per system, so one agent can't replace another host's SBOM (the old global table `image_sboms` is unused) |
| `scan_runs`, `scan_jobs`, `system_scan_results`, `findings` | | §8 |

## 5. Authentication flows

**First setup** (`api.py`): at every start while no admin exists, the server logs a fresh setup token; the DB
stores only its SHA-256. `POST /setup/totp` (token) returns a new TOTP secret and QR code.
`POST /setup/complete` (token + username + password ≥ 12 + TOTP code) creates the admin, deletes the token,
and moves the TOTP secret to `totp.<id>`. Failures are limited to 5 per 15 min per IP.

**Login with TOTP**: `POST /login`. The password is checked with argon2 (against a dummy hash if the user is
unknown, so timing reveals nothing), and the TOTP code must be from a step **newer than the last one used**
(replay protection). Limits: 5 failures per 15 min per username **and IP** (so nobody else can lock you out),
20 per IP. On success the server creates a
session row and sets the cookie `vw_session` (HttpOnly, Secure, SameSite=Strict, 12 h).

**Login with passkey**: `POST /login/passkey/options` (username + password → challenge for that user's
credentials), then `POST /login/passkey` (assertion, UV required).

**Logout** deletes the session row. The SSE stream re-checks the session on every tick and ends.

## 6. Secret store (`secrets_store.py`)

- `master.key` (32 random bytes, 0600) lives in its own volume `keys`, mounted only into `server`.
- Each secret gets a fresh 32-byte data key (DEK). `wrapped_dek = AESGCM(master).encrypt(nonce, DEK, aad=name)`
  and `ciphertext = AESGCM(DEK).encrypt(nonce, value, aad=name)`. Using the name as AAD means you can't swap
  rows between names.
- Contents: TOTP secrets, Apprise URLs, SMTP password, AI provider keys and endpoint URL, one-time pairing
  tokens.
- The API only ever returns `meta()` (`set`, `updated_at`), never values. The validation error handler strips
  submitted input from 422 responses.

## 7. Agent-facing flows

### Enrollment (token)
1. Admin: `POST /systems/enrollment-token` returns `token` (1 h, single use), `ca_fingerprint`, `install_cmd`
   (download, SHA-256 check, install, `enroll --ca-fingerprint`) and `setup_cmd`.
2. Agent: `POST /agent/enroll` creates (or resets) the system with status `pending` and a new agent token. Only
   its hash is stored.
3. Admin: `POST /systems/{id}/approve` sets it `active`.

### Pairing (no token, `vulnwatch-agent setup`)
1. Agent: `POST /agent/pair {hostname, commitment}` (commitment = SHA-256(secret)). Unauthenticated, limited to
   10 per 10 min per IP, at most 2 open per IP and 20 in total. The server stores the commitment and answers with
   a fresh random `nonce`. Status is `committed`: no code yet, not shown in the UI, can't be approved.
2. Agent: `POST /agent/pair/{id}/reveal {secret}`. It must match the commitment. Then
   `code = base32(SHA-256(FP:secret:nonce))[:6]`, status `pending`.
3. Admin: sees the code under *Pending pairings* and approves (`/pairings/{id}/approve`, passkey-signed if the
   admin has a passkey). `approve_pairing` creates or attaches the system, sets it `active`, and stores the new
   agent token in the secret store.
4. Agent: `POST /agent/pair/{id}/status {secret}` returns the token once (status → `collected`).

The UI's `setup_cmd` also carries `--ca-fingerprint` and, if passkeys exist, `--passkeys-sha256`. It is only
offered when the served agent is ≥ 0.12.0 (`SECURE_SETUP_VERSION`).

### Report
`POST /agent/report` (bearer agent token) validates the inventory (pydantic limits) and builds a CycloneDX SBOM
from the packages (`sbom.py`). It then writes `data/sboms/<id>.json` atomically, updates the system row, and
returns `needed_sboms`: image IDs from the system's inventory without a stored SBOM.
The token is checked before the SBOM is built. Container labels are reduced to `com.docker.compose.*` and
`org.opencontainers.*`. `POST /agent/image-sbom` stores `data/images/<system>/<sha>.json` if the ID appears in
**that system's own inventory**. Each system has its own copy, and the worker scans identical content only once
(cache keyed by SHA-256 of the file).

### Long-poll and commands
`POST /agent/commands/next?wait≤45` checks every second whether a report is due or commands are queued. It marks
commands `sent` and always includes the current passkey trust list. Results come back through
`POST /agent/commands/{id}/result` (only from the target system, only while `sent`). Limits: queued commands
expire after 5 min, `sent` ones fail after 15 min, at most 5 open per system.

### Signed commands (`passkeys.py`)
- `POST /systems/{id}/commands/prepare {type}` builds the canonical JSON envelope
  `{kind:"command", system_id, type, params, issued_at, expires_at:+300 s, nonce}` and returns WebAuthn request
  options with `challenge = SHA-256(envelope)`, restricted to credentials in the agents' **trusted list**.
- `POST /systems/{id}/commands/confirm {credential}` verifies the assertion server-side too, then stores the
  command with `envelope` + `assertion`. The **agent's root part verifies it again** (see agent INTERNALS §5.7),
  so a hijacked server can't forge one.
- Trust list: the first passkey registered creates revision 1 **unsigned**. Later revisions are signed through
  `POST /passkeys/trust/options` + `POST /passkeys/trust` with a key from the current list.

### Agent releases (`releases.py`)
Every minute (and on demand) the server reads `latest.json` and `release.pub` from the read-only volume that
`agent-sign` writes (`VULNWATCH_AGENT_RELEASES_DIR`). It verifies the Ed25519 signature of the manifest and every
checksum, takes a release only if it is newer or signed with a different key, copies it into `data/agent-releases/`
and serves it from there. Build and signing: `agent/docs/INTERNALS.md`, section 5.10.

## 8. Scan pipeline

```
trigger (UI or 03:00 UTC) → request_scan_run: run "collecting", set refresh.requested
   agents see report=true on their next long-poll → fresh reports + image SBOMs
advance_collecting_runs (on every report and every 60 s): all active systems fresh, or 10 min passed
   → run "queued" + ScanJob with payload {systems:[{id,name,sbom?,images:[…]}]}
worker: POST /worker/claim → GET sbom/image-sbom per entry → grype db update → freshness gate (≤36 h)
        → canary (log4j 2.14.1 must be KEV-critical) → grype per SBOM → POST /worker/jobs/{id}/result
process_scan_result: canary or DB not ok → run "failed" (findings untouched)
   per system: no SBOM / error → "fehler", findings untouched (never silently "resolved")
   ok → upsert findings by (target, cve, component, version), mark missing ones resolved, reopen expired accepts
   severity from rules.classify_severity (KEV → critical, …)
→ report text (report.py) → Apprise notification
expire_stale_jobs: no claim or no result within 30 min → run failed + alert
```

The worker never sees the DB or the master key. It gets exactly the SBOMs listed in the job, and only while the
job is `running`.

## 9. Live updates (`events.py`)

`GET /api/events` (session required, at most 50 streams) sends Server-Sent Events. A SQLAlchemy hook collects
the touched tables per commit and publishes **topic names only** (`systems`, `runs`, `findings`, …). The browser
then re-fetches through the normal API. A watcher compares a snapshot every 10 s for time-based changes
(online/offline).

## 10. API endpoints

| Method + path | Auth | Purpose |
|---|---|---|
| GET `/api/state` | none | setup done? logged in? (+ CSRF token if logged in) |
| POST `/api/setup/totp`, `/api/setup/complete` | setup token | first setup |
| POST `/api/login`, `/api/login/passkey/options`, `/api/login/passkey` | password + 2nd factor | login |
| POST `/api/logout` | session + CSRF | |
| GET `/api/overview`, `/api/systems`, `/api/systems/{id}`, `/api/findings`, `/api/runs`, `/api/runs/{id}`, `/api/pairings`, `/api/passkeys`, `/api/systems/{id}/commands`, `/api/settings/*`, `/api/integrations/*`, `/api/systems/agent-update`, `/api/events` | session | read |
| POST/PUT/DELETE everything else under `/api/systems`, `/api/findings`, `/api/runs/trigger`, `/api/pairings`, `/api/passkeys`, `/api/settings`, `/api/integrations` | admin (session + CSRF) | change |
| POST `/api/agent/enroll` | enrollment token | |
| POST `/api/agent/pair`, `/api/agent/pair/{id}/reveal`, `/api/agent/pair/{id}/status` | none / commitment / pairing secret | |
| POST `/api/agent/poll`, `/report`, `/image-sbom`, `/commands/next`, `/commands/{id}/result` | agent token | |
| GET `/api/agent/download/{arch.pkg}`, `/api/agent/release/{manifest…}` | none | signed artifacts |
| `/api/worker/*` | worker token (blocked by Caddy from outside) | |
| GET `/api/internal/tls-allowed` | none (blocked by Caddy from outside) | |

## 11. Web UI (`web/`)

Vue 3 + Vite. `src/api.js` wraps `fetch` (same-origin cookies, `X-CSRF-Token` on non-GET). `src/live.js`
consumes SSE. `src/webauthn.js` wraps `navigator.credentials`. The views are Overview, Systems (pairing,
commands, install command), Findings, Runs, Settings, Setup and Login. There is no `v-html`: every value is
rendered as escaped text, and the setup QR code is an `<img>` with an SVG data URL.

## 12. Development and tests

See `AGENTS.md`: prefix with `CI=true` and append `< /dev/null`.

```bash
cd server && .venv/bin/pytest            # server
cd web && npm test && npm run build      # UI
cd deploy && docker compose build server && docker compose up -d --no-deps server
```
