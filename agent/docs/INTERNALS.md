# vulnwatch agent: internals

How the agent is built, what runs where with which rights, and how every flow works. New to Go? Read
[GO-GUIDE.md](GO-GUIDE.md) first. The threat model is in [SECURITY.md](../../SECURITY.md).

State: agent 0.11.x (2026-10-25).

---

## 1. The big picture: one binary, three roles

The package installs a single binary, `/usr/bin/vulnwatch-agent`. systemd runs it in three different roles with
very different rights:

```
                      HTTPS (pinned CA), outgoing only
   vulnwatch master  ◄──────────────────────────────────┐
                                                        │
 ┌──────────────────────────────────────────────────────┴───────────┐
 │ vulnwatch-agentd.service   "daemon"                              │
 │ user vulnwatch, no capabilities, network: yes                    │
 │ long-poll, send reports, receive commands                        │
 └───────┬───────────────────────────────▲─────────────────┬────────┘
         │ writes request files          │ reads results    │ writes request
         ▼ /run/vulnwatch/*.request      │ /run/vulnwatch-out
 ┌────────────────────────────────────┐  │   ┌───────────────────────────────────┐
 │ vulnwatch-collect.service          │──┘   │ vulnwatch-action.service          │
 │ "collect-job", root, NO network    │      │ "action-job", root, NO network    │
 │ dpkg/rpm, apt, Docker socket, Syft │      │ verifies passkey signature, then  │
 │ fixed queries                      │      │ reboot / update / uninstall,      │
 │ started by vulnwatch-collect.path  │      │ keeps the trusted passkey list    │
 └────────────────────────────────────┘      │ started by vulnwatch-action.path  │
                                             └───────────────────────────────────┘
```

**Why the split:** the part that talks to the network (and could be attacked from it) has no rights. The parts
with root rights have no network and treat everything the daemon gives them as untrusted input.

| Role | Sub-command | User | Network | What it may do |
|---|---|---|---|---|
| Daemon | `daemon` | `vulnwatch` | yes (IPv4/6 only) | write only `/run/vulnwatch`, read `/etc/vulnwatch` (group) |
| Collector | `collect-job` | root (only `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`) | **no** (`PrivateNetwork`, only `AF_UNIX`) | read the system and the Docker socket; write `/run/vulnwatch-out` |
| Action handler | `action-job` | root (full) | **no** | reboot, `dpkg`/`rpm`, write `/etc/vulnwatch/passkeys.json`, `/var/lib/vulnwatch-action` |
| Admin CLI | `setup`, `enroll`, `scan` | root (run by hand) | yes | write the configuration |

## 2. Files and directories

| Path | Owner / mode | Written by | Content |
|---|---|---|---|
| `/etc/vulnwatch/agent.json` | root:vulnwatch 0640 | `setup`/`enroll` | server URL, agent token, CA fingerprint, CA file path, system ID, optional `passkeys_sha256` |
| `/etc/vulnwatch/ca.pem` | 0644 | `setup`/`enroll` | pinned root certificate of the master |
| `/etc/vulnwatch/passkeys.json` | root 0644 | action handler | trusted passkey list (signed envelope) |
| `/run/vulnwatch/` | vulnwatch 0750 | daemon | `collect.request`, `action.request`, `update/` (staged update files) |
| `/run/vulnwatch-out/` | root:vulnwatch 0750 | collector, action handler | `result.json`, `sbom-N.json`, `action-result.json` |
| `/var/lib/vulnwatch-action/` | root 0700 | action handler | `nonces.json` (replay protection), `last-reboot` |

The directories under `/run` come from `packaging/tmpfiles.conf`. `/var/lib/vulnwatch-action` comes from
`StateDirectory=` in the action unit.

## 3. Packages (`internal/…`)

| Package | Job | Runs in |
|---|---|---|
| `config` | load, validate and save `agent.json`; `Validate()` refuses to run without a pinned CA whose fingerprint matches | all |
| `client` | all HTTP to the master; `FetchCA` (only TLS-unverified call), `New` (pinned CA only) | daemon, CLI |
| `collector` | inventory: os-release, kernel, dpkg/rpm packages, security update count, reboot flag, Docker containers | collector |
| `images` | `SyftSBOM(imageID)`: CycloneDX SBOM of a local image via the Syft library and the Docker socket | collector |
| `jobs` | file IPC daemon ↔ collector; `ReadNoFollow`, `TakeFile`, `WriteAtomic` | both |
| `queries` | four fixed read-only queries: `disk_usage`, `failed_units`, `listening_ports`, `uptime` | collector |
| `passkey` | verifies WebAuthn ES256 assertions against the trusted list | action handler |
| `actions` | root side of `reboot`, `update_agent`, `uninstall`, and of the passkey list update | action handler (+ daemon helpers `Submit`/`Wait`) |
| `release` | signed manifest (version + SHA-256 per file), Ed25519 verify, `Newer` (no downgrades) | action handler, CI |
| `pairing` | pairing code and secret for `setup` | CLI |
| `discover` | mDNS search for `_vulnwatch._tcp` | CLI |

`cmd/vulnwatch-agent/main.go` glues these together. `cmd/vw-release` is the tool that creates the signing key, plans and signs
releases.

## 4. Trust anchors (what the agent believes, and why)

| Anchor | Where | Set by | Protects against |
|---|---|---|---|
| Master's root CA (pinned) | `ca.pem` + fingerprint in `agent.json` | `enroll` (checked against a fingerprint from the UI) or `setup` (trust on first use + pairing code) | someone impersonating the master |
| Agent token | `agent.json` | master, at enroll/pairing | someone impersonating this agent |
| Passkey trust list | `/etc/vulnwatch/passkeys.json` | first list: only the one whose SHA-256 came with the setup command (`--passkeys-sha256`), otherwise trust on first use; later lists must be signed by a passkey already in it | a hijacked master issuing reboots/updates |
| Release public key | compiled in (`release.publicKeyB64`, set by `-ldflags -X` in `packaging/build-agent.sh`) | `vw-release init-key` in the `agent-key` container | a hijacked master serving a forged agent |

## 5. Flows

### 5.1 Install

The UI shows a one-liner. It detects the architecture, downloads the `.deb`/`.rpm` from the master
(`curl -k`, because the CA is not trusted yet), **checks the SHA-256 that is embedded in the command**, installs
it, and then runs `enroll` or `setup`.

`postinst.sh` creates the user and group `vulnwatch`, fixes the permissions on `/etc/vulnwatch`, creates the
`/run` directories and enables `vulnwatch-agentd.service` plus both `.path` units.

### 5.2 `enroll` (token from the UI)

`runEnroll` in `main.go`:

1. `client.FetchAndVerifyCA(server, fp)` fetches `/ca.crt` without TLS checks, then **aborts unless its SHA-256
   equals `--ca-fingerprint`**. Nothing secret is sent before this.
2. `client.New(..., caPEM)`: from now on only that CA is trusted, with full hostname checks.
3. `POST /api/agent/enroll` with the one-time token, which returns the agent token.
4. `config.SaveConfig` writes `agent.json` (0600, then 0640 root:vulnwatch) and `ca.pem`, then restarts the
   daemon.
5. The admin approves the host in the UI. Until then the master answers `403 waiting for approval`.

### 5.3 `setup` (pairing without a token)

`runSetup` in `main.go`:

1. If `--master` is missing, `discover.Masters` asks via mDNS. Exactly one answer is required.
2. With `--ca-fingerprint` (part of the command the UI shows), it calls `client.FetchAndVerifyCA` and aborts
   on a mismatch before anything is sent. Without it, `client.FetchCA` uses trust on first use, and the
   pairing code is the only check.
3. **Commit:** `POST /api/agent/pair {hostname, commitment = SHA-256(secret)}`. The master answers with a fresh
   random `nonce` (16 bytes hex). A master without a nonce (old protocol) is refused.
4. **Reveal:** `POST /api/agent/pair/{id}/reveal {secret}`. The master checks it against the commitment and
   only now computes the code.
5. The host prints `pairing.Code(fp, secret, nonce)`: the first 6 base32 characters of
   `SHA-256(FP:secret:nonce)`. The admin compares it with the UI and approves.
6. The agent polls `POST /api/agent/pair/{id}/status` with the secret. On approval it receives the agent token
   **once**, saves the config (pinned CA, optional `passkeys_sha256`), and restarts the daemon.

Why commit first: someone in the middle has to commit to a secret at the real master before it sees the
master's nonce, and before it knows the host's secret. It can't search for a secret that produces the host's
code. Each attempt costs a new request, at 2⁻³⁰ odds (rate-limited, at most 2 open per IP).

### 5.4 Daemon loop

`runDaemon` → `daemonStep`, forever:

1. Load the config. If it is missing, wait 30 s (not set up yet).
2. After a start or restart: send a report right away (`force`).
3. `POST /api/agent/commands/next?wait=45`: a **long-poll**. The master answers immediately if a report is due
   or commands are waiting, otherwise after 45 s. The answer always contains the master's current passkey list
   (`passkeys`).
4. `syncPasskeys`: if the offered list has a higher revision, hand it to the action handler, which decides
   whether to accept it (§5.8).
5. If `report: true`, send a report (§5.5).
6. For each command, call `runCommand` and post its result to `/api/agent/commands/{id}/result`.
7. Errors: wait 60 s. If the token was rejected (401, or 403 "revoked"), wait 15 min.

The agent opens **no listening port**. Every connection goes out from the host.

### 5.5 Report and image SBOMs

`deliver(cl, viaCollector(p))`:

1. The daemon writes `{"nonce": …}` to `/run/vulnwatch/collect.request`.
2. `vulnwatch-collect.path` notices the file and starts `vulnwatch-collect.service` as root.
3. `Paths.Take` reads the request with `ReadNoFollow` (no symlinks, only regular files, at most 64 KiB) and
   deletes it. `collector.Collect` gathers the inventory. `Execute` writes `result.json` atomically.
4. The daemon polls for `result.json` with **its** nonce and sends the report to `/api/agent/report`.
5. The master answers with `needed_sboms` (image IDs it has no SBOM for). The daemon keeps only IDs **that
   appear in its own container list** (at most 10 per round) and submits a second request with `sbom_images`.
6. The collector checks the IDs again against its own fresh inventory, runs Syft per image, writes
   `sbom-N.json`, and the daemon uploads each one to `/api/agent/image-sbom`.

So the master can never make the collector touch an image that isn't on the host.

### 5.6 Commands without a signature

| Type | What happens |
|---|---|
| `report_now` | same as §5.5 (skipped if a report was just sent) |
| `query` | name must be in `queries.Names`; collector runs the fixed query and returns its text output |

The master has the same allowlist (`commands.py`). Unknown types are answered with `rejected`.

### 5.7 Signed commands: `reboot`, `update_agent`, `uninstall`

```
Admin UI ─ prepare ─► master builds envelope {"kind":"command","system_id","type","params",
                      "issued_at","expires_at"(+5 min),"nonce"} and asks the browser for a passkey
                      signature with challenge = SHA-256(envelope)
Admin touches passkey ─ confirm ─► master stores envelope + assertion as the command's params
Daemon gets it via long-poll ─► runSigned ─► /run/vulnwatch/action.request
vulnwatch-action.service (root, no network) ─► actions.Env.command():
    1. passkey.Verify(trust list, envelope, assertion)
         - credential ID is in the trusted list
         - clientDataJSON.type == "webauthn.get"
         - clientDataJSON.challenge == base64url(SHA-256(envelope))     ← binds the signature to this exact command
         - origin is https://<rp_id>, rpIdHash matches, UP and UV flags set
         - ECDSA P-256 signature over authenticatorData ‖ SHA-256(clientDataJSON)
    2. envelope.kind == "command", system_id == own system ID, not expired, issued_at ≤ now + 120 s
       (since 0.13: system_id 0 with system_ids [..] containing the own ID is accepted for update_agent only,
       so one touch updates several hosts; reboot and uninstall stay one host per touch)
    3. nonce never seen before (nonces.json)  ← replay protection
    4. run the type
```

| Type | Root side does |
|---|---|
| `reboot` | refuses if the last reboot was < 30 min ago; `systemd-run --on-active=<10…600 s> systemctl reboot` |
| `update_agent` | §5.9 |
| `uninstall` | `systemd-run --on-active=10 dpkg --purge vulnwatch-agent` (or `rpm -e`). `postrm` deletes config, token, passkey list and user |

### 5.8 Passkey trust list

- The master builds `{"kind":"passkeys","rev":N,"rp_id":…,"keys":[{id,x,y}…],"issued_at"}`.
- **No local list yet:** if `agent.json` has `passkeys_sha256`, only the list with exactly that SHA-256 is
  accepted. Otherwise any valid-looking list is accepted (trust on first use).
- **Local list exists:** the new revision must be higher **and** signed (same `Verify` as above, with the
  envelope as the challenge) by a key that is **already** trusted.
- Removing a passkey in the UI does not affect agents until a new list is signed (documented in `SECURITY.md`).

### 5.9 Agent update

1. The daemon (`stageUpdate`) downloads `manifest.json`, `manifest.json.sig` and the right package into
   `/run/vulnwatch/update/`.
2. The action handler copies those three files with `ReadNoFollow` into a fresh root-only temp dir. All checks
   run against **that copy**, so the daemon can't swap files after the check (TOCTOU).
3. `release.Verify`: Ed25519 signature with the compiled-in key, manifest version == the version in the signed
   envelope, `Newer` than the running version (no downgrade), and the package's SHA-256 matches the manifest.
4. `dpkg -i` / `rpm -U`. `postinst` restarts the services, and the new daemon reports its version. The master
   marks the command done when the reported version is high enough.

### 5.10 Release pipeline

Every install builds its own agents (`deploy/compose.yaml`, image `deploy/Dockerfile.agent`). The image build
downloads the modules and nfpm, then runs `go vet` and `go test`; the containers run without network:

1. `agent-key`: `vw-release init-key` creates the Ed25519 key in the volume `agent_key` on the first start and writes
   the public key to `agent_releases/release.pub`.
2. `agent-build` (no key): `packaging/build-agent.sh` asks `vw-release plan` whether anything changed (SHA-256 over
   the sources without `_test.go`, plus the public key, against `latest.json`). If so, it builds amd64 and arm64
   binaries with the version and public key as `-ldflags -X`, packages them with nfpm and leaves them in
   `agent_stage`.
3. `agent-sign`: `vw-release publish` (standard library only) signs the manifest, verifies it, moves the release to
   `agent_releases/<version>/` and updates `latest.json`.

The server mounts `agent_releases` read-only, checks every minute, verifies signature and checksums and serves the
newest release (`master` `releases.py`).

**Versions.** `VERSION` is the base. `release.NextVersion` uses it when it is newer than the last release, otherwise
the last release's patch number plus one. `AgentVersion` in `main.go` is `dev` and only matters for `go run`.

**Releasing a change:** `docker compose up -d --build` in `deploy/`, then **Systems → Update all** (one passkey touch)
and **Report now** on a host to see data from the new version.

## 6. systemd hardening at a glance

| Setting | agentd | collect | action |
|---|---|---|---|
| User | vulnwatch | root | root |
| Capabilities | none | `DAC_READ_SEARCH`, `DAC_OVERRIDE` | all |
| Network | AF_INET/6 | none (`PrivateNetwork`) | none (`PrivateNetwork`) |
| File system | `ProtectSystem=strict`, writes `/run/vulnwatch` | `strict`, writes `/run/vulnwatch*` | writable (dpkg needs it) |
| `NoNewPrivileges`, `PrivateTmp`, `Protect*`, `SystemCallFilter` | yes | yes | most |

## 7. Tests

`CI=true go test ./... < /dev/null` in `agent/`. Notable tests: `actions_test.go` (rejections: wrong system,
expired, replay, unsigned list update, downgrade), `passkey_test.go` (uses a software authenticator in
`passkey/passkeytest`), `client_test.go` (CA pinning), `main_test.go` (the daemon flow end to end with fakes).
