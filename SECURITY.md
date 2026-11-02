# Security

Principle: neither a compromised master nor a compromised agent may become a weapon against the other hosts.
Convenience (commands, updates, reboots, automatic discovery) is fine as long as every dangerous action depends on
something the attacker does not have at that point.

## Building blocks

| Part | Protection |
|---|---|
| Web UI | LAN only, behind Caddy with its own internal CA; login with password plus TOTP or passkey; CSRF token; rate limits |
| Live updates | Server-sent events only with a valid session (cookie, same origin), the session is re-checked continuously and logging out ends the stream; the stream carries topic names only, data comes through the normal API; at most 50 connections |
| Secrets | AES-256-GCM with a master key that exists only in the server container; fields are write-only; a stored password or token is only reused for the same address (scheme, host, port): a changed address needs it entered again, so a stolen session cannot redirect it |
| Worker | own container without the data and key volumes, job API only |
| Agent connection | the agent connects out (no listening port), TLS against the pinned Caddy CA, the agent token is stored only as a hash on the server |
| Image SBOMs | stored per system: an agent can only deliver the SBOMs of its own host |
| Client IP | `X-Forwarded-For` is believed only from the proxy's fixed address (own network `edge`); login lockout per user and address |
| Agent on the host | `vulnwatch-agentd` runs as user `vulnwatch` without capabilities; `vulnwatch-collect` and `vulnwatch-action` run as root **without network**; hand-over through files that root reads without following symlinks |
| Commands | fixed list without arguments and without a shell, expire after 5 minutes, at most 5 open per host, result accepted only from the receiving host |
| Reboot, agent update | passkey signature over exactly this command envelope (host, type, parameters, expiry, nonce), verified **by the root part of the agent**; each nonce once; at most one reboot per 30 minutes. An `update_agent` envelope may name several hosts ("Update all" with one touch); the package must still be signed and newer. Reboot and removal stay one touch per host, so that one touch never takes down all hosts at once |
| Agent releases | each install builds its agents from `agent/` and signs the manifest with its own Ed25519 key, created on first start. The private key lives only in the volume `agent_key`, mounted only by `agent-key` and `agent-sign`, which run nothing but `vw-release` (Go standard library) and have no network. `agent-build` (Go toolchain, nfpm) never sees the key. The server reads the signed packages read-only. The agent checks the signature against the key compiled into it, the version (no downgrade) and the checksum of the copy it installs |
| Passkey list of the agents | the setup command contains the SHA-256 of the current list (`--passkeys-sha256`): only exactly this list is accepted as the first one (without a passkey at setup time: trust on first use); every later list must be signed by an already trusted passkey |
| Pairing new hosts | the setup command from the UI contains the CA fingerprint (a wrong master aborts at once). Without it the agent first commits to SHA-256(secret), the master answers with a fresh random nonce, then the agent reveals; code = SHA-256(fingerprint : secret : nonce). A man in the middle gets one chance in 2³⁰ per request (requests per address are limited, at most 2 open). The admin compares the code and approves with a passkey; the token is issued once and only to the holder of the secret |
| mDNS announcement | own container without data or rights; a forged announcement fails at the code comparison |

## Threat model

| Attacker controls | can | cannot |
|---|---|---|
| the master's server container | read inventory and findings, request reports, run the fixed queries; at the admin's next passkey touch (even a login) obtain a signature over a command or passkey list of its choice (see Known limits): then reboot hosts (at most once per 30 minutes each), remove agents, or add its own passkey to the agents' list | act on the hosts before the admin touches a passkey, ship foreign agent code (no release key), run shell commands (there are none) |
| one `vulnwatch-agentd` | forge its own reports, trigger collection and queries on its own host | become root, reboot or update without a valid passkey signature, attack other hosts or the master |
| an attacker in the LAN | announce a master, send pairing requests (rate limited) | pass pairing (the code does not match, the admin must approve), read traffic (pinned TLS) |
| root on the master's Docker host | everything the server container can, plus sign agent releases (key volume): combined with the admin's next passkey touch this is root on every host ("Update all") | update hosts before the admin touches a passkey again |
| the passkey store (e.g. Vaultwarden) | confirm reboots and updates | create commands without the admin login; updates stay bound to the release signature |

## Known limits

- **A passkey prompt does not show what it signs.** The server chooses the challenge of every passkey prompt, the
  login included. A taken-over master can therefore turn the next touch into a signature over a command or passkey
  list of its choice. Log in with password and TOTP, and touch a passkey only for an action you just started yourself.
  If you suspect the master was taken over, remove each agent together with its configuration
  (`dpkg --purge vulnwatch-agent` or `rpm -e vulnwatch-agent`) and set it up again with the command from the UI; that
  also resets the passkey list the host trusts.
- **First passkey list:** a host set up before there is a passkey (or without the command from the UI) accepts the
  first list unchecked; a compromised master could then give it a list of its own. Create the first passkey before
  setting up hosts.
- **`setup` without `--ca-fingerprint`** (mDNS only): protection depends on the code comparison. Use the command from
  the UI, it contains the fingerprint.
- **Removed passkeys** stay valid on the agents until the new list is signed with a remaining passkey.
- **Passkeys need a host name** (e.g. `vulnwatch.lan`) with a trusted certificate; browsers refuse them on an IP
  address.
- **The agent signing key sits on the master host.** Back up the volume `agent_key` separately (see
  [docs/INSTALL.md](docs/INSTALL.md)). If it is lost, agents accept no more updates until they are set up again.
- The root part `vulnwatch-collect` reads the Docker socket; whoever has root on the host has it anyway.

## Reporting a vulnerability

Please report vulnerabilities in vulnwatch privately through GitHub: **Security → Report a vulnerability** on the
repository page. Do not open a public issue. Leave out addresses, host names and tokens of your own network; a
description and the steps to reproduce are enough.
