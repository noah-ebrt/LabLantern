# Agents

An agent is a small Go program in a `.deb` or `.rpm` package (amd64, arm64). It runs as three parts:

| Part | Runs as | Does |
| --- | --- | --- |
| `vulnwatch-agentd` | user `vulnwatch`, no rights | keeps one outgoing HTTPS connection to the master, sends reports, receives commands |
| `vulnwatch-collect` | root, no network | reads packages, pending security updates, reboot flag, Docker containers and image SBOMs |
| `vulnwatch-action` | root, no network | reboot and agent update, only with a passkey signature it verifies itself |

No port is opened on the host. The master never holds a key to log in to your hosts.

## Add a host

**Systems → Add Linux agent** shows a setup command with the master address and the CA fingerprint. Run it on the
host. It downloads the package from the master, verifies its checksum, installs it and starts pairing:

1. The agent finds the master (mDNS, or the address in the command) and pins its certificate authority.
2. Host and master show the same pairing code. Compare it under **Systems → Pending pairings** and approve. With a
   passkey registered, the approval needs a touch.
3. The first report arrives within seconds; the next full run scans the host.

For hosts where nobody can compare a code, use the one-time token in the same dialog (valid 60 minutes), then
approve the host in the list.

## What an agent reports

- OS name and version, kernel, architecture
- installed packages (dpkg, rpm, apk) as an SBOM, pending security updates, reboot required
- Docker and Podman containers (also stopped ones) with runtime, image, image ID, registry digests, published ports
  and a safe subset of labels (`com.docker.compose.*`, `org.opencontainers.*`, `traefik.enable` and Traefik router
  labels from 0.17). **Never** environment variables, Traefik middlewares or services, or other labels.
- Podman (from 0.17): the agent asks the rootful socket `/run/podman/podman.sock` and every rootless socket
  `/run/user/<uid>/podman/podman.sock` over the Docker-compatible API. If Podman is installed but no socket is active,
  the host shows a containers error. Enable it with `systemctl enable --now podman.socket`, or for rootless Podman
  as that user `systemctl --user enable --now podman.socket` plus `loginctl enable-linger <user>`. Podman images
  are exported over the socket into a temporary file for the SBOM, so the host needs free space of about the image
  size, as with Docker. Images built locally (`localhost/…`) get no version check.
- an SBOM per container image, generated locally with Syft

Reports come about every 55 minutes on their own, and immediately when a full run asks for fresh data.

## Commands

From the host dialog: **Report now** and fixed read-only queries (uptime, disk usage, failed services, open ports).
**Reboot** and **Update agent** need a passkey touch, and the agent checks that signature itself. A compromised
master can neither reboot your hosts nor install anything on them.

## Updates

When a newer signed release is available, **Systems** shows "Agent X is available" with **Update all**. Agents from
0.13 on accept one passkey touch for all listed hosts. Older agents need one touch each, one after another. The agent
only installs a package signed by the release key and newer than itself. The same card has the manual command
(copy button) for hosts that are not connected.

## Remove a host

**Systems → Delete** sends an uninstall command (passkey) and removes the host once the agent confirms.
**Revoke** only blocks the agent's token. Manually: `sudo apt purge vulnwatch-agent` (or `rpm -e`).

## Change the agent

The agent is part of this repository (`agent/`, Go). Your master builds it, signs it with its own key and offers it
to your hosts. No release server or CI is involved:

1. Change the code in `agent/`, or `git pull` to get upstream changes.
2. In `deploy/`: `docker compose up -d --build`. The image build runs `go vet` and `go test`; a failing test stops
   the build and your hosts keep the current agent. You do not need Go installed.
3. Within a minute **Systems** shows "Agent X is available". **Update all** updates every host with one passkey
   touch.

The version comes from `agent/VERSION`. If you change the code without raising it, the build takes the next patch
version (0.16.0 → 0.16.1), so changed code never ships under an old version. Changes to tests or docs alone build
nothing new. `docker compose logs agent-build agent-sign` shows what happened.

**The signing key.** The first start creates an Ed25519 key in the volume `agent_key`. Only the containers
`agent-key` and `agent-sign` mount it; they run nothing but `vw-release` and have no network. Every agent carries the
public key from its build and installs only updates signed with it. Back up `agent_key` (see
[INSTALL.md](INSTALL.md#5-backup-and-restore)): with a new key, hosts accept no more updates until you run the setup
command on them once more.
