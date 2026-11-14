# Agents

An agent is a small Go program in a `.deb` or `.rpm` package (amd64, arm64). It runs as three parts:

| Part | Runs as | Does |
| --- | --- | --- |
| `lablantern-agentd` | user `lablantern`, no rights | keeps one outgoing HTTPS connection to the master, sends reports, receives commands |
| `lablantern-collect` | root, no network | reads packages, pending security updates, reboot flag, Docker containers and image SBOMs; on bare metal also drives and pools (`lsblk`, `zpool`, `/proc/mdstat`, `smartctl` if installed) |
| `lablantern-action` | root, no network | reboot and agent update, only with a passkey signature it verifies itself |

No port is opened on the host. The master never holds a key to log in to your hosts.

## Add a host

**Systems → + Add host → Linux server** shows a setup command with the master address and the CA fingerprint. Run it on the
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
  labels). **Never** environment variables, Traefik middlewares or services, or other labels.
- Podman: the agent asks the rootful socket `/run/podman/podman.sock` and every rootless socket
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

When a newer signed release is available, **Systems** shows "Agent X is available" with **Update all**: one passkey
touch for all listed hosts. The agent
only installs a package signed by the release key and newer than itself. The same card has the manual command
(copy button) for hosts that are not connected.

## Remove a host

**Systems → Delete** sends an uninstall command (passkey) and removes the host once the agent confirms.
**Revoke** only blocks the agent's token. Manually: `sudo apt purge lablantern-agent` (or `rpm -e`).

## Windows

The Windows agent is experimental and deliberately small. It reports:

- the Windows version (with end of support) and the security updates Windows Update lists as pending,
- whether a reboot is due,
- **Protection** (from agent 0.21): whether an antivirus with real-time protection is on (Microsoft Defender, or
  another product registered with Windows Security), whether Defender's signatures are older than 7 days, and
  whether the firewall is on for every network profile. What cannot be read is shown as an error, never as OK; on a
  Windows Server without Defender the antivirus state stays unreadable.
- the programs installed for all users (from agent 0.21). No vulnerability database covers them, so **Package CVEs**
  shows n/a; instead the early warning watches the well-known ones (browsers, VPN and remote-access tools, archivers,
  password managers and similar) by name and version. Programs a user installed only for themselves and Store apps
  are not listed.

It does not report containers or storage.

**Set up:** **Systems → + Add host → Windows PC or server**, then paste the one command into a PowerShell opened with
"Run as administrator" (Windows 10, 11, Server 2019 or newer; it uses the `curl.exe` that ships with Windows). The
command downloads `lablantern-agent.exe`, checks its SHA-256, shows the pairing code and, once you approve it in the web
UI, installs and starts the service `LabLanternAgent`. A one-time token works instead of the code, as on Linux.

**What it installs:**

| Path | Content | Who may write |
|---|---|---|
| `%ProgramFiles%\LabLantern\lablantern-agent.exe`, `agent.log` | program and its log (starts over at 1 MB) | administrators and SYSTEM |
| `%ProgramData%\LabLantern\agent.json`, `ca.pem` | server address, agent token, pinned certificate | administrators and SYSTEM; nobody else may read |

The service runs as LocalSystem: Windows Update refuses the search for pending updates to a service account without
rights. For a report it starts Windows PowerShell with a fixed, read-only script (registry, the Windows Update
search, the state of Defender and the firewall). Security software may ask about that; the first report can take a few minutes because Windows Update is
queried.

Agent 0.20.0 still ran as LocalService and reports "Windows Update could not be queried: access denied". Run the
update command from **+ Add host → Windows → Update or remove the agent by hand** once on such a host; it switches the
service account and tightens the file rights.

**Manage:**

- **Update:** the **Update** button in the host's row, with your passkey, as on Linux. The agent downloads the new
  program, accepts it only if it is signed with this installation's release key and newer than the running one, swaps
  its own file and restarts. If that is not possible (agent too old or offline), the dialog under **+ Add host →
  Windows** has a command that replaces the program by hand; the pairing stays.
- **Run the setup command again** on a host that is already paired, and it updates the program and restarts the
  service instead of pairing again (add `--force` to pair again). That is also the way to repair a broken install.
- **Remove:** `& "$env:ProgramFiles\LabLantern\lablantern-agent.exe" uninstall` in an administrator PowerShell, then
  **Delete** the host in the web UI. The agent does not remove itself on command.
- **Not available:** reboot and the queries (uptime, disk usage …). The Windows agent does not check passkeys, so it
  takes no command beyond "report now" and a signed update.

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
`agent-key` and `agent-sign` mount it; they run nothing but `ll-release` and have no network. Every agent carries the
public key from its build and installs only updates signed with it. Back up `agent_key` (see
[INSTALL.md](INSTALL.md#5-backup-and-restore)): with a new key, hosts accept no more updates until you run the setup
command on them once more.
