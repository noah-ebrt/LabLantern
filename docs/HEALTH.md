# Health monitoring

vulnwatch checks whether your hosts and services are up and keeps their uptime and response times. Other devices,
such as an ESP32 status LED strip, Home Assistant or a script, read the result through a read-only API.

Open **Health** in the sidebar. The page has two tabs:

- **Status:** hosts up, degraded and down, availability over 24 h, 7 and 30 days, a 24-hour bar per host and
  recent outages. Click a host to see response-time charts, every check with its last result and all state changes
  (24 h, 7, 30 or 90 days).
- **Settings:** the monitored hosts, the check generator, router checks and the API tokens.

## Everything under Systems is watched automatically

Every approved agent gets a monitor on its own, with two checks:

- **Agent:** the agent's live connection to vulnwatch. The agent daemon holds a long-poll open, so vulnwatch
  notices within about a minute when it stops. No agent update is needed.
- **Ping** to the address the agent enrolled with.

A host's state combines what vulnwatch sees from outside with what the agent reports:

| Checks from outside | Agent | Host |
| --- | --- | --- |
| ok | ok | up |
| ok | silent | up, with the warning "Agent not reporting" |
| failing | silent | down |
| failing | ok | degraded: likely a network or firewall problem |

Devices without an agent that you connected under **Systems** (TrueNAS, Home Assistant and every
other connector type with a URL) are watched the same way: a ping plus an HTTP(S) check on the address vulnwatch
reads them from. For a pinned, self-signed certificate the HTTP check doesn't verify the certificate; the connector
itself already checks its fingerprint.

If you already monitor such a device by hand under the same address and the same name (system name or device type,
e.g. "TrueNAS"), that monitor is taken over: its API key, history and checks stay, and the default checks are added.
A monitor for a service on that host with a different name (AdGuard Home on the Pi) stays separate.

Revoking an agent or removing a connector removes its monitor. Hosts from Systems can't be deleted from Health, only
paused, but you can add more checks to them (for example HTTP for the web UI).

## Adding other hosts

**Settings → Add host** opens the generator: a name, a host (IP or name) and one or more checks. **Test** runs a
check once before you save it. The quick picks fill in common services (SSH, SMB, RDP, web UI, Home Assistant,
Proxmox VE and Backup Server, TrueNAS, Synology DSM, UGREEN, QNAP, Unraid, OPNsense, pfSense, UniFi, OpenWrt,
Pi-hole, AdGuard Home, DNS, certificate). The ports are the vendors' defaults; change them if yours differ.

| Check | What it does | Typical use |
| --- | --- | --- |
| Ping (ICMP) | echo request | is the host there at all |
| TCP port | connection to a port | SSH 22, SMB 445, RDP 3389, any service |
| HTTP(S) | GET or HEAD; expected status (`2xx`, `200,301`, `200-399`), optional text the answer must contain, optional `Authorization` header, certificate check on or off | web UIs and APIs |
| TLS certificate | days until the certificate expires; degraded below the warning days, down once expired | anything with HTTPS |
| DNS server | A or AAAA query to the server | AdGuard Home, Pi-hole |
| FRITZ!Box: device active | asks the FRITZ!Box whether it sees the device (by MAC or IP) | phones and laptops that ignore ping in Wi-Fi power save |
| FRITZ!Box: internet | connection status of the WAN line (DSL, cable, fibre) | is the internet actually up |
| Heartbeat (push) | the device calls a URL regularly; silence means down | laptops, cron jobs, devices vulnwatch can't reach |

Every check has its own target (optional, otherwise the host), interval, retry interval after a failure, timeout and
two thresholds:

- one success makes a check **up**,
- *failures until degraded* in a row (default 2) make it **degraded**,
- *failures until down* in a row (default 4) make it **down**.

After the first failure the check is repeated at the shorter retry interval (default 10 s). Single dropped packets
therefore don't turn anything red, and a real outage shows after about half a minute.

A host with several checks is **down** when all of them fail and **degraded** when only some of them do.

**Critical** hosts send an alert through your notification channels (the ones that get alerts) when they go down
and again when they are back. If at least three quarters of all hosts fail at once, you get a single "network
outage" alert instead of one per host.

### Router checks (FRITZ!Box)

The two FRITZ!Box checks become available once the FRITZ!Box connector is set up under
**Settings → Exposure**. Use a separate FRITZ!Box user with the right "FRITZ!Box settings"; vulnwatch only reads.
If the FRITZ!Box itself is unreachable, these checks show **unknown**, not down.

Phones change their Wi-Fi MAC address per network by default. Turn off the private address for your home Wi-Fi,
or check by a fixed IP instead.

### Heartbeat

After saving, the generator shows the heartbeat address once (a new one can be made from the list):

```sh
curl -fsS https://vulnwatch.lan:8443/api/health/beat/<token>             # "I'm alive"
curl -fsS "https://vulnwatch.lan:8443/api/health/beat/<token>?state=down" # shutting down: red right away
```

The device must call it at least once per interval (plus the grace time). A systemd unit with `ExecStop=` or a
shutdown script can send `?state=down`.

## API for other devices

Create a token per device under **Health → Settings → API for other devices**. It is shown once; only its hash is
stored. A token can read states, nothing else. Revoke it there at any time.

```sh
curl -s --cacert vulnwatch-ca.crt -H "Authorization: Bearer vwh_…" https://vulnwatch.lan:8443/api/health/states
```

| Endpoint | Returns |
| --- | --- |
| `GET /api/health/states` | compact, for microcontrollers: `{"engine_ok": true, "generated_at": …, "states": {"nas": "up", …}, "critical": ["nas", …]}` |
| `GET /api/health/status` | every host with state, `since`, warning, latency and each check with its state, latency, error and the age of its result; plus a summary and `critical_down` |
| `GET /api/health/status/<key>` | one host |

States are `up`, `degraded`, `down`, `unknown` and `paused`. The key of a host (`nas`) is generated from its name and
can be changed under "API key" in the generator. Devices use it, so changing it breaks their configuration.

**Never green on stale data:** each check carries the age of its result. If a result is older than three intervals,
or the check engine has not run for a minute, the API reports `unknown` and `"engine_ok": false`. A status LED
should show "no data" in that case, the same as when it can't reach vulnwatch at all.

The certificate comes from vulnwatch's own CA: download it from `https://<vulnwatch>/ca.crt` and give it to the
device (`WiFiClientSecure::setCACert` on an ESP32).

### Webhooks

Instead of asking every few seconds, a device can be told. Add a URL under **Health → Settings → API for other
devices → Webhooks**. On every state change (and on pause or resume) vulnwatch sends a `POST` with JSON:

```json
{"event": "health.changed", "ts": 1793000000, "engine_ok": true,
 "changes": [{"slug": "nas", "name": "NAS", "state": "down", "prev": "up", "critical": true}],
 "states": {"nas": "down", "pve": "up"}, "critical": ["nas"]}
```

`states` has the same shape as `/api/health/states`, so a device can use the same code for both. **Test** sends
`"event": "test"` with no changes. The header `X-Vulnwatch-Signature: sha256=<hex>` is an HMAC-SHA256 of the raw body
with the webhook's signing key, shown once when you add it; check it before acting on a call. Plain `http://` works
for devices in your network, `https://` targets need a certificate the master trusts.

A failed delivery is retried once after 5 seconds, then shown at the webhook. Redirects aren't followed. Calls can
arrive out of order: use `ts`. A webhook only fires when something changes, so it can't tell a device that vulnwatch
itself stopped. Read `/api/health/states` once at start and every few minutes as well, and show "no data" when that
fails.

Prometheus users get the same states as `vulnwatch_health_state{monitor="nas"}` (1 up, 0.5 degraded, 0 down,
-1 unknown or paused).

## How it runs

The checks run inside the server container in their own thread pool; each has a hard timeout. Ping uses
unprivileged ICMP sockets, so the container keeps all capabilities dropped; `deploy/compose.yaml` sets
`net.ipv4.ping_group_range` for that. Results are kept for 7 days, hourly summaries for a year.

Health checks only contact the hosts you configured (and the FRITZ!Box), webhooks only the URLs you added. Nothing
else leaves your network.
