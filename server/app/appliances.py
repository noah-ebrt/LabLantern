"""Connectors ohne Agent (PLAN Abschnitt 4.3): TrueNAS über JSON-RPC (WebSocket `/api/current`) und Home Assistant
über REST (`/api/states`). Jede Verbindung ist ein eigenes System mit Status „connector“: Funde und Abdeckung hängen
daran, Scan-Läufe und Agent-Alarme (nur Status „active“) lassen es in Ruhe. Löschen des Systems entfernt die Verbindung.

TLS: Das Zertifikat wird beim Speichern gelesen und per SHA-256-Fingerabdruck gepinnt (TrueNAS hat meist ein
selbstsigniertes). Ein Token geht nur über eine Verbindung mit genau diesem Zertifikat hinaus. TrueNAS nur über
HTTPS: ein API-Key, der einmal über HTTP kam, wird von TrueNAS widerrufen."""
import base64
import hashlib
import http.client
import json
import logging
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from . import eol as eol_mod
from .connectors import NPM_STATE, sync_cert_findings
from .context import Context
from .guards import Guards
from .models import Finding, System, put_setting, setting
from .rules import (BATTERY_LOW_PERCENT, SCRUB_GRACE_DAYS, classify_appliance_alert, classify_backup_age,
                    classify_disk, classify_product, classify_task_age, classify_update)

log = logging.getLogger("vulnwatch.appliances")

CONFIG_KEY = "appliances.config"   # {System-ID: {"kind", "url", "fingerprint"}}
STATE_KEY = "appliances.state"     # {System-ID: letzter Abruf}
KINDS = {"truenas": "TrueNAS", "homeassistant": "Home Assistant", "proxmox": "Proxmox VE", "synology": "Synology DSM",
         "opnsense": "OPNsense"}
HTTPS_ONLY = {"truenas": "TrueNAS only over HTTPS: it revokes an API key that was sent over HTTP",
              "proxmox": "Proxmox VE only over HTTPS, e.g. https://pve.lan:8006",
              "synology": "Synology DSM only over HTTPS, e.g. https://nas.lan:5001: the password must not travel in plain text",
              "opnsense": "OPNsense only over HTTPS, e.g. https://opnsense.lan"}
WITH_ACCOUNT = {"synology": "Account", "opnsense": "API key"}   # zweites Feld neben dem Geheimnis
_URL = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?/?$")
TIMEOUT = 15
MAX_MESSAGE = 20_000_000
MAX_ITEMS = 500
STALE_HOURS = 24.0


class ApplianceError(Exception):
    pass


class _Refused(ApplianceError):   # kein WebSocket unter diesem Pfad
    pass


def secret_name(system_id: int) -> str:
    return f"connector.{system_id}.token"


def _split(url: str) -> tuple[str, str, int]:
    u = urlsplit(url)
    return u.scheme, u.hostname or "", u.port or (443 if u.scheme == "https" else 80)


def _unverified() -> ssl.SSLContext:
    tls = ssl.create_default_context()
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE   # geprüft wird der Fingerabdruck
    return tls


def _fingerprint(sock: ssl.SSLSocket) -> str:
    return hashlib.sha256(sock.getpeercert(binary_form=True) or b"").hexdigest()


def read_fingerprint(url: str) -> str:
    _, host, port = _split(url)
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw, \
                _unverified().wrap_socket(raw, server_hostname=host) as tls:
            return _fingerprint(tls)
    except (OSError, ssl.SSLError) as e:
        raise ApplianceError(f"no TLS connection to {host}:{port} ({e})") from None


def _check_pin(sock: ssl.SSLSocket, pinned: str) -> None:
    if _fingerprint(sock) != pinned:
        raise ApplianceError("TLS certificate changed since it was saved: compare it and trust the new one in settings")


# --- TrueNAS ---------------------------------------------------------------------------------------------------

class _WebSocket:
    """Gerade genug RFC 6455 für JSON-RPC: Textnachrichten, Fragmente, Ping/Pong. Spart eine Abhängigkeit."""
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, sock, host: str, path: str):
        self.sock, self.r = sock, sock.makefile("rb")
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        status = self.r.readline(4096).decode("latin-1")
        headers = {}
        while (line := self.r.readline(4096).decode("latin-1").strip()):
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        if " 101 " not in status:
            raise _Refused(f"WebSocket refused: {status.strip()[:100] or 'no answer'}")
        accept = base64.b64encode(hashlib.sha1((key + self.GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != accept:
            raise ApplianceError("WebSocket handshake failed")

    def _frame(self, opcode: int, data: bytes) -> None:
        n, mask = len(data), os.urandom(4)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _read(self, n: int) -> bytes:
        data = self.r.read(n)
        if len(data) != n:
            raise ApplianceError("connection closed by TrueNAS")
        return data

    def send(self, text: str) -> None:
        self._frame(0x1, text.encode())

    def close(self) -> None:
        self.r.close()   # sonst hält die Datei-Ansicht den Socket offen

    def recv(self) -> str:
        parts, size = [], 0
        while True:
            b0, b1 = self._read(2)
            opcode, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self._read(2), "big")
            elif n == 127:
                n = int.from_bytes(self._read(8), "big")
            mask = self._read(4) if b1 & 0x80 else b""
            size += n
            if size > MAX_MESSAGE:
                raise ApplianceError("TrueNAS answer too large")
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                raise ApplianceError("TrueNAS closed the connection")
            if opcode == 0x9:
                self._frame(0xA, data)
                continue
            if opcode in (0x0, 0x1, 0x2):
                parts.append(data)
                if b0 & 0x80:
                    return b"".join(parts).decode()


class RpcError(ApplianceError):
    pass


class TrueNasClient:
    """Ab 24.10 JSON-RPC 2.0 unter `/api/current`, davor das ältere Protokoll unter `/websocket`
    (`connect`, dann `{"msg": "method"}`). Methoden und Ergebnisse sind in beiden gleich."""

    def __init__(self, url: str, fingerprint: str):
        _, self.host, self.port = _split(url)
        self.n = 0
        try:
            self._open(fingerprint, "/api/current")
            self.legacy = False
        except _Refused:
            self._open(fingerprint, "/websocket")
            self.legacy = True
            self.ws.send(json.dumps({"msg": "connect", "version": "1", "support": ["1"]}))
            if json.loads(self.ws.recv()).get("msg") != "connected":
                self.close()
                raise ApplianceError("TrueNAS refused the API session")

    def _open(self, fingerprint: str, path: str) -> None:
        try:
            raw = socket.create_connection((self.host, self.port), timeout=TIMEOUT)
            self.sock = _unverified().wrap_socket(raw, server_hostname=self.host)
        except (OSError, ssl.SSLError) as e:
            raise ApplianceError(f"TrueNAS unreachable ({e})") from None
        try:
            _check_pin(self.sock, fingerprint)
            self.ws = _WebSocket(self.sock, self.host, path)
        except Exception:
            self.sock.close()
            raise

    def call(self, method: str, *params):
        self.n += 1
        req = ({"id": str(self.n), "msg": "method", "method": method, "params": list(params)} if self.legacy
               else {"jsonrpc": "2.0", "id": self.n, "method": method, "params": list(params)})
        try:
            self.ws.send(json.dumps(req))
            while True:
                msg = json.loads(self.ws.recv())
                if self.legacy and msg.get("msg") == "ping":
                    self.ws.send(json.dumps({"msg": "pong", "id": msg.get("id")}))
                elif msg.get("id") == req["id"]:   # Benachrichtigungen überspringen
                    break
        except (OSError, ValueError) as e:
            raise ApplianceError(f"TrueNAS connection failed on {method} ({type(e).__name__})") from None
        if msg.get("error"):
            err = msg["error"]
            text = (err.get("message") or err.get("reason") or err) if isinstance(err, dict) else err
            raise RpcError(f"{method}: {str(text)[:200]}")
        return msg.get("result")

    def close(self) -> None:
        if getattr(self, "ws", None):
            self.ws.close()
        self.sock.close()


def _version(text) -> str:
    return re.sub(r"^TrueNAS-(SCALE-)?", "", str(text or ""))[:60]


def _update_available(client: TrueNasClient) -> tuple[str, bool]:
    """(neue Version oder "", Neustart ausstehend). 25.10 hat `update.status`, ältere `update.check_available`."""
    try:
        st = client.call("update.status") or {}
        if st.get("code") == "ERROR":
            raise ApplianceError(f"update check failed on TrueNAS: {str(st.get('error'))[:200]}")
        new = (st.get("status") or {}).get("new_version") or {}
        return _version(new.get("version")), False
    except RpcError:
        pass
    st = client.call("update.check_available") or {}
    return (_version(st.get("version")) if st.get("status") == "AVAILABLE" else ""), st.get("status") == "REBOOT_REQUIRED"


def _optional(client: TrueNasClient, method: str, *params):
    """Für Zusatz-Checks: kennt die Version die Methode nicht oder darf die Rolle sie nicht, fehlt nur dieser Check."""
    try:
        return client.call(method, *params)
    except RpcError:
        return None


def _ts(value) -> float | None:
    """Zeitpunkte kommen als {"$date": Millisekunden}."""
    ms = value.get("$date") if isinstance(value, dict) else None
    return ms / 1000 if isinstance(ms, (int, float)) else None


def _interval_days(schedule) -> float:
    """Erwarteter Abstand zweier Läufe aus dem Cron-Schedule der Aufgabe."""
    s = schedule if isinstance(schedule, dict) else {}
    for field, days in (("month", 365), ("dom", 31), ("dow", 7)):
        if str(s.get(field, "*")) != "*":
            return days
    return 1


def _pools(client: TrueNasClient, pools) -> list[dict] | None:
    if not isinstance(pools, list):
        return None
    scrubs = {t.get("pool_name"): t for t in _optional(client, "pool.scrub.query") or []
              if isinstance(t, dict) and t.get("enabled")}
    out = []
    for p in pools[:50]:
        if not isinstance(p, dict):
            continue
        scan = p.get("scan") or {}
        scrubbed = scan.get("function") == "SCRUB"
        size = p.get("size") or 0
        task = scrubs.get(p.get("name"))
        out.append({"name": str(p.get("name") or "")[:100], "healthy": p.get("healthy") is not False,
                    "status": str(p.get("status") or "")[:30], "detail": str(p.get("status_detail") or "")[:300],
                    "percent": round((p.get("allocated") or 0) * 100 / size, 1) if size else None,
                    # Letzter Lauf war ein Resilver: Scrub-Alter unbekannt, kein Fund
                    "scrub_known": not scan or scrubbed,
                    "scrub_end": _ts(scan.get("end_time")) if scrubbed and scan.get("state") == "FINISHED" else None,
                    "scrub_errors": int(scan.get("errors") or 0) if scrubbed else 0,
                    "scrub_threshold": int(task.get("threshold") or 35) if task else None})
    return out


def _job_result(job) -> tuple[float | None, bool, str]:
    """(Ende des letzten erfolgreichen Laufs, letzter Lauf fehlgeschlagen, Fehler) aus dem Job einer Aufgabe."""
    job = job if isinstance(job, dict) else {}
    state = job.get("state")
    return (_ts(job.get("time_finished")) if state == "SUCCESS" else None, state in ("FAILED", "ERROR"),
            str(job.get("error") or "")[:200])


def _tasks(client: TrueNasClient) -> list[dict] | None:
    """Datensicherung: Replikation, Cloud Sync, Rsync, Cloud Backup, Snapshots. Nach einem Neustart fehlt TrueNAS
    der letzte Lauf mancher Aufgaben; die bleiben ohne Zeitpunkt und ohne Fund statt als „nie gelaufen“."""
    out, readable = [], False
    snaps = _optional(client, "pool.snapshottask.query")
    if isinstance(snaps, list):
        readable = True
        for t in snaps[:MAX_ITEMS]:
            if isinstance(t, dict) and t.get("enabled"):
                st = t.get("state") or {}
                out.append({"kind": "snapshot", "name": str(t.get("dataset") or "")[:200], "interval": None,
                            "last_ok": None, "failed": st.get("state") == "ERROR",
                            "error": str(st.get("error") or "")[:200]})
    reps = _optional(client, "replication.query")
    if isinstance(reps, list):
        readable = True
        for t in reps[:MAX_ITEMS]:
            if not isinstance(t, dict) or not t.get("enabled"):
                continue
            st = t.get("state") or {}
            last_ok, failed, error = _job_result(t.get("job"))
            if st.get("state") == "FINISHED":
                last_ok = max(filter(None, (last_ok, _ts(st.get("datetime")))), default=None)
            failed = failed or st.get("state") == "ERROR"
            if t.get("schedule"):
                interval = _interval_days(t["schedule"])
            elif t.get("auto"):   # läuft nach den Snapshot-Aufgaben, die sie überträgt
                interval = min((_interval_days(p.get("schedule")) for p in t.get("periodic_snapshot_tasks") or []
                                if isinstance(p, dict)), default=1)
            else:   # nur von Hand
                interval = None
            out.append({"kind": "replication", "name": str(t.get("name") or "")[:200], "interval": interval,
                        "last_ok": last_ok, "failed": failed, "error": error or str(st.get("error") or "")[:200]})
    for kind, method, name_field in (("cloudsync", "cloudsync.query", "description"),
                                     ("cloud_backup", "cloud_backup.query", "description"),
                                     ("rsync", "rsynctask.query", "desc")):
        tasks = _optional(client, method)
        if not isinstance(tasks, list):
            continue
        readable = True
        for t in tasks[:MAX_ITEMS]:
            if isinstance(t, dict) and t.get("enabled"):
                last_ok, failed, error = _job_result(t.get("job"))
                out.append({"kind": kind, "name": str(t.get(name_field) or t.get("path") or "")[:200],
                            "interval": _interval_days(t.get("schedule")), "last_ok": last_ok, "failed": failed,
                            "error": error})
    return out if readable else None


def _hardening(client: TrueNasClient) -> dict:
    """Nur die Schalter selbst. `ssh.config` enthält die privaten Host-Schlüssel: die Antwort wird nie gespeichert."""
    running = {s.get("service"): s.get("state") == "RUNNING" for s in _optional(client, "service.query") or []
               if isinstance(s, dict)}
    out: dict = {}
    if (smb := _optional(client, "smb.config")) is not None and running.get("cifs"):
        out["smb1"] = bool(smb.get("enable_smb1"))
    if (ssh := _optional(client, "ssh.config")) is not None and running.get("ssh"):
        out["ssh_password"] = bool(ssh.get("passwordauth"))
    if (ftp := _optional(client, "ftp.config")) is not None and running.get("ftp"):
        out["ftp_plain"] = not ftp.get("tls")
    if (general := _optional(client, "system.general.config")) is not None:
        out["ui_http"] = not general.get("ui_httpsredirect")
    if (twofa := _optional(client, "auth.twofactor.config")) is not None:
        out["twofa_off"] = not twofa.get("enabled")
    users = _optional(client, "user.query", [["locked", "=", False]])
    if isinstance(users, list):
        out["admins_without_2fa"] = sorted(
            str(u.get("username"))[:60] for u in users[:MAX_ITEMS]
            if isinstance(u, dict) and "FULL_ADMIN" in (u.get("roles") or []) and not u.get("password_disabled")
            and not u.get("twofactor_auth_configured"))[:20]
    return out


def fetch_truenas(url: str, fingerprint: str, key: str) -> dict:
    client = TrueNasClient(url, fingerprint)
    try:
        if client.call("auth.login_with_api_key", key) is not True:
            raise ApplianceError("TrueNAS rejected the API key")
        info = client.call("system.info") or {}
        new, reboot = _update_available(client)
        alerts = client.call("alert.list") or []
        try:
            # Versionen der Katalog-Apps: `version`/`latest_version` sind die des Charts (vergleichbar),
            # die App-Version selbst steht nur in den Metadaten
            apps = [{**a, "app_version": (a.get("metadata") or {}).get("app_version") or a.get("human_version")}
                    for a in client.call("app.query") or [] if isinstance(a, dict)]
        except RpcError:   # vor 24.10: Apps auf Kubernetes
            apps = [{"name": a.get("name"), "state": a.get("status"), "version": a.get("human_version"),
                     "latest_version": a.get("human_latest_version"), "app_version": a.get("human_version"),
                     "upgrade_available": a.get("update_available"),
                     "image_updates_available": a.get("container_images_update_available")}
                    for a in (client.call("chart.release.query") or []) if isinstance(a, dict)]
        raw_pools = _optional(client, "pool.query")
        pools, tasks, hardening = _pools(client, raw_pools), _tasks(client), _hardening(client)
        storage = _truenas_storage(client, raw_pools)
    finally:
        client.close()
    return {
        "hostname": str(info.get("hostname") or "")[:100], "version": _version(info.get("version")),
        "new_version": new, "reboot_required": reboot,
        "alerts": [{"uuid": str(a.get("uuid") or "")[:80], "klass": str(a.get("klass") or "")[:80],
                    "level": str(a.get("level") or "").upper()[:20], "text": str(a.get("formatted") or "")[:400]}
                   for a in alerts[:MAX_ITEMS] if isinstance(a, dict) and not a.get("dismissed")],
        "apps": [{"name": str(a.get("name") or "")[:100], "state": str(a.get("state") or "")[:30],
                  "version": str(a.get("app_version") or a.get("version") or "")[:60],
                  "chart": str(a.get("version") or "")[:60], "latest": str(a.get("latest_version") or "")[:60],
                  "upgrade": bool(a.get("upgrade_available")), "image_updates": bool(a.get("image_updates_available")),
                  "images": [str(i)[:300] for i in ((a.get("active_workloads") or {}).get("images") or [])][:20]}
                 for a in apps[:MAX_ITEMS] if isinstance(a, dict)],
        "pools": pools, "tasks": tasks, "hardening": hardening, "storage": storage,
    }


def _members(topology: dict) -> tuple[list[tuple[str, dict, str]], str]:
    """([(Laufwerk, vdev-Eintrag, Rolle)], Aufbau der Datenvdevs wie „RAIDZ1“ oder „2× MIRROR“)."""
    members, layouts = [], []
    for role, vdevs in (topology or {}).items():
        for v in vdevs or []:
            if not isinstance(v, dict):
                continue
            leaves = [v] if v.get("type") == "DISK" else [c for c in v.get("children") or [] if isinstance(c, dict)]
            if role == "data":
                layouts.append("STRIPE" if v.get("type") == "DISK" else str(v.get("type") or "?"))
            members += [(str(c.get("disk") or c.get("device") or c.get("name") or "?"), c, role) for c in leaves]
    from .storage import layout_of
    return members, layout_of(layouts)


def _truenas_storage(client: TrueNasClient, raw_pools) -> dict:
    from .storage import disk, pool, storage

    if not isinstance(raw_pools, list):
        return storage(None, None, "pools not readable with this API key")
    boot = _optional(client, "boot.get_state")
    temps = _optional(client, "disk.temperatures") or {}
    pools, member_of = [], {}
    for p, kind in [(p, "ZFS pool") for p in raw_pools[:50] if isinstance(p, dict)] + \
                   ([(boot, "Boot pool")] if isinstance(boot, dict) else []):
        members, layout = _members(p.get("topology") or {})
        for name, leaf, role in members:
            stats = leaf.get("stats") or {}
            errors = sum(int(stats.get(k) or 0) for k in ("read_errors", "write_errors", "checksum_errors"))
            member_of[name] = (str(p.get("name") or ""), str(leaf.get("status") or ""), errors, role)
        size = p.get("size") or 0
        pools.append(pool(p.get("name"), kind, p.get("status"), (p.get("allocated") or 0) * 100 / size if size else None,
                          size or None, layout, [m[0] for m in members]))
    disks = []
    for d in (_optional(client, "disk.query") or [])[:MAX_ITEMS]:
        if not isinstance(d, dict) or not d.get("name"):
            continue
        name = str(d["name"])
        pool_name, status, errors, role = member_of.get(name, ("", "", 0, ""))
        disks.append(disk(name, d.get("model"), d.get("serial"), d.get("size"),
                          "nvme" if name.startswith("nvme") else d.get("type"),
                          "warning" if errors and status.upper() == "ONLINE" else status,
                          temp=temps.get(name) if isinstance(temps, dict) else None, pool_name=pool_name,
                          detail=", ".join(x for x in (f"{role} vdev" if role not in ("", "data") else "",
                                                       f"{errors} read/write/checksum errors" if errors else "") if x)))
    return storage(pools, disks)


TASK_LABELS = {"snapshot": "Snapshot task", "replication": "Replication", "cloudsync": "Cloud sync",
               "cloud_backup": "Cloud backup", "rsync": "Rsync task"}
HARDENING = {   # Schalter: (Stufe, Titel, Abhilfe)
    "smb1": ("hoch", "SMB1 is enabled on TrueNAS: the protocol has no protection against relay and wormable attacks",
             "Shares → SMB → Configure → Enable SMB1 support off"),
    "ssh_password": ("mittel", "SSH on TrueNAS accepts passwords: open to password guessing",
                     "System → Services → SSH → Allow Password Authentication off, use keys"),
    "ftp_plain": ("mittel", "FTP on TrueNAS runs without TLS: logins and data go over the network in clear text",
                  "System → Services → FTP → TLS on, or stop FTP"),
    "ui_http": ("mittel", "TrueNAS web UI also answers over plain HTTP: a login there sends the password in clear text",
                "System → General → GUI → Web Interface HTTP → HTTPS Redirect on"),
    "twofa_off": ("mittel", "Two-factor authentication is off on TrueNAS",
                  "Credentials → 2FA → Enable Two-Factor Authentication Globally"),
}


def _pool_findings(pools: list[dict], now: float) -> list[dict]:
    out = []
    for p in pools:
        base = {"cve_id": "VW-POOL", "component": f"Pool {p['name']}"}
        if not p["healthy"]:
            out.append({**base, "target": f"pool:{p['name']}", "severity": "hoch", "installed_version": p["status"],
                        "fixed_version": "replace the failed disk",
                        "title": f"Pool {p['name']} is {p['status']}: {p['detail'] or 'not healthy'}"[:500]})
        if p["percent"] is not None and (sev := classify_disk(p["percent"])):
            out.append({**base, "cve_id": "VW-DISK", "target": f"disk:{p['name']}", "severity": sev,
                        "installed_version": f"{p['percent']:.0f} %", "fixed_version": "free space",
                        "title": f"Pool {p['name']} is {p['percent']:.0f} % full"})
        scrub = {**base, "cve_id": "VW-SCRUB", "target": f"scrub:{p['name']}"}
        if p["scrub_errors"]:
            out.append({**scrub, "severity": "hoch", "installed_version": f"{p['scrub_errors']} errors",
                        "fixed_version": "check the disks (zpool status)",
                        "title": f"Last scrub of pool {p['name']} found {p['scrub_errors']} errors"})
        elif p["scrub_threshold"] is None:
            out.append({**scrub, "severity": "mittel", "installed_version": "no scrub task",
                        "fixed_version": "Data Protection → Scrub Tasks → Add",
                        "title": f"Pool {p['name']} has no scheduled scrub: silent data corruption goes unnoticed"})
        elif p["scrub_known"]:
            days = None if p["scrub_end"] is None else (now - p["scrub_end"]) / 86400
            if days is None or days > p["scrub_threshold"] + SCRUB_GRACE_DAYS:
                out.append({**scrub, "severity": "mittel",
                            "installed_version": "never" if days is None else f"{days:.0f} days ago",
                            "fixed_version": "check the scrub task",
                            "title": (f"Pool {p['name']} was never scrubbed" if days is None else
                                      f"Last scrub of pool {p['name']} is {days:.0f} days old")})
    return out


def _task_findings(tasks: list[dict], now: float) -> list[dict]:
    out = []
    for t in tasks:
        label = TASK_LABELS.get(t["kind"], t["kind"])
        base = {"target": f"task:{t['kind']}:{t['name']}"[:300], "cve_id": "VW-BACKUP",
                "component": f"{label} {t['name']}"[:200]}
        if t["failed"]:
            out.append({**base, "severity": "mittel", "installed_version": "failed", "fixed_version": "check the task log",
                        "title": f"{label} '{t['name']}' failed: {t['error'] or 'see the task log'}"[:500]})
        elif t["last_ok"] and t["interval"]:
            days = (now - t["last_ok"]) / 86400
            if sev := classify_task_age(days, t["interval"]):
                out.append({**base, "severity": sev,
                            "installed_version": datetime.fromtimestamp(t["last_ok"], timezone.utc).date().isoformat(),
                            "fixed_version": "check the task",
                            "title": f"{label} '{t['name']}' last succeeded {days:.0f} days ago"[:500]})
    if not any(t["kind"] != "snapshot" for t in tasks):
        out.append({"target": "backup", "cve_id": "VW-BACKUP", "component": "TrueNAS backup", "severity": "mittel",
                    "installed_version": "not set up", "fixed_version": "Data Protection → Replication or Cloud Sync",
                    "title": "No replication, cloud sync or rsync task on TrueNAS: its data has no copy elsewhere"})
    return out


def _hardening_findings(hardening: dict) -> list[dict]:
    out = [{"target": f"config:{key}", "cve_id": "VW-CONFIG", "component": "TrueNAS", "severity": sev,
            "installed_version": "on" if key != "twofa_off" else "off", "fixed_version": fix, "title": title}
           for key, (sev, title, fix) in HARDENING.items() if hardening.get(key)]
    if hardening.get("admins_without_2fa") and not hardening.get("twofa_off"):
        names = ", ".join(hardening["admins_without_2fa"])
        out.append({"target": "config:admins_without_2fa", "cve_id": "VW-CONFIG", "component": "TrueNAS",
                    "severity": "mittel", "installed_version": names[:100], "fixed_version": "set up 2FA for them",
                    "title": f"TrueNAS administrators without two-factor authentication: {names}"[:500]})
    return out


def truenas_findings(data: dict, now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    out = []
    if data["new_version"]:
        out.append({"target": "host", "cve_id": "VW-UPDATE", "component": "TrueNAS",
                    "severity": classify_update(data["version"], data["new_version"]),
                    "installed_version": data["version"], "fixed_version": data["new_version"],
                    "title": f"TrueNAS {data['new_version']} is available (installed {data['version']})"})
    for a in data["apps"]:
        if a["upgrade"]:
            latest = a["latest"] or "newer version"
            out.append({"target": f"app:{a['name']}", "cve_id": "VW-UPDATE", "component": a["name"],
                        "severity": classify_update(a.get("chart", a["version"]), a["latest"]),
                        "installed_version": a["version"], "fixed_version": latest,
                        "title": (f"App {a['name']} {a['version']}: update available (app package "
                                  f"{a.get('chart') or '?'} → {latest})")[:500]})
        elif a["image_updates"]:
            out.append({"target": f"app:{a['name']}", "cve_id": "VW-UPDATE", "component": a["name"],
                        "severity": classify_product("outdated"), "installed_version": a["version"],
                        "fixed_version": "newer image", "title": f"App {a['name']}: newer image available"[:500]})
    for a in data["alerts"]:
        sev = classify_appliance_alert(a["level"])
        if sev:
            out.append({"target": f"alert:{a['uuid'] or a['klass']}", "cve_id": "VW-ALERT", "component": a["klass"],
                        "severity": sev, "installed_version": a["level"], "fixed_version": "",
                        "title": f"TrueNAS alert: {a['text']}"[:500]})
    if data.get("pools") is not None:
        out += _pool_findings(data["pools"], now)
    if data.get("tasks") is not None:
        out += _task_findings(data["tasks"], now)
    if data.get("storage"):
        from .storage import drive_findings
        out += drive_findings(data["storage"], "Storage → Disks: check S.M.A.R.T., replace the drive if errors grow")
    return out + _hardening_findings(data.get("hardening") or {})


# --- Home Assistant --------------------------------------------------------------------------------------------

# Kern-Domänen von Home Assistant (Entitätsarten, Helfer, Oberfläche): keine Produkte für die Frühwarnung
HA_BUILTIN = frozenset("""
    homeassistant default_config frontend http api websocket_api auth onboarding config system_log logger recorder
    history logbook energy persistent_notification repairs diagnostics search backup cloud mobile_app my map
    media_source network ssdp zeroconf dhcp usb bluetooth hardware file_upload image_upload tag trace blueprint
    lovelace analytics application_credentials device_automation intent webhook hassio system_health stream ffmpeg
    go2rtc web_rtc conversation assist_pipeline tts stt wake_word intent_script labs ai_task usage_prediction
    sensor binary_sensor switch light cover climate fan lock media_player camera button number select text image
    event update device_tracker person zone sun automation script scene group notify weather calendar todo valve
    siren vacuum water_heater humidifier alarm_control_panel remote lawn_mower date datetime time air_quality
    geo_location image_processing counter timer schedule input_boolean input_number input_select input_text
    input_datetime input_button shopping_list radio_browser google_translate met template
    brands integration file homeassistant_alerts homeassistant_hardware bluetooth_adapters assist_satellite llm
    map_tiles infrared radio_frequency raspberry_pi rpi_power systemmonitor utility_meter switch_as_x plant
    emulated_hue wake_on_lan ping ipp proximity thread otbr
""".split())
# Gerätearten (device_class) tauchen in `components` auf, als wären es Integrationen: Tür, Fenster, Bewegung, …
HA_DEVICE_CLASSES = frozenset("""
    battery door window garage_door gate motion occupancy presence moisture humidity temperature illuminance
    vibration power energy voltage current pressure smoke gas carbon_monoxide opening light sound tamper problem
    connectivity plug outlet running safety heat cold lock
""".split())


def _ha_get(conn, path: str, token: str):
    conn.request("GET", path, headers={"Authorization": f"Bearer {token}", "User-Agent": "vulnwatch"})
    r = conn.getresponse()
    body = r.read(MAX_MESSAGE)
    if r.status == 401:
        raise ApplianceError("Home Assistant rejected the token")
    if r.status != 200:
        raise ApplianceError(f"Home Assistant answered HTTP {r.status} on {path}")
    return json.loads(body)


def _number(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fetch_homeassistant(url: str, fingerprint: str, token: str) -> dict:
    scheme, host, port = _split(url)
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=_unverified())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        conn.connect()
        if scheme == "https":
            _check_pin(conn.sock, fingerprint)
        states = _ha_get(conn, "/api/states", token)
        config = _ha_get(conn, "/api/config", token)
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        raise ApplianceError(f"Home Assistant unreachable ({e})") from None
    except ValueError:
        raise ApplianceError("Home Assistant sent no JSON") from None
    finally:
        conn.close()
    if not isinstance(states, list) or not isinstance(config, dict):
        raise ApplianceError("unexpected answer from Home Assistant")
    return parse_homeassistant(states, config)


def parse_homeassistant(states: list, config: dict) -> dict:
    """Entitäts-IDs hängen von der Sprache ab (sensor.backup_letztes_erfolgreiches_…): erkannt wird deshalb an
    device_class, Einheit und Wertart. Vom Config-Endpunkt nur Zustand und Integrationen, nie Standort oder URLs."""
    updates, batteries, disks, backup_times = [], [], [], []
    backup_seen = False
    host_disk: dict[str, dict[str, float]] = {}
    for e in states:
        if not isinstance(e, dict):
            continue
        eid, state = str(e.get("entity_id", ""))[:200], str(e.get("state") or "")[:60]
        a = e.get("attributes") or {}
        name = str(a.get("friendly_name") or eid)[:200]
        dc, unit = a.get("device_class"), a.get("unit_of_measurement")
        if eid.startswith("update."):
            updates.append({"entity_id": eid, "state": state[:20], "name": str(a.get("title") or name)[:200],
                            "version": str(a.get("installed_version") or "")[:60],
                            "latest": str(a.get("latest_version") or "")[:60]})
        elif dc == "battery" and eid.startswith("sensor.") and unit == "%" and _number(state) is not None:
            batteries.append({"entity_id": eid, "name": name, "level": _number(state), "low": False})
        elif dc == "battery" and eid.startswith("binary_sensor."):
            batteries.append({"entity_id": eid, "name": name, "level": None, "low": state == "on"})
        elif eid.startswith("sensor.backup_"):   # Gerät „Backup“ der Backup-Integration, Name in jeder Sprache gleich
            backup_seen = True
            if dc == "timestamp" and state not in ("unknown", "unavailable", ""):
                backup_times.append(state)
        elif eid.startswith("sensor.") and "disk_use_percent" in eid and unit == "%" and _number(state) is not None:
            disks.append({"entity_id": eid, "name": name, "percent": _number(state)})
        elif eid.startswith("sensor.") and (m := re.match(r"^sensor\.(.+)_disk_(used|total)$", eid)) \
                and _number(state) is not None:
            host_disk.setdefault(m.group(1), {})[m.group(2)] = _number(state)
    for prefix, v in host_disk.items():   # Supervisor: belegt und gesamt in GB
        if v.get("total") and "used" in v:
            disks.append({"entity_id": f"sensor.{prefix}_disk_used", "name": f"{prefix.replace('_', ' ')} disk",
                          "percent": round(v["used"] * 100 / v["total"], 1)})
    integrations = sorted({c for c in config.get("components") or [] if isinstance(c, str) and "." not in c
                           and c not in HA_BUILTIN and c not in HA_DEVICE_CLASSES})
    core = next((u["version"] for u in updates if u["entity_id"] == "update.home_assistant_core_update"), "")
    return {"version": core or str(config.get("version") or "")[:40], "updates": updates[:MAX_ITEMS],
            "state": str(config.get("state") or "")[:30], "safe_mode": bool(config.get("safe_mode")),
            "recovery_mode": bool(config.get("recovery_mode")), "integrations": integrations[:MAX_ITEMS],
            "backup": {"present": backup_seen, "times": backup_times[:10]},
            "batteries": batteries[:MAX_ITEMS], "disks": disks[:50]}


def homeassistant_findings(data: dict, now: datetime) -> list[dict]:
    from .connectors import _expires

    # state „on“ = Update verfügbar; übersprungene Versionen meldet HA als „off“
    out = [{"target": f"update:{u['entity_id']}", "cve_id": "VW-UPDATE", "component": u["name"],
            "severity": classify_update(u["version"], u["latest"]),
            "installed_version": u["version"], "fixed_version": u["latest"],
            "title": f"{u['name']}: update {u['version']} → {u['latest']} available"[:500]}
           for u in data["updates"] if u["state"] == "on"]
    if data.get("recovery_mode") or data.get("safe_mode"):
        mode = "recovery mode" if data.get("recovery_mode") else "safe mode"
        out.append({"target": "host", "cve_id": "VW-HA-MODE", "component": "Home Assistant", "severity": "hoch",
                    "installed_version": data.get("version", ""), "fixed_version": "restart normally",
                    "title": f"Home Assistant runs in {mode}: integrations and automations are not loaded"})
    backup = data.get("backup") or {}
    if backup.get("present"):
        # Zeitstempel der Backup-Sensoren: nächstes geplantes (Zukunft), letzter Versuch, letzter Erfolg.
        # Der älteste vergangene ist der letzte Erfolg, der jüngste der letzte Versuch.
        past = sorted(t for t in (_expires(x) for x in backup.get("times") or []) if t and t <= now)
        days = round((now - past[0]).total_seconds() / 86400, 1) if past else None
        sev = classify_backup_age(days)
        if sev:
            out.append({"target": "backup", "cve_id": "VW-BACKUP", "component": "Home Assistant backup", "severity": sev,
                        "installed_version": past[0].date().isoformat() if past else "never",
                        "fixed_version": "run a backup",
                        "title": ("No successful automatic backup of Home Assistant" if days is None else
                                  f"Last successful Home Assistant backup is {days:.0f} days old")})
        elif len(past) > 1 and (past[-1] - past[0]).total_seconds() > 3600:
            out.append({"target": "backup", "cve_id": "VW-BACKUP", "component": "Home Assistant backup",
                        "severity": "mittel", "installed_version": past[0].date().isoformat(),
                        "fixed_version": "check the backup log",
                        "title": "The last automatic Home Assistant backup failed; the last good one is older"})
    else:
        out.append({"target": "backup", "cve_id": "VW-BACKUP", "component": "Home Assistant backup", "severity": "mittel",
                    "installed_version": "not set up", "fixed_version": "Settings → System → Backups",
                    "title": "No automatic backups configured in Home Assistant"})
    for d in data.get("disks") or []:
        sev = classify_disk(d["percent"])
        if sev:
            out.append({"target": f"disk:{d['entity_id']}", "cve_id": "VW-DISK", "component": d["name"], "severity": sev,
                        "installed_version": f"{d['percent']:.0f} %", "fixed_version": "free space",
                        "title": f"Disk almost full on Home Assistant: {d['name']} at {d['percent']:.0f} %"[:500]})
    for b in data.get("batteries") or []:
        if b["low"] or (b["level"] is not None and b["level"] < BATTERY_LOW_PERCENT):
            level = "low" if b["level"] is None else f"{b['level']:.0f} %"
            out.append({"target": f"battery:{b['entity_id']}", "cve_id": "VW-BATTERY", "component": b["name"],
                        "severity": "info", "installed_version": level, "fixed_version": "replace the battery",
                        "title": f"Battery {level}: {b['name']}"[:500]})
    return out


# --- Abruf -----------------------------------------------------------------------------------------------------

def _configs(s) -> dict[str, dict]:
    """Verbindungen, deren System noch existiert (gelöschtes System = Verbindung entfernt)."""
    cfg = setting(s, CONFIG_KEY) or {}
    return {sid: c for sid, c in cfg.items() if (sys := s.get(System, int(sid))) and sys.status == "connector"}


def _exposed(s, url: str) -> bool:
    _, host, port = _split(url)
    return any(u.get("target") == f"{host}:{port}" for u in (setting(s, NPM_STATE) or {}).get("unmatched", []))


def refresh_one(ctx: Context, sid: str, cfg: dict) -> dict:
    from .products import _eol_finding

    key = ctx.secrets.get(secret_name(int(sid)))
    state = {"at": time.time(), "kind": cfg["kind"]}
    try:
        if not key:
            raise ApplianceError("no token saved")
        if cfg["kind"] == "truenas":
            data = fetch_truenas(cfg["url"], cfg["fingerprint"], key)
            desired = truenas_findings(data)
            db, _ = eol_mod.load(ctx.settings.data_dir / "eol")   # ohne Daten: kein EOL-Fund, der Rest bleibt
            if db and (f := _eol_finding(db, "truenas", data["version"], "eol", "TrueNAS")):
                desired.append(f)
        elif cfg["kind"] == "proxmox":
            from .proxmox import fetch_proxmox, proxmox_findings
            data = fetch_proxmox(cfg["url"], cfg["fingerprint"], key)
            desired = proxmox_findings(data)
            db, _ = eol_mod.load(ctx.settings.data_dir / "eol")
            for n in data["nodes"] if db else []:
                if f := _eol_finding(db, "proxmox-ve", n["version"], f"eol:{n['node']}", "Proxmox VE"):
                    desired.append(f)
        elif cfg["kind"] == "synology":
            from .synology import fetch_synology, synology_findings
            data = fetch_synology(cfg["url"], cfg["fingerprint"], cfg.get("account", ""), key)
            desired = synology_findings(data)   # endoflife.date führt DSM nicht: kein EOL-Fund
        elif cfg["kind"] == "opnsense":
            from .opnsense import fetch_firmware, opnsense_findings
            data = fetch_firmware(cfg["url"], cfg["fingerprint"], cfg.get("account", ""), key)
            desired = opnsense_findings(data)
            db, _ = eol_mod.load(ctx.settings.data_dir / "eol")
            if db and (f := _eol_finding(db, "opnsense", data["version"], "eol", "OPNsense")):
                desired.append(f)
        elif cfg["kind"] == "homeassistant":
            data = fetch_homeassistant(cfg["url"], cfg.get("fingerprint", ""), key)
            desired = homeassistant_findings(data, datetime.now(timezone.utc))
        else:
            raise ApplianceError(f"unknown device kind {cfg['kind']}")
        now = datetime.now(timezone.utc)
        with ctx.session_factory() as s:
            sys = s.get(System, int(sid))
            exposed = _exposed(s, cfg["url"])
            for d in desired:
                d["internet_exposed"] = exposed
            sync_cert_findings(s, sys.id, desired, now, source=cfg["kind"])
            sys.last_seen = now
            sys.reboot_required = bool(data.get("reboot_required"))
            sys.container_count = len(data.get("apps", []))
            sys.collection_errors = "{}"
            sys.inventory_json = json.dumps({"connector": data})
            s.commit()
        state.update(ok=True, error="", version=data["version"], findings=len(desired))
    except ApplianceError as e:
        log.warning("%s connector %s: %s", cfg["kind"], sid, e)
        with ctx.session_factory() as s:
            sys = s.get(System, int(sid))
            sys.collection_errors = json.dumps({"connector": str(e)[:300]})
            s.commit()
        state.update(ok=False, error=str(e)[:300])
    return state


def refresh_appliances(ctx: Context, only: str | None = None) -> dict:
    with ctx.session_factory() as s:
        configs = _configs(s)
        states = setting(s, STATE_KEY) or {}
        gone = set(setting(s, CONFIG_KEY) or {}) - set(configs)
        if gone:   # System unter „Systeme“ gelöscht: Verbindung und Token mit entfernen
            put_setting(s, CONFIG_KEY, configs)
            s.commit()
    for sid in gone:
        ctx.secrets.delete(secret_name(int(sid)))
    for sid, cfg in configs.items():
        if only is None or sid == only:
            try:
                states[sid] = refresh_one(ctx, sid, cfg)
            except Exception:  # noqa: BLE001 (ein Gerät darf die anderen nicht aufhalten)
                log.exception("%s connector %s failed", cfg["kind"], sid)
                states[sid] = {"at": time.time(), "kind": cfg["kind"], "ok": False, "error": "internal error"}
    with ctx.session_factory() as s:
        put_setting(s, STATE_KEY, {k: v for k, v in states.items() if k in configs})
        s.commit()
    return states


def connector_checks(sys: System, now: datetime, open_updates: int) -> dict[str, tuple[str, str]]:
    """Spalten der Abdeckungsmatrix für ein Connector-System: Versionen (und bei TrueNAS Apps und Neustart),
    alles andere gibt die API nicht her („na“, zählt nicht zur Abdeckung)."""
    from .coverage import CHECK_KEYS

    data = json.loads(sys.inventory_json or "{}").get("connector") or {}
    err = json.loads(sys.collection_errors or "{}").get("connector")
    age = None if sys.last_seen is None else (now - sys.last_seen).total_seconds() / 3600
    checks = {k: ("na", "not available via the API") for k in CHECK_KEYS}
    problem = err or ("never read" if age is None else f"last read {age:.0f} h ago" if age > STALE_HOURS else "")
    truenas = sys.host_type == "truenas"
    keys = ("versionen", "images", "reboot") if truenas else ("versionen",)
    if problem:
        return {**checks, **{k: ("fehler", problem) for k in keys}}
    if sys.host_type in ("proxmox", "synology", "opnsense"):
        from importlib import import_module
        versions_check = import_module(f".{sys.host_type}", __package__).versions_check
        return {**checks, "versionen": versions_check(data, open_updates)}
    checks["versionen"] = ("fund" if open_updates else "ok",
                           f"{data.get('version') or '?'} · {open_updates} update(s) open")
    if truenas:
        apps = data.get("apps", [])
        behind = sum(a["upgrade"] or a["image_updates"] for a in apps)
        checks["images"] = ("fund" if behind else "ok", f"{len(apps)} apps, {behind} with updates")
        checks["reboot"] = ("fund" if sys.reboot_required else "ok",
                            "reboot required for the update" if sys.reboot_required else "no")
    return checks


# --- API -------------------------------------------------------------------------------------------------------

class ApplianceIn(BaseModel):
    kind: Literal["truenas", "homeassistant", "proxmox", "synology", "opnsense"]
    name: str = Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    url: str = Field(max_length=300)
    account: str = Field(default="", max_length=200)   # Synology: Konto, OPNsense: API-Schlüssel
    token: str | None = Field(default=None, min_length=8, max_length=4096)   # None = unverändert
    trust_certificate: bool = False   # neues Zertifikat übernehmen


def build_appliances_router(ctx: Context, guards: Guards) -> APIRouter:
    router = APIRouter(prefix="/settings/appliances")

    def entry(s, sid: str, c: dict, states: dict) -> dict:
        sys = s.get(System, int(sid))
        return {"system_id": int(sid), "name": sys.name, **c, "token": ctx.secrets.meta(secret_name(int(sid))),
                "state": states.get(sid)}

    @router.get("", dependencies=[Depends(guards.require_session)])
    def read():
        with ctx.session_factory() as s:
            states = setting(s, STATE_KEY) or {}
            return [entry(s, sid, c, states) for sid, c in _configs(s).items()]

    def save(body: ApplianceIn, sid: int | None, user: str) -> dict:
        url = body.url.strip().rstrip("/")
        if not _URL.match(url):
            raise HTTPException(422, "URL must look like https://truenas.lan or http://homeassistant.lan:8123")
        if body.kind in HTTPS_ONLY and not url.startswith("https://"):
            raise HTTPException(422, HTTPS_ONLY[body.kind])
        account = body.account.strip()
        if body.kind in WITH_ACCOUNT and not account:
            raise HTTPException(422, f"{WITH_ACCOUNT[body.kind]} required")
        with ctx.session_factory() as s:
            all_cfg = setting(s, CONFIG_KEY) or {}
            old = all_cfg.get(str(sid), {}) if sid else {}
            if sid is None and body.token is None:
                raise HTTPException(422, "Token required")
            fp = old.get("fingerprint", "")
            if url.startswith("https://") and (not fp or old.get("url") != url or body.trust_certificate):
                try:
                    fp = read_fingerprint(url)
                except ApplianceError as e:
                    raise HTTPException(422, str(e)) from None
            elif not url.startswith("https://"):
                fp = ""
            clash = s.scalar(select(System).where(System.name == body.name))
            if clash is not None and clash.id != sid:
                raise HTTPException(409, f"A system named {body.name} already exists")
            if sid is None:
                sys = System(name=body.name, host_type=body.kind, ip=_split(url)[1], status="connector")
                s.add(sys)
                s.flush()
                sid = sys.id
            else:
                sys = s.get(System, sid)
                sys.name, sys.ip = body.name, _split(url)[1]
            all_cfg[str(sid)] = {"kind": body.kind, "url": url, "fingerprint": fp,
                                 **({"account": account} if body.kind in WITH_ACCOUNT else {})}
            put_setting(s, CONFIG_KEY, all_cfg)
            ctx.audit(s, user, "connector.appliance.saved", f"{KINDS[body.kind]} {url}")
            s.commit()
        if body.token is not None:
            ctx.secrets.set(secret_name(sid), body.token)
        return refresh_appliances(ctx, only=str(sid)).get(str(sid)) | {"system_id": sid, "fingerprint": fp}

    @router.post("")
    def create(body: ApplianceIn, found=Depends(guards.require_admin)):
        return save(body, None, found[0].username)

    def existing(sid: int) -> None:
        with ctx.session_factory() as s:
            if str(sid) not in _configs(s):
                raise HTTPException(404, "Connector not found")

    @router.put("/{sid}")
    def update(sid: int, body: ApplianceIn, found=Depends(guards.require_admin)):
        existing(sid)
        with ctx.session_factory() as s:
            if (setting(s, CONFIG_KEY) or {})[str(sid)]["kind"] != body.kind:
                raise HTTPException(422, "The kind of a connector cannot change")
        return save(body, sid, found[0].username)

    @router.post("/{sid}/test")
    def test(sid: int, found=Depends(guards.require_admin)):
        existing(sid)
        state = refresh_appliances(ctx, only=str(sid))[str(sid)]
        with ctx.session_factory() as s:
            ctx.audit(s, found[0].username, "connector.appliance.tested", "ok" if state["ok"] else state["error"])
            s.commit()
        return state

    @router.delete("/{sid}")
    def remove(sid: int, found=Depends(guards.require_admin)):
        """Entfernt Verbindung, Token und das System samt Funden."""
        existing(sid)
        ctx.secrets.delete(secret_name(sid))
        with ctx.session_factory() as s:
            cfg = setting(s, CONFIG_KEY) or {}
            cfg.pop(str(sid), None)
            put_setting(s, CONFIG_KEY, cfg)
            sys = s.get(System, sid)
            ctx.audit(s, found[0].username, "connector.appliance.removed", sys.name)
            s.delete(sys)
            s.commit()
        return {"ok": True}

    return router
