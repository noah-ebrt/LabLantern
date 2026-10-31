"""Synology DSM als Geräteart neben TrueNAS und Proxmox: Verbindung und Zertifikats-Pinning wie in appliances.py.
DSM kennt keine API-Tokens und keine Nur-Lese-Rolle, gelesen wird daher mit Konto und Passwort (Sitzung je Abruf,
danach abgemeldet). Die Version liest jedes Konto; Update-Prüfung, Pakete und Speicher nur ein Administrator. Was
das Konto nicht darf, bleibt „na“ mit Grund, nie „ok“. Geschrieben wird nichts."""
import http.client
import json
import re
import ssl
from urllib.parse import urlencode

from .appliances import MAX_ITEMS, MAX_MESSAGE, TIMEOUT, ApplianceError, _check_pin, _split, _unverified
from .rules import classify_disk, classify_update

# Fehlercodes der DSM-Web-API: 102–104 API, Methode oder Version gibt es nicht, 105 keine Berechtigung
MISSING = {102, 103, 104}
DENIED = 105
LOGIN_ERRORS = {400: "DSM rejected the account or password", 401: "the DSM account is disabled",
                402: "DSM denied the login for this account",
                403: "the DSM account uses 2-factor authentication: use an account without it",
                404: "the DSM account uses 2-factor authentication: use an account without it",
                406: "DSM enforces 2-factor authentication for this account: exempt it or use another",
                407: "DSM blocked vulnwatch's IP address (Control Panel → Security → Protection → Allow/Block List)",
                408: "the DSM password has expired", 409: "the DSM password has expired",
                410: "DSM wants a new password for this account"}
NOT_ADMIN = "not readable: the DSM account is not an administrator"
BAD_STATES = {"degraded": "hoch", "crashed": "hoch", "failing": "hoch", "abnormal": "hoch",
              "attention": "mittel", "warning": "mittel"}


class _Unavailable(ApplianceError):
    pass


class DsmClient:
    def __init__(self, url: str, fingerprint: str, account: str, password: str):
        scheme, self.host, self.port = _split(url)
        if scheme != "https":
            raise ApplianceError("Synology DSM only over HTTPS (port 5001)")
        self.fingerprint = fingerprint
        self.sid = ""
        login = {"api": "SYNO.API.Auth", "version": "6", "method": "login", "account": account, "passwd": password,
                 "session": "vulnwatch", "format": "sid"}
        self.sid = str(self._post(login, login=True).get("sid") or "")
        if not self.sid:
            raise ApplianceError("DSM sent no session")

    def _post(self, form: dict, login: bool = False) -> dict:
        # POST statt GET: Passwort und Sitzung stehen so in keinem Zugriffslog von DSM
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=TIMEOUT, context=_unverified())
        try:
            conn.connect()
            _check_pin(conn.sock, self.fingerprint)
            conn.request("POST", "/webapi/entry.cgi", body=urlencode(form),
                         headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "vulnwatch"})
            r = conn.getresponse()
            status, body = r.status, r.read(MAX_MESSAGE)
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            raise ApplianceError(f"Synology DSM unreachable ({e})") from None
        finally:
            conn.close()
        if status != 200:
            raise ApplianceError(f"Synology DSM answered HTTP {status} on {form['api']}")
        try:
            doc = json.loads(body)
        except ValueError:
            raise ApplianceError("Synology DSM sent no JSON") from None
        if not isinstance(doc, dict):
            raise ApplianceError("unexpected answer from Synology DSM")
        if doc.get("success"):
            return doc.get("data") if isinstance(doc.get("data"), dict) else {}
        code = (doc.get("error") or {}).get("code") if isinstance(doc.get("error"), dict) else None
        if login:
            raise ApplianceError(LOGIN_ERRORS.get(code, f"DSM login failed (error {code})"))
        if code == DENIED:
            raise _Unavailable(NOT_ADMIN)
        if code in MISSING:
            raise _Unavailable(f"not available on this DSM version ({form['api']})")
        raise ApplianceError(f"Synology DSM error {code} on {form['api']}")

    def call(self, api: str, method: str, versions: tuple[int, ...] = (1,), **params) -> dict:
        """Erste Version, die DSM kennt (neuere zuerst)."""
        for i, v in enumerate(versions):
            try:
                return self._post({"api": api, "version": str(v), "method": method, "_sid": self.sid, **params})
            except _Unavailable as e:
                if str(e) == NOT_ADMIN or i == len(versions) - 1:
                    raise

    def optional(self, api: str, method: str, versions: tuple[int, ...] = (1,), **params) -> tuple[dict | None, str]:
        try:
            return self.call(api, method, versions, **params), ""
        except _Unavailable as e:
            return None, str(e)

    def close(self) -> None:
        try:
            self._post({"api": "SYNO.API.Auth", "version": "6", "method": "logout", "session": "vulnwatch",
                        "_sid": self.sid})
        except ApplianceError:
            pass


def _version(text) -> str:
    """„DSM 7.2.2-72806 Update 3“ -> „7.2.2-72806 Update 3“."""
    return re.sub(r"^\s*DSM\s*", "", str(text or ""))[:100]


def _update(data: dict) -> dict:
    u = data.get("update") if isinstance(data.get("update"), dict) else data
    available = bool(u.get("available"))
    new = _version(u.get("version")) if available else ""
    d = u.get("version_details") if isinstance(u.get("version_details"), dict) else {}
    if available and not new and d.get("major") is not None:
        new = f"{d.get('major')}.{d.get('minor', 0)}.{d.get('micro', 0)}-{d.get('buildnumber', '')}".rstrip("-")
        new += f" Update {d['nano']}" if d.get("nano") else ""
    return {"available": available, "version": new, "reboot": str(u.get("reboot") or "") not in ("", "none")}


def _number(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _storage(data: dict) -> tuple[list[dict], list[dict]]:
    """(Speicherpools und Volumes, Laufwerke). Unbekannte Zustände zählen nicht als Problem: nur BAD_STATES."""
    spaces = []
    for kind, key in (("Storage pool", "storagePools"), ("Volume", "volumes")):
        for v in (data.get(key) or [])[:MAX_ITEMS]:
            if not isinstance(v, dict):
                continue
            size = v.get("size") if isinstance(v.get("size"), dict) else {}
            total, used = _number(size.get("total")), _number(size.get("used"))
            spaces.append({"kind": kind, "name": str(v.get("vol_path") or v.get("id") or "?")[:100],
                           "status": str(v.get("status") or "").lower()[:40],
                           "percent": used / total * 100 if total and used is not None else None})
    disks = [{"name": str(d.get("longName") or d.get("name") or d.get("id") or "?")[:100],
              "model": str(d.get("model") or "").strip()[:100], "status": str(d.get("status") or "").lower()[:40],
              "smart": str(d.get("smart_status") or "").lower()[:40]}
             for d in (data.get("disks") or [])[:MAX_ITEMS] if isinstance(d, dict)]
    return spaces, disks


def _dsm_storage(data: dict | None, error: str) -> dict:
    """Gemeinsame Speicherform (storage.py): Speicherpools mit ihren Laufwerken, Volumes mit Füllstand."""
    from .storage import disk, pool, storage

    if data is None:
        return storage(None, None, f"storage {error}")
    raw_disks = [d for d in (data.get("disks") or [])[:MAX_ITEMS] if isinstance(d, dict)]
    label = {str(d.get("id") or ""): str(d.get("longName") or d.get("name") or d.get("id") or "?") for d in raw_disks}
    pools, used_by = [], {}
    for p in (data.get("storagePools") or [])[:MAX_ITEMS]:
        if not isinstance(p, dict):
            continue
        size = p.get("size") if isinstance(p.get("size"), dict) else {}
        total, used = _number(size.get("total")), _number(size.get("used"))
        members = [str(x) for x in p.get("disks") or [] if isinstance(x, (str, int))]
        for m in members:
            used_by[m] = str(p.get("id") or "")
        pools.append(pool(p.get("id"), "Storage pool", p.get("status"), used / total * 100 if total and used is not None else None,
                          total, str(p.get("device_type") or p.get("raidType") or "").replace("_", " ").upper(),
                          [label.get(m, m) for m in members]))
    for v in (data.get("volumes") or [])[:MAX_ITEMS]:
        if not isinstance(v, dict):
            continue
        size = v.get("size") if isinstance(v.get("size"), dict) else {}
        total, used = _number(size.get("total")), _number(size.get("used"))
        pools.append(pool(v.get("vol_path") or v.get("id"), "Volume", v.get("status"),
                          used / total * 100 if total and used is not None else None, total,
                          str(v.get("fs_type") or "").upper()))
    disks = [disk(label[str(d.get("id") or "")], d.get("model"), d.get("serial"), d.get("size_total"),
                  "nvme" if "nvme" in str(d.get("diskType") or d.get("id") or "").lower() else "ssd" if d.get("isSsd") else "hdd",
                  d.get("status"), d.get("smart_status"), d.get("temp"),
                  pool_name=used_by.get(str(d.get("id") or ""), str(d.get("used_by") or "")))
             for d in raw_disks]
    return storage(pools, disks)


def fetch_synology(url: str, fingerprint: str, account: str, password: str) -> dict:
    client = DsmClient(url, fingerprint, account, password)
    try:
        info, _ = client.optional("SYNO.DSM.Info", "getinfo", (2, 1))
        version = _version((info or {}).get("version_string"))
        model = str((info or {}).get("model") or "")[:100]
        if not version:
            sysinfo, _ = client.optional("SYNO.Core.System", "info", (1,))
            version = _version((sysinfo or {}).get("firmware_ver"))
            model = model or str((sysinfo or {}).get("model") or "")[:100]
        upd, update_error = client.optional("SYNO.Core.Upgrade.Server", "check", (2, 1))
        pkgs, packages_error = client.optional("SYNO.Core.Package", "list", (2, 1))
        storage, storage_error = client.optional("SYNO.Storage.CGI.Storage", "load_info", (1,))
    finally:
        client.close()
    spaces, disks = _storage(storage) if storage is not None else (None, None)
    packages = None if pkgs is None else [
        {"id": str(p.get("id") or "")[:100], "name": str(p.get("name") or p.get("id") or "")[:100],
         "version": str(p.get("version") or "")[:100]}
        for p in (pkgs.get("packages") or [])[:MAX_ITEMS] if isinstance(p, dict) and (p.get("id") or p.get("name"))]
    update = None if upd is None else _update(upd)
    return {"version": version, "model": model, "update": update, "update_error": update_error,
            "packages": packages, "packages_error": packages_error, "spaces": spaces, "disks": disks,
            "storage_error": storage_error, "storage": _dsm_storage(storage, storage_error), "reboot_required": False}


def synology_findings(data: dict) -> list[dict]:
    out = []
    u = data.get("update")
    if u and u["available"] and u["version"]:
        out.append({"target": "host", "cve_id": "VW-UPDATE", "component": "Synology DSM",
                    "severity": classify_update(data["version"], u["version"]),
                    "installed_version": data["version"], "fixed_version": u["version"],
                    "title": f"DSM {u['version']} is available (installed {data['version'] or '?'})"})
    for sp in data.get("spaces") or []:
        if sev := BAD_STATES.get(sp["status"]):
            out.append({"target": f"pool:{sp['name']}", "cve_id": "VW-POOL", "component": f"{sp['kind']} {sp['name']}",
                        "severity": sev, "installed_version": sp["status"], "fixed_version": "check Storage Manager",
                        "title": f"{sp['kind']} {sp['name']} is {sp['status']}"})
        if sp["kind"] == "Volume" and sp["percent"] is not None and (sev := classify_disk(sp["percent"])):
            out.append({"target": f"disk:{sp['name']}", "cve_id": "VW-DISK", "component": f"Volume {sp['name']}",
                        "severity": sev, "installed_version": f"{sp['percent']:.0f} %", "fixed_version": "free space",
                        "title": f"Volume {sp['name']} is {sp['percent']:.0f} % full"})
    for d in data.get("disks") or []:
        worst = max((BAD_STATES.get(d["status"]), BAD_STATES.get(d["smart"])), key=lambda s: {"hoch": 2, "mittel": 1}.get(s, 0))
        if worst:
            state = d["status"] if BAD_STATES.get(d["status"]) == worst else f"S.M.A.R.T. {d['smart']}"
            out.append({"target": f"drive:{d['name']}", "cve_id": "VW-DRIVE", "component": f"{d['name']} {d['model']}".strip(),
                        "severity": worst, "installed_version": state, "fixed_version": "replace the drive",
                        "title": f"{d['name']} ({d['model'] or 'drive'}) reports {state}"})
    return out


def versions_check(data: dict, open_updates: int) -> tuple[str, str]:
    if data.get("update") is None:
        return "na", f"DSM update check {data.get('update_error') or 'not readable'}"
    detail = f"DSM {data.get('version') or '?'} · {open_updates} update(s) open"
    return ("fund" if open_updates else "ok"), detail
