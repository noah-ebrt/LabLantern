"""OPNsense als Geräteart (Firmware), neben den Portfreigaben aus routerforwards.py: Version, ausstehende Updates,
Major-Upgrade und Plugins, gelesen mit API-Schlüssel und -Geheimnis über HTTPS mit gepinntem Zertifikat. Den Stand
der Updates liefert die letzte Prüfung der Firewall selbst; LabLantern stößt keine an (das wäre ein POST, und der
Connector schreibt nichts)."""
import base64

from .appliances import MAX_ITEMS, ApplianceError
from .rules import classify_update

NOT_CHECKED = "the firewall has not checked for updates yet: System → Firmware → Status → Check for updates"


def _get(url: str, fingerprint: str, key: str, secret: str, path: str):
    from .routerforwards import _get as get

    auth = base64.b64encode(f"{key}:{secret}".encode()).decode()
    return get(url, fingerprint, path, {"Authorization": f"Basic {auth}"}, "OPNsense",
               {401: "OPNsense rejected the API key and secret",
                403: "OPNsense rejected the request: the API user needs the privilege System: Firmware",
                404: "no firmware API at this address: is it an OPNsense?"})


def fetch_firmware(url: str, fingerprint: str, key: str, secret: str) -> dict:
    status = _get(url, fingerprint, key, secret, "/api/core/firmware/status")
    info = _get(url, fingerprint, key, secret, "/api/core/firmware/info")
    if not isinstance(status, dict) or not isinstance(info, dict):
        raise ApplianceError("unexpected answer from OPNsense")
    product = info.get("product") if isinstance(info.get("product"), dict) else {}
    version = str(product.get("product_version") or status.get("product_version") or "")[:100]
    if not version:
        raise ApplianceError("OPNsense sent no version")
    core = str(product.get("product_id") or status.get("product_id") or "opnsense")
    state = str(status.get("status") or "")
    checked = state in ("none", "update", "upgrade") and bool(status.get("last_check") or status.get("product_version"))
    updates = [{"package": str(p.get("name") or "")[:100], "installed": str(p.get("current_version") or "")[:100],
                "new": str(p.get("new_version") or "")[:100]}
               for p in (status.get("upgrade_packages") or [])[:MAX_ITEMS] if isinstance(p, dict)] if checked else []
    plugins = [{"name": str(p.get("name") or "")[:100], "version": str(p.get("version") or "")[:100]}
               for p in (info.get("plugin") or [])[:MAX_ITEMS]
               if isinstance(p, dict) and str(p.get("installed", "0")) == "1" and p.get("name")]
    return {"version": version, "series": str(product.get("product_series") or status.get("product_abi") or "")[:20],
            "core": core, "checked": checked, "last_check": str(status.get("last_check") or "")[:100],
            "error": str(status.get("status_msg") or "")[:300] if state == "error" else "",
            "updates": updates, "major": str(status.get("upgrade_major_version") or "")[:20] if checked else "",
            "update_needs_reboot": str(status.get("upgrade_needs_reboot") or status.get("needs_reboot") or "0") == "1",
            "plugins": plugins, "packages": len(info.get("package") or []), "reboot_required": False}


def opnsense_findings(data: dict) -> list[dict]:
    """Das Core-Update als Fund (gleiche Linie hoch, neue mittel). Andere Pakete kommen mit ihm; stehen nur sie an
    (Basis, Kernel, Plugins), ein Sammelfund. Ein Major-Upgrade ist mittel; das Ende der Linie meldet endoflife.date."""
    out = []
    core = next((u for u in data["updates"] if u["package"] == data["core"]), None)
    if core:
        out.append({"target": "host", "cve_id": "LL-UPDATE", "component": "OPNsense",
                    "severity": classify_update(core["installed"] or data["version"], core["new"]),
                    "installed_version": core["installed"] or data["version"], "fixed_version": core["new"],
                    "title": f"OPNsense {core['new']} is available (installed {core['installed'] or data['version']})"})
    elif data["updates"]:
        names = ", ".join(u["package"] for u in data["updates"][:5]) + (" …" if len(data["updates"]) > 5 else "")
        out.append({"target": "packages", "cve_id": "LL-UPDATE", "component": "OPNsense packages", "severity": "mittel",
                    "installed_version": f"{len(data['updates'])} pending", "fixed_version": "System → Firmware → Updates",
                    "title": f"{len(data['updates'])} package update(s) pending on OPNsense: {names}"[:500]})
    if data["major"]:
        out.append({"target": "major", "cve_id": "LL-UPDATE", "component": "OPNsense",
                    "severity": classify_update(data["version"], data["major"]),
                    "installed_version": data["version"], "fixed_version": data["major"],
                    "title": f"OPNsense {data['major']} is available as a major upgrade (installed {data['version']})"})
    return out


def versions_check(data: dict, open_updates: int) -> tuple[str, str]:
    if data.get("error"):
        return "fehler", f"update check on the firewall failed: {data['error']}"
    if not data.get("checked"):
        return "na", NOT_CHECKED
    detail = f"{data.get('version') or '?'} · {open_updates} update(s) open · last check {data.get('last_check') or '?'}"
    return ("fund" if open_updates else "ok"), detail
