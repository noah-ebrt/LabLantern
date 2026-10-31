"""Proxmox VE (PLAN-extensions D1) als dritte Geräteart neben TrueNAS und Home Assistant: Verbindung, Token und
Zertifikats-Pinning wie in appliances.py. Gelesen wird mit einem API-Token mit der Rolle PVEAuditor:
PVE-Version und ausstehende Updates je Knoten, dazu alle VMs und LXCs. Die Gäste werden den Agenten-Hosts
zugeordnet (Name, sonst IP); ein laufender Gast ohne Agent ist eine Lücke in der Abdeckung, ein gestoppter auch,
bis er mit Grund ausgenommen wird. Vorlagen zählen nicht. Geschrieben wird nichts."""
import http.client
import ipaddress
import json
import ssl
from urllib.parse import quote

from sqlalchemy import select

from .appliances import MAX_ITEMS, MAX_MESSAGE, TIMEOUT, ApplianceError, _check_pin, _split, _unverified
from .models import System
from .rules import classify_disk, classify_update

APT_FORBIDDEN = ("pending updates not readable: this Proxmox VE version needs Sys.Modify for /apt/update, "
                 "vulnwatch asks only for PVEAuditor (read-only)")


class _Forbidden(ApplianceError):
    pass


class PveClient:
    def __init__(self, url: str, fingerprint: str, token: str):
        scheme, self.host, self.port = _split(url)
        if scheme != "https":
            raise ApplianceError("Proxmox VE only over HTTPS (port 8006)")
        self.fingerprint = fingerprint
        self.auth = "PVEAPIToken=" + token.strip().removeprefix("PVEAPIToken=")

    def get(self, path: str):
        # Je Anfrage eine Verbindung mit Pin-Prüfung: pveproxy schließt sie ohnehin oft, und das Token geht nie
        # über eine Verbindung hinaus, deren Zertifikat nicht geprüft wurde.
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=TIMEOUT, context=_unverified())
        try:
            conn.connect()
            _check_pin(conn.sock, self.fingerprint)
            conn.request("GET", "/api2/json" + path, headers={"Authorization": self.auth, "User-Agent": "vulnwatch"})
            r = conn.getresponse()
            status, body = r.status, r.read(MAX_MESSAGE)
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            raise ApplianceError(f"Proxmox VE unreachable ({e})") from None
        finally:
            conn.close()
        if status == 401:
            raise ApplianceError("Proxmox VE rejected the API token")
        if status == 403:
            raise _Forbidden(f"Proxmox VE denied {path.split('?')[0]} (HTTP 403)")
        if status != 200:
            raise ApplianceError(f"Proxmox VE answered HTTP {status} on {path.split('?')[0]}")
        try:
            return json.loads(body)["data"]
        except (ValueError, KeyError, TypeError):
            raise ApplianceError("Proxmox VE sent no JSON") from None


def _usable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local)


def _guest_ips(client: PveClient, g: dict) -> list[str]:
    """Nur für die Zuordnung ohne passenden Namen. Fehlt das Recht oder der QEMU-Agent, bleibt die Liste leer."""
    base = f"/nodes/{quote(g['node'])}/{g['type']}/{g['vmid']}"
    try:
        if g["type"] == "lxc":
            ips = [part.partition("=")[2].split("/")[0]
                   for key, value in (client.get(f"{base}/config") or {}).items() if key.startswith("net")
                   for part in str(value).split(",") if part.partition("=")[0] in ("ip", "ip6")]
        elif g["status"] == "running":
            ips = [a.get("ip-address", "") for iface in (client.get(f"{base}/agent/network-get-interfaces") or {})
                   .get("result") or [] for a in iface.get("ip-addresses") or []]
        else:
            ips = []
    except ApplianceError:
        return []
    return [ip for ip in dict.fromkeys(ips) if _usable(ip)][:20]


def _owner(member: str, disks: list[dict]) -> dict | None:
    """Laufwerk zu einem Gerät im ZFS-Pool: „sda3“, „nvme0n1p2“ oder ein by-id-Name wie „ata-WDC_…-part3“."""
    base = member.split("/")[-1]
    for d in disks:
        dev = str(d.get("devpath") or "").removeprefix("/dev/")
        by_id = str(d.get("by_id_link") or "").split("/")[-1]
        if dev and (base == dev or (base.startswith(dev) and base[len(dev):].lstrip("p").isdigit())):
            return d
        if by_id and (base == by_id or base.startswith(by_id + "-part")):
            return d
    return None


def _node_storage(client: PveClient, node: str, prefix: str) -> tuple[list[dict], list[dict], str]:
    """(Pools, Laufwerke, Fehler) eines Knotens: Laufwerke mit S.M.A.R.T.-Zustand, ZFS-Pools mit ihren Laufwerken."""
    from .storage import disk, layout_of, pool

    try:
        raw = [d for d in (client.get(f"/nodes/{quote(node)}/disks/list") or [])[:MAX_ITEMS] if isinstance(d, dict)]
    except ApplianceError as e:
        return [], [], f"{node}: drives not readable ({e})"
    member_of, pools = {}, []
    try:
        zpools = client.get(f"/nodes/{quote(node)}/disks/zfs") or []
    except ApplianceError:
        zpools = []
    for z in zpools[:50]:
        name = str(z.get("name") or "?")
        try:
            tree = client.get(f"/nodes/{quote(node)}/disks/zfs/{quote(name)}") or {}
        except ApplianceError:
            tree = {}
        names, layouts = [], []
        for vdev in tree.get("children") or []:
            leaves = vdev.get("children") or [vdev]
            layouts.append(str(vdev.get("name") or "").split("-")[0].upper() if vdev.get("children") else "STRIPE")
            for leaf in leaves:
                if (d := _owner(str(leaf.get("name") or ""), raw)) is not None:
                    member_of[d["devpath"]] = (prefix + name, str(leaf.get("state") or ""))
                    names.append(prefix + str(d["devpath"]).removeprefix("/dev/"))
        layout = layout_of(layouts)
        size, alloc = z.get("size"), z.get("alloc")
        pools.append(pool(prefix + name, "ZFS pool", z.get("health"),
                          alloc * 100 / size if isinstance(size, (int, float)) and size and isinstance(alloc, (int, float)) else None,
                          size, layout, names))
    disks = []
    for d in raw:
        dev = str(d.get("devpath") or "?")
        pool_name, member_state = member_of.get(dev, ("", ""))
        health = str(d.get("health") or "")
        wear = d.get("wearout")
        disks.append(disk(prefix + dev.removeprefix("/dev/"), d.get("model"), d.get("serial"), d.get("size"), d.get("type"),
                          member_state, "" if health.upper() == "UNKNOWN" else health, pool_name=pool_name,
                          detail=", ".join(x for x in (f"used by {d['used']}" if d.get("used") and not pool_name else "",
                                                       f"wearout {wear} %" if isinstance(wear, (int, float)) else "") if x)))
    return pools, disks, ""


def fetch_proxmox(url: str, fingerprint: str, token: str) -> dict:
    client = PveClient(url, fingerprint, token)
    version = (client.get("/version") or {}).get("version", "")
    nodes = []
    raw_nodes = (client.get("/nodes") or [])[:MAX_ITEMS]
    pools, disks, errors = [], [], []
    for n in raw_nodes:
        name = str(n.get("node") or "")
        if not name:
            continue
        node = {"node": name, "version": version, "updates": None, "error": ""}
        if n.get("status") != "online":
            node["error"] = "node offline"
        else:
            node["version"] = (client.get(f"/nodes/{quote(name)}/version") or {}).get("version") or version
            try:
                node["updates"] = [{"package": u.get("Package", ""), "installed": u.get("OldVersion", ""),
                                    "new": u.get("Version", "")}
                                   for u in (client.get(f"/nodes/{quote(name)}/apt/update") or [])[:MAX_ITEMS]]
            except _Forbidden:
                node["error"] = APT_FORBIDDEN
            p, d, err = _node_storage(client, name, f"{name}/" if len(raw_nodes) > 1 else "")
            pools, disks = pools + p, disks + d
            errors += [err] if err else []
        nodes.append(node)
    guests = []
    for g in (client.get("/cluster/resources?type=vm") or [])[:MAX_ITEMS]:
        if g.get("type") not in ("qemu", "lxc") or g.get("vmid") is None:
            continue
        guest = {"node": str(g.get("node") or ""), "vmid": int(g["vmid"]), "type": g["type"],
                 "name": str(g.get("name") or f"{g['type']}-{g['vmid']}")[:100], "status": g.get("status", ""),
                 "template": bool(g.get("template")),
                 "tags": [t for t in str(g.get("tags") or "").split(";") if t][:20]}
        guest["subject"] = f"pve-guest:{guest['node']}/{guest['vmid']}"
        guest["ips"] = [] if guest["template"] else _guest_ips(client, guest)
        guests.append(guest)
    from .storage import storage
    return {"version": version, "nodes": nodes, "guests": guests, "storage": storage(pools, disks, "; ".join(errors))}


def proxmox_findings(data: dict) -> list[dict]:
    """Je Knoten ein Fund für ein neueres pve-manager. Die übrigen Paket-Updates meldet der Agent auf dem Knoten."""
    out = []
    for n in data["nodes"]:
        pm = next((u for u in n["updates"] or [] if u["package"] == "pve-manager"), None)
        if pm:
            out.append({"target": f"node:{n['node']}", "cve_id": "VW-UPDATE", "component": "Proxmox VE",
                        "severity": classify_update(pm["installed"], pm["new"]),
                        "installed_version": pm["installed"], "fixed_version": pm["new"],
                        "title": f"Proxmox VE {pm['new']} is available on {n['node']} (installed {pm['installed']})"})
    from .storage import drive_findings
    st = data.get("storage") or {}
    for p in st.get("pools") or []:
        if p["state"] in ("bad", "warn"):
            out.append({"target": f"pool:{p['name']}", "cve_id": "VW-POOL", "component": f"ZFS pool {p['name']}",
                        "severity": "hoch" if p["state"] == "bad" else "mittel", "installed_version": p["status"],
                        "fixed_version": "zpool status -v on the node", "title": f"ZFS pool {p['name']} is {p['status']}"})
        if p["percent"] is not None and (sev := classify_disk(p["percent"])):
            out.append({"target": f"disk:{p['name']}", "cve_id": "VW-DISK", "component": f"ZFS pool {p['name']}",
                        "severity": sev, "installed_version": f"{p['percent']:.0f} %", "fixed_version": "free space",
                        "title": f"ZFS pool {p['name']} is {p['percent']:.0f} % full"})
    return out + drive_findings(st, "node → Disks: check S.M.A.R.T. values and replace the drive")


def versions_check(data: dict, open_updates: int) -> tuple[str, str]:
    nodes = data.get("nodes") or []
    detail = f"{data.get('version') or '?'} · {len(nodes)} node(s) · {open_updates} update(s) open"
    offline = [n["node"] for n in nodes if n["error"] == "node offline"]
    if offline:
        return "fehler", f"node(s) offline, not checked: {', '.join(offline)}"
    if open_updates:
        return "fund", detail
    if any(n["updates"] is None for n in nodes):
        return "na", APT_FORBIDDEN
    return "ok", detail


def _short(name: str) -> str:
    return name.strip().lower().split(".")[0]


def match_guests(guests: list[dict], systems: list[System]) -> tuple[dict[str, int], list[dict]]:
    """(Gast → System-ID, nicht zugeordnete Gäste). Erst der Name ohne Domain, dann eine IP des Gasts."""
    by_name: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for s in systems:
        if s.status != "active":
            continue
        by_name.setdefault(_short(s.name), s.id)
        if s.ip:
            by_ip.setdefault(s.ip, s.id)
    matched, unmatched = {}, []
    for g in guests:
        if g.get("template"):
            continue
        sid = by_name.get(_short(g["name"])) or next((by_ip[ip] for ip in g.get("ips") or [] if ip in by_ip), None)
        if sid is None:
            unmatched.append(g)
        else:
            matched[g["subject"]] = sid
    return matched, unmatched


def _connectors(systems: list[System]):
    for sys in systems:
        if sys.status == "connector" and sys.host_type == "proxmox":
            try:
                yield sys, json.loads(sys.inventory_json or "{}").get("connector") or {}
            except ValueError:
                continue


def known_guest(s, subject: str) -> bool:
    systems = s.scalars(select(System)).all()
    return any(g["subject"] == subject for _, data in _connectors(systems) for g in data.get("guests") or [])


def guest_rows(s, exclusions: dict) -> list[dict]:
    """Zeilen der Abdeckung je Gast (ohne Vorlagen), aus dem letzten gelungenen Abruf jeder PVE-Verbindung."""
    systems = s.scalars(select(System)).all()
    names = {x.id: x.name for x in systems}
    rows = []
    for conn, data in _connectors(systems):
        guests = data.get("guests") or []
        matched, _ = match_guests(guests, systems)
        for g in guests:
            if g["template"]:
                continue
            sid = matched.get(g["subject"])
            row = {"subject": g["subject"], "name": g["name"], "node": g["node"], "vmid": g["vmid"], "type": g["type"],
                   "source": conn.name, "source_id": conn.id, "system_id": sid, "system_name": names.get(sid)}
            ex = exclusions.get(g["subject"])
            if ex is not None:
                row.update(status="excluded", detail=f"excluded until {ex.until.date().isoformat()}: {ex.reason}",
                           exclusion_id=ex.id)
            elif sid is not None:
                row.update(status="ok", detail=f"agent on {names[sid]}")
            elif g["status"] != "running":
                state = "stopped" if g["status"] == "stopped" else g["status"] or "not running"
                row.update(status="fehler", detail=f"{state}, not checked")
            else:
                ips = ", ".join(g.get("ips") or [])
                row.update(status="fehler", detail=f"no agent{f' ({ips})' if ips else ''}")
            rows.append(row)
    return rows
