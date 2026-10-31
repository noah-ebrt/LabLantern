"""Speicher in gemeinsamer Form (storage.py): TrueNAS-Topologie und Proxmox-Laufwerke, Zustände, Kurzform für Listen."""
from app import appliances
from app.proxmox import fetch_proxmox, proxmox_findings
from app.storage import layout_of, state_of, summary
from tests.test_appliances import KEY, TRUENAS, truenas  # noqa: F401 (Fixture)
from tests.test_proxmox import TOKEN, FakePve, pve  # noqa: F401 (Fixture)


def leaf(name, status="ONLINE", errors=0):
    return {"type": "DISK", "disk": name, "status": status,
            "stats": {"read_errors": errors, "write_errors": 0, "checksum_errors": 0}}


STORAGE = {
    "pool.query": [{"name": "tank", "healthy": False, "status": "DEGRADED", "size": 1000, "allocated": 400, "scan": None,
                    "topology": {"data": [{"type": "RAIDZ1", "status": "DEGRADED",
                                           "children": [leaf("sda"), leaf("sdb", errors=4), leaf("sdc", "FAULTED")]}],
                                 "cache": [leaf("nvme0n1")]}}],
    "boot.get_state": {"name": "boot-pool", "status": "ONLINE", "size": 100, "allocated": 10,
                       "topology": {"data": [{"type": "DISK", "disk": "sdd", "status": "ONLINE"}]}},
    "disk.query": [{"name": n, "model": "WDC WD40EFRX", "serial": f"S{n}", "size": 4_000_000_000_000, "type": t}
                   for n, t in (("sda", "HDD"), ("sdb", "HDD"), ("sdc", "HDD"), ("sdd", "SSD"), ("nvme0n1", "SSD"),
                                ("sde", "HDD"))],
    "disk.temperatures": {"sda": 34, "sdb": 37},
}


def test_states_and_layout():
    assert state_of("ONLINE") == "ok" and state_of("DEGRADED") == "bad" and state_of("attention") == "warn"
    assert state_of("") == "unknown" and state_of("whatever") == "unknown"   # Unbekanntes ist nie „ok“
    assert state_of("normal", "failing") == "bad"
    assert layout_of(["MIRROR", "MIRROR"]) == "2× MIRROR" and layout_of(["RAIDZ2"]) == "RAIDZ2"
    assert layout_of([]) == ""


def test_truenas_topology_drives_and_temperatures(truenas):  # noqa: F811
    nas = truenas({**TRUENAS, **STORAGE})
    url = f"https://127.0.0.1:{nas.port}"
    data = appliances.fetch_truenas(url, appliances.read_fingerprint(url), KEY)
    st = data["storage"]
    pools = {p["name"]: p for p in st["pools"]}
    assert (pools["tank"]["layout"], pools["tank"]["state"], pools["tank"]["percent"]) == ("RAIDZ1", "bad", 40.0)
    assert pools["tank"]["disks"] == ["sda", "sdb", "sdc", "nvme0n1"]
    assert pools["boot-pool"]["kind"] == "Boot pool" and pools["boot-pool"]["layout"] == "STRIPE"
    disks = {d["name"]: d for d in st["disks"]}
    assert (disks["sda"]["state"], disks["sda"]["temp"], disks["sda"]["pool"]) == ("ok", 34, "tank")
    assert disks["sdb"]["state"] == "warn" and "4 read/write/checksum errors" in disks["sdb"]["detail"]
    assert disks["sdc"]["state"] == "bad"
    assert disks["nvme0n1"]["type"] == "nvme" and "cache vdev" in disks["nvme0n1"]["detail"]
    assert (disks["sde"]["pool"], disks["sde"]["state"]) == ("", "unknown")   # kein Pool: Zustand unbekannt, nicht ok
    found = {f["target"]: f for f in appliances.truenas_findings(data)}
    assert found["drive:sdc"]["severity"] == "hoch" and found["drive:sdb"]["severity"] == "mittel"
    s = summary(st)
    assert (s["pools"], len(s["disks"]), s["bad"], s["warn"]) == (2, 6, 2, 1)   # tank + sdc schlecht, sdb Warnung


def test_proxmox_drives_and_zfs(pve, monkeypatch):  # noqa: F811
    monkeypatch.setattr(FakePve, "routes", {**FakePve.routes,
        "/api2/json/nodes/pve1/disks/list": {"data": [
            {"devpath": "/dev/sda", "model": "Samsung SSD 870", "serial": "A", "size": 500e9, "type": "ssd", "health": "PASSED",
             "wearout": 97, "by_id_link": "/dev/disk/by-id/ata-Samsung_SSD_870_A"},
            {"devpath": "/dev/sdb", "model": "Samsung SSD 870", "serial": "B", "size": 500e9, "type": "ssd", "health": "FAILED"},
            {"devpath": "/dev/nvme0n1", "model": "WD SN770", "size": 1e12, "type": "nvme", "health": "UNKNOWN", "used": "LVM"}]},
        "/api2/json/nodes/pve1/disks/zfs": {"data": [{"name": "rpool", "health": "DEGRADED", "size": 1000, "alloc": 950}]},
        "/api2/json/nodes/pve1/disks/zfs/rpool": {"data": {"name": "rpool", "state": "DEGRADED", "children": [
            {"name": "mirror-0", "state": "DEGRADED", "children": [
                {"name": "ata-Samsung_SSD_870_A-part3", "state": "ONLINE"}, {"name": "sdb3", "state": "FAULTED"}]}]}},
    })
    data = fetch_proxmox(pve, appliances.read_fingerprint(pve), TOKEN)
    st = data["storage"]
    assert st["error"] == ""
    rpool = st["pools"][0]
    assert (rpool["layout"], rpool["state"], rpool["disks"]) == ("MIRROR", "bad", ["sda", "sdb"])
    disks = {d["name"]: d for d in st["disks"]}
    assert disks["sda"]["state"] == "ok" and "wearout 97 %" in disks["sda"]["detail"]
    assert disks["sdb"]["state"] == "bad"
    assert (disks["nvme0n1"]["state"], disks["nvme0n1"]["type"], disks["nvme0n1"]["detail"]) == ("unknown", "nvme", "used by LVM")
    found = {f["target"]: f for f in proxmox_findings(data)}
    assert found["pool:rpool"]["severity"] == "hoch" and found["disk:rpool"]["severity"] == "hoch"   # 95 %
    assert found["drive:sdb"]["severity"] == "hoch" and "drive:sda" not in found


def test_proxmox_without_disk_rights_keeps_the_rest(pve):  # noqa: F811
    """Fehlt /disks/list (Fake antwortet 500), bleiben Version und Gäste; der Speicher sagt, warum er fehlt."""
    data = fetch_proxmox(pve, appliances.read_fingerprint(pve), TOKEN)
    assert data["version"] and data["guests"]
    assert data["storage"]["disks"] == [] and "drives not readable" in data["storage"]["error"]
    assert summary(data["storage"])["error"]
