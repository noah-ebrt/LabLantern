import hashlib
import json
import os

import pytest
from sqlalchemy import select

from app.models import System
from tests.conftest import Env

PKGS = [
    {"name": "libssl3t64", "version": "3.0.13-0ubuntu3.16", "arch": "amd64", "source": "openssl",
     "source_version": "3.0.13-0ubuntu3.16", "type": "deb"},
    {"name": "curl", "version": "8.5.0-2ubuntu10.6", "arch": "amd64", "source": "", "source_version": "", "type": "deb"},
]


def report(**over):
    base = {
        "agent_version": "0.3.0", "os_name": "Ubuntu 24.04.5 LTS", "os_id": "ubuntu", "os_version_id": "24.04",
        "kernel": "6.8.0-45-generic", "arch": "amd64", "security_updates_count": 2, "security_updates_known": True,
        "reboot_required": True, "packages": PKGS, "collection_errors": {},
        "containers": [{"id": "abc123", "name": "caddy", "image": "caddy:2.9.1-alpine", "image_id": "sha256:1"},
                       {"id": "def456", "name": "server", "image": "lablantern-server:dev", "image_id": "sha256:2"}],
    }
    base.update(over)
    return base


def enroll(env, admin_client, h, hostname="host-a", ip="192.0.2.10"):
    token = admin_client.post("/api/systems/enrollment-token", headers=h).json()["token"]
    r = env.new_client().post("/api/agent/enroll", json={
        "enrollment_token": token, "hostname": hostname, "ip": ip, "host_type": "linux", "agent_version": "0.3.0"})
    assert r.status_code == 200, r.text
    return r.json()


def activate(env, client, h, **kw):
    e = enroll(env, client, h, **kw)
    assert client.post(f"/api/systems/{e['system_id']}/approve", headers=h).status_code == 200
    return e["system_id"], {"Authorization": f"Bearer {e['agent_token']}"}


def system(env, sid):
    with env.app.state.ctx.session_factory() as s:
        return s.get(System, sid)


# ---------- Einmal-Token, Fingerabdruck, Befehle ----------

def test_enrollment_token_requires_admin(env, admin):
    e, client, h = admin
    assert e.new_client().post("/api/systems/enrollment-token").status_code == 401
    assert client.post("/api/systems/enrollment-token").status_code == 403    # ohne CSRF


def test_enrollment_info_carries_the_real_ca_fingerprint_and_a_pinned_command(admin):
    env, client, h = admin
    r = client.post("/api/systems/enrollment-token", headers={**h, "Host": "192.0.2.10:8443"})
    d = r.json()
    assert d["ca_fingerprint"] == os.environ["LL_TEST_CA_FP"]
    assert d["server_url"] == "https://192.0.2.10:8443"
    assert f"--ca-fingerprint {d['ca_fingerprint']}" in d["enroll_cmd"]
    assert f"--token {d['token']}" in d["enroll_cmd"] and f"--server {d['server_url']}" in d["enroll_cmd"]
    assert d["expires_at"] == env.clock() + 3600


def test_agents_get_the_configured_ip_not_the_name_the_admin_used(admin):
    # Neue Hosts kennen den Namen oft nicht (anderer DNS); die IP funktioniert immer
    env, client, h = admin
    d = client.post("/api/systems/enrollment-token", headers={**h, "Host": "lablantern.lan:9443"}).json()
    assert d["server_url"] == "https://192.0.2.10:8443"


def test_without_a_configured_ip_the_used_name_is_taken_if_configured(tmp_path, caplog):
    env = Env(tmp_path, caplog, hostnames=["lablantern.lan", "localhost"])
    secret = env.complete_setup()
    csrf = env.login(env.client, secret).json()["csrf_token"]
    d = env.client.post("/api/systems/enrollment-token", headers={"X-CSRF-Token": csrf, "Host": "lablantern.lan:9443"}).json()
    assert d["server_url"] == "https://lablantern.lan:9443"


def test_unknown_host_header_is_not_reflected_into_the_command(admin):
    env, client, h = admin
    d = client.post("/api/systems/enrollment-token", headers={**h, "Host": "evil.example:8443"}).json()
    assert "evil.example" not in json.dumps(d)
    assert d["server_url"] == "https://192.0.2.10:8443"


def test_enrollment_info_is_refused_when_the_ca_cannot_be_read(tmp_path, caplog):
    env = Env(tmp_path, caplog, ca_url="http://127.0.0.1:9/ca.crt")
    secret = env.complete_setup()
    csrf = env.login(env.client, secret).json()["csrf_token"]
    r = env.client.post("/api/systems/enrollment-token", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 503 and "Root certificate" in r.json()["detail"]


def test_install_command_pins_package_checksums_and_enrolls(admin):
    env, client, h = admin
    d = client.post("/api/systems/enrollment-token", headers={**h, "Host": "192.0.2.10:8443"}).json()
    cmd = d["install_cmd"]
    for name in ("amd64.deb", "arm64.deb", "amd64.rpm", "arm64.rpm"):
        assert f"{name}) SUM={hashlib.sha256(f'fake-{name}'.encode()).hexdigest()};;" in cmd
    assert "sha256sum -c" in cmd and "/api/agent/download/$ARCH.$PKG" in cmd
    assert "sudo dpkg -i" in cmd and "sudo rpm -U" in cmd and "mktemp -d" in cmd
    assert cmd.endswith(f"sudo lablantern-agent enroll --server https://192.0.2.10:8443 --token {d['token']} "
                        f"--ca-fingerprint {d['ca_fingerprint']}")


def test_install_command_is_missing_when_the_server_has_no_agent_binaries(tmp_path, caplog):
    env = Env(tmp_path, caplog)
    for f in env.agent_dir.iterdir():
        f.unlink()
    secret = env.complete_setup()
    csrf = env.login(env.client, secret).json()["csrf_token"]
    d = env.client.post("/api/systems/enrollment-token", headers={"X-CSRF-Token": csrf}).json()
    assert d["install_cmd"] is None and d["enroll_cmd"]


def test_windows_setup_is_one_line_with_pinned_checksums(admin):
    env, client, h = admin
    d = client.post("/api/systems/enrollment-token", headers={**h, "Host": "192.0.2.10:8443"}).json()
    w = d["windows"]
    for arch in ("amd64", "arm64"):
        assert f"{arch}='{hashlib.sha256(f'fake-windows-{arch}'.encode()).hexdigest()}'" in w["setup_cmd"]
    for cmd in (w["setup_cmd"], w["install_cmd"], w["update_cmd"]):
        assert "\n" not in cmd and "&&" not in cmd   # eine Zeile, auch für Windows PowerShell 5.1
        assert 'curl.exe -fsSLk "https://192.0.2.10:8443/api/agent/download/windows-$a.exe" -o $f; ' in cmd
        assert "(Get-FileHash $f -Algorithm SHA256).Hash -ne $s){throw" in cmd
    assert w["setup_cmd"].endswith(f"& $f setup --master https://192.0.2.10:8443 --ca-fingerprint {d['ca_fingerprint']}")
    assert w["install_cmd"].endswith(f"& $f enroll --server https://192.0.2.10:8443 --token {d['token']} "
                                     f"--ca-fingerprint {d['ca_fingerprint']}")
    assert w["update_cmd"].endswith("& $f install") and w["uninstall_cmd"].endswith("lablantern-agent.exe\" uninstall")


def test_windows_commands_are_missing_without_a_windows_build(tmp_path, caplog):
    env = Env(tmp_path, caplog)
    for f in env.agent_dir.glob("*windows*"):
        f.unlink()
    secret = env.complete_setup()
    csrf = env.login(env.client, secret).json()["csrf_token"]
    d = env.client.post("/api/systems/enrollment-token", headers={"X-CSRF-Token": csrf}).json()
    assert d["windows"] is None and d["install_cmd"]


def test_windows_host_reports_without_packages_and_package_cves_are_na(admin):
    env, client, h = admin
    token = client.post("/api/systems/enrollment-token", headers=h).json()["token"]
    e = env.new_client().post("/api/agent/enroll", json={
        "enrollment_token": token, "hostname": "host-w", "ip": "192.0.2.20", "host_type": "windows",
        "agent_version": "0.20.0"}).json()
    assert client.post(f"/api/systems/{e['system_id']}/approve", headers=h).status_code == 200
    bearer = {"Authorization": f"Bearer {e['agent_token']}"}
    r = env.new_client().post("/api/agent/report", headers=bearer, json=report(
        os_name="Windows 11 Pro 24H2", os_id="windows", os_version_id="11-24h2-w", kernel="10.0.26100.2314",
        packages=[], containers=[], security_updates_count=1, reboot_required=False,
        security_updates=[{"name": "2026-11 Cumulative Update for Windows 11 (KB5000001)", "to": ""}]))
    assert r.status_code == 200 and r.json()["needed_sboms"] == []
    row = system(env, e["system_id"])
    assert json.loads(row.collection_errors) == {} and row.sbom_updated_at is None
    assert not (env.data_dir / "sboms" / f"{e['system_id']}.json").exists()
    checks = coverage_of(client, "host-w")["checks"]
    assert checks["paket_cve"]["status"] == "na" and "Windows" in checks["paket_cve"]["detail"]
    assert checks["sicherheitsupdates"]["status"] == "fund" and "KB5000001" in checks["sicherheitsupdates"]["detail"]
    assert checks["reboot"]["status"] == "ok"
    # Container sammelt der Windows-Agent nicht: nicht geprüft ist nicht "ok"
    assert checks["container"]["status"] == "na" and checks["images"]["status"] == "na"
    # der Build ist kein Linux-Kernel: Die Frühwarnung beobachtet nur das Betriebssystem
    from app import earlywarning
    with env.app.state.ctx.session_factory() as s:
        watched = [(p["kind"], p["keyword"], p["version"]) for p in earlywarning.inventory_products(s)]
    assert watched == [("os", "windows", "11-24h2-w")]
    # ein Linux-Agent ohne Pakete bleibt ein Fehler
    sid, linux = activate(env, client, h, hostname="host-l", ip="192.0.2.21")
    env.new_client().post("/api/agent/report", headers=linux, json=report(packages=[]))
    assert "packages" in json.loads(system(env, sid).collection_errors)


WIN = dict(os_name="Windows 11 Pro 24H2", os_id="windows", os_version_id="11-24h2-w", kernel="10.0.26100.2314",
           packages=[], containers=[], security_updates_count=0, security_updates=[], reboot_required=False)
PROTECTED = {"antivirus": "on", "antivirus_name": "Microsoft Defender", "signature_age_days": 1, "firewall": "on"}


def windows_host(env, client, h):
    token = client.post("/api/systems/enrollment-token", headers=h).json()["token"]
    e = env.new_client().post("/api/agent/enroll", json={
        "enrollment_token": token, "hostname": "host-w", "ip": "192.0.2.20", "host_type": "windows",
        "agent_version": "0.21.0"}).json()
    assert client.post(f"/api/systems/{e['system_id']}/approve", headers=h).status_code == 200
    return e["system_id"], {"Authorization": f"Bearer {e['agent_token']}"}


def test_windows_protection_is_a_check_of_its_own(admin):
    env, client, h = admin
    sid, bearer = windows_host(env, client, h)

    def check(protection):
        body = report(**WIN) if protection is None else report(**WIN, protection=protection)
        assert env.new_client().post("/api/agent/report", headers=bearer, json=body).status_code == 200
        return coverage_of(client, "host-w")["checks"]["schutz"]

    # ein Agent vor 0.21 meldet es nicht: nicht geprüft, aber kein Fehler des Hosts
    old = check(None)
    assert old["status"] == "na" and "update the agent" in old["detail"]
    ok = check(PROTECTED)
    assert ok == {"status": "ok", "detail": "Microsoft Defender on, signatures 1 day old; firewall on"}
    off = check({**PROTECTED, "firewall": "off", "firewall_off": ["Public"]})
    assert off["status"] == "fund" and off["detail"].startswith("firewall off for the profile Public")
    stale = check({**PROTECTED, "signature_age_days": 12})
    assert stale["status"] == "fund" and "signatures are 12 days old" in stale["detail"]
    other = check({"antivirus": "off", "antivirus_name": "Other AV", "firewall": "on"})
    assert other["status"] == "fund" and "Other AV is off" in other["detail"]
    # nicht lesbar ist ein Fehler, nie ok; ein Fund daneben geht vor
    unknown = check({"antivirus": "unknown", "firewall": "on", "detail": "antivirus state not readable"})
    assert unknown["status"] == "fehler" and "antivirus could not be read (antivirus state not readable)" in unknown["detail"]
    both = check({"antivirus": "unknown", "firewall": "off", "firewall_off": ["Domain", "Public"]})
    assert both["status"] == "fund" and "profiles Domain, Public" in both["detail"] and "antivirus could not be read" in both["detail"]
    # der Fund steht bei den nächsten Schritten; Linux-Hosts haben die Prüfung nicht
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from app.actions import next_steps
    now = datetime.now(timezone.utc)
    run = SimpleNamespace(id=1, status="success", canary_status="ok", finished_at=now - timedelta(hours=1))
    cov = {"systems": client.get("/api/overview").json()["coverage"]}
    with env.app.state.ctx.session_factory() as s:
        steps = next_steps(s, {"kritisch": 0, "hoch": 0}, cov, run, now)
    assert any(st["title"] == "Protection" and "host-w: firewall off" in st["detail"] for st in steps)
    activate(env, client, h, hostname="host-l", ip="192.0.2.21")
    assert "schutz" not in coverage_of(client, "host-l")["checks"]
    # ein ungültiger Zustand wird abgelehnt statt als "an" gelesen
    bad = report(**WIN, protection={"antivirus": "yes", "firewall": "on"})
    assert env.new_client().post("/api/agent/report", headers=bearer, json=bad).status_code == 422


def test_windows_programs_are_stored_and_the_known_ones_watched(admin):
    env, client, h = admin
    sid, bearer = windows_host(env, client, h)
    software = [{"name": "Mozilla Firefox (x64 en-US)", "version": "131.0.3", "publisher": "Mozilla"},
                {"name": "Mozilla Maintenance Service", "version": "131.0.3", "publisher": "Mozilla"},
                {"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"},
                {"name": "Tailscale", "version": "1.76.6", "publisher": "Tailscale Inc."},
                {"name": "Example Tool with (odd) – name", "version": "", "publisher": ""}]
    r = env.new_client().post("/api/agent/report", headers=bearer, json=report(
        **{**WIN, "security_updates_count": 1,
           "security_updates": [{"name": "2026-11 Security Update (KB5000001)", "to": ""}]},
        protection=PROTECTED, software=software))
    assert r.status_code == 200
    inv = client.get(f"/api/systems/{sid}").json()["inventory"]
    assert [a["name"] for a in inv["software"]] == [a["name"] for a in software] and inv["protection"]["firewall"] == "on"
    sec = coverage_of(client, "host-w")["checks"]["sicherheitsupdates"]
    assert sec["status"] == "fund" and sec["detail"].endswith("Settings → Windows Update") and "command" not in sec
    from app import earlywarning
    with env.app.state.ctx.session_factory() as s:
        products = earlywarning.inventory_products(s)
    watched = {p["keyword"]: p for p in products if p["kind"] == "software"}
    assert set(watched) == {"firefox", "7-zip", "tailscale"}
    assert watched["firefox"]["product"] == "Mozilla Firefox (x64 en-US)" and watched["firefox"]["version"] == "131.0.3"
    assert earlywarning._watch_group(watched["firefox"]) == "Installed programs"
    # nur im Titel, wie Host-Pakete; der Schritt nennt die Version des Herstellers, ohne Befehl
    item = {"title": "Security Advisory: Firefox 132 fixes a sandbox escape", "summary": ""}
    assert [p["keyword"] for p in earlywarning.prefilter(item, products)] == ["firefox"]
    assert earlywarning.prefilter({"title": "Weekly roundup", "summary": "also Firefox and 7-Zip"}, products) == []
    ai = {"products": [{"product": "Firefox", "fixed_versions": ["132.0"], "affected": []}], "fix_available": "yes"}
    assert earlywarning.recommend(ai, [watched["firefox"]]) == [{
        "system": "host-w", "product": "Mozilla Firefox (x64 en-US)", "command": "",
        "text": "Update Mozilla Firefox (x64 en-US) to 132.0"}]
    # ein Linux-Host legt weder Programme noch Schutz ab, auch wenn ein Report sie nennt
    lid, linux = activate(env, client, h, hostname="host-l", ip="192.0.2.21")
    env.new_client().post("/api/agent/report", headers=linux, json=report(software=software, protection=PROTECTED))
    assert "software" not in client.get(f"/api/systems/{lid}").json()["inventory"]


def test_agent_download_serves_only_known_files(env):
    c = env.new_client()
    r = c.get("/api/agent/download/amd64")
    assert r.status_code == 200 and r.content == b"fake-agent-amd64"
    assert c.get("/api/agent/download/arm64.rpm").content == b"fake-arm64.rpm"
    r = c.get("/api/agent/download/windows-amd64.exe")
    assert r.content == b"fake-windows-amd64" and "lablantern-agent.exe" in r.headers["content-disposition"]
    assert c.get("/api/agent/download/windows-386.exe").status_code == 404
    for bad in ("386", "..%2F..%2Fetc%2Fpasswd", "amd64%00", "AMD64", "amd64.tar", "amd64.deb.sig"):
        assert c.get(f"/api/agent/download/{bad}").status_code == 404


def test_download_404_when_binary_is_missing(env):
    (env.agent_dir / "lablantern-agent-linux-arm64").unlink()
    assert env.new_client().get("/api/agent/download/arm64").status_code == 404


def test_tls_allowed_only_for_configured_names(env):
    c = env.new_client()
    for ok in ("lablantern.lan", "192.0.2.10", "localhost", "LABLANTERN.LAN"):
        assert c.get(f"/api/internal/tls-allowed?domain={ok}").status_code == 200, ok
    for bad in ("evil.example", "10.0.0.1", ""):
        assert c.get(f"/api/internal/tls-allowed?domain={bad}").status_code in (404, 422), bad
    assert c.get("/api/internal/tls-allowed").status_code in (404, 422)


# ---------- Anmeldung und Lebenszyklus ----------

def test_enrollment_and_lifecycle(admin):
    env, client, h = admin
    agent = env.new_client()
    token = client.post("/api/systems/enrollment-token", headers=h).json()["token"]

    r = agent.post("/api/agent/enroll", json={"enrollment_token": "invalid", "hostname": "host-a"})
    assert r.status_code == 400

    e = agent.post("/api/agent/enroll", json={"enrollment_token": token, "hostname": "host-a",
                                              "ip": "192.0.2.10", "agent_version": "0.3.0"}).json()
    assert e["ok"] and e["status"] == "pending"
    sid, bearer = e["system_id"], {"Authorization": f"Bearer {e['agent_token']}"}
    assert agent.post("/api/agent/enroll", json={"enrollment_token": token, "hostname": "dup"}).status_code == 400

    r = agent.post("/api/agent/report", headers=bearer, json=report())
    assert r.status_code == 403 and "waiting for approval" in r.text
    assert agent.post("/api/agent/report", json=report()).status_code == 401
    assert agent.post("/api/agent/report", headers={"Authorization": "Bearer falsch"}, json=report()).status_code == 401

    assert client.get("/api/systems").json()[0]["status"] == "pending"
    assert client.post(f"/api/systems/{sid}/approve", headers=h).status_code == 200
    assert agent.post("/api/agent/report", headers=bearer, json=report()).json()["ok"] is True

    detail = client.get(f"/api/systems/{sid}").json()
    assert detail["status"] == "active" and detail["security_updates_count"] == 2
    assert detail["reboot_required"] is True and detail["container_count"] == 2
    assert detail["inventory"]["kernel"] == "6.8.0-45-generic" and len(detail["inventory"]["containers"]) == 2

    assert client.post(f"/api/systems/{sid}/revoke", headers=h).status_code == 200
    r = agent.post("/api/agent/report", headers=bearer, json=report())
    assert r.status_code == 403 and "revoked" in r.text
    assert client.delete(f"/api/systems/{sid}", headers=h).status_code == 200
    assert client.get(f"/api/systems/{sid}").status_code == 404


def test_reenrolling_the_same_host_replaces_its_token_and_needs_approval_again(admin):
    env, client, h = admin
    first = enroll(env, client, h)
    client.post(f"/api/systems/{first['system_id']}/approve", headers=h)
    second = enroll(env, client, h)
    assert second["system_id"] == first["system_id"] and second["status"] == "pending"
    agent = env.new_client()
    old = agent.post("/api/agent/report", headers={"Authorization": f"Bearer {first['agent_token']}"}, json=report())
    assert old.status_code == 401


# ---------- SBOM und Fehlererfassung ----------

def test_report_writes_a_sbom_with_syft_style_purls(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report())
    sbom = json.loads((env.data_dir / "sboms" / f"{sid}.json").read_text())
    purls = [c["purl"] for c in sbom["components"] if c["type"] == "library"]
    assert purls[0] == "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.16?arch=amd64&distro=ubuntu-24.04&upstream=openssl"
    assert purls[1] == "pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6?arch=amd64&distro=ubuntu-24.04"
    assert system(env, sid).sbom_updated_at is not None


def coverage_of(client, name="host-a"):
    return next(s for s in client.get("/api/overview").json()["coverage"] if s["system_name"] == name)


def test_collection_errors_are_visible_in_the_coverage_matrix(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    errs = {"containers": "Docker-Socket nicht lesbar: permission denied",
            "security_updates": "weder apt-check noch apt-get verfügbar"}
    env.new_client().post("/api/agent/report", headers=bearer, json=report(
        containers=[], security_updates_known=False, security_updates_count=0, collection_errors=errs))
    checks = coverage_of(client)["checks"]
    assert checks["container"]["status"] == "fehler" and "permission denied" in checks["container"]["detail"]
    assert checks["sicherheitsupdates"]["status"] == "fehler"
    assert checks["paket_cve"]["status"] == "offen"        # noch kein Scan: nie „ok“, sondern wartend


def test_named_security_updates_give_the_exact_command(admin):
    env, client, h = admin
    _, bearer = activate(env, client, h, hostname="host-c", ip="192.0.2.67")
    agent = env.new_client()
    updates = [{"name": "libssl3t64", "from": "3.0.13-0ubuntu3.4", "to": "3.0.13-0ubuntu3.5"},
               {"name": "curl", "from": "8.5.0-2ubuntu10.1", "to": "8.5.0-2ubuntu10.2"}]
    agent.post("/api/agent/report", headers=bearer, json=report(security_updates=updates))
    sec = coverage_of(client, "host-c")["checks"]["sicherheitsupdates"]
    assert sec["detail"] == "2 pending: libssl3t64 → 3.0.13-0ubuntu3.5, curl → 8.5.0-2ubuntu10.2"
    assert sec["command"] == "sudo apt update && sudo apt install --only-upgrade libssl3t64 curl"
    overview = client.get("/api/overview").json()
    assert [(u["name"], u["count"]) for u in overview["updates"]["security"]] == [("host-c", 2)]
    # Nennt der Agent nicht alle (oder gar keine, vor 0.15): das ganze System aktualisieren
    agent.post("/api/agent/report", headers=bearer, json=report(security_updates=updates[:1]))
    assert coverage_of(client, "host-c")["checks"]["sicherheitsupdates"]["command"] == \
        "sudo apt update && sudo apt full-upgrade"


def test_unknown_security_update_state_is_an_error_not_zero_updates(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report(security_updates_known=False))
    assert coverage_of(client)["checks"]["sicherheitsupdates"]["status"] == "fehler"


def test_missing_package_list_removes_the_stale_sbom_and_flags_the_system(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    agent = env.new_client()
    agent.post("/api/agent/report", headers=bearer, json=report())
    path = env.data_dir / "sboms" / f"{sid}.json"
    assert path.is_file()
    agent.post("/api/agent/report", headers=bearer, json=report(
        packages=[], collection_errors={"packages": "dpkg-query fehlgeschlagen"}))
    assert not path.exists()                           # nichts Veraltetes als aktuell weiterscannen
    assert "dpkg-query" in system(env, sid).collection_errors


def test_empty_package_list_without_a_reported_reason_is_still_an_error(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report(packages=[]))
    assert not (env.data_dir / "sboms" / f"{sid}.json").exists()
    assert json.loads(system(env, sid).collection_errors)["packages"]


def test_report_from_an_agent_without_os_id_cannot_produce_a_valid_sbom(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report(os_id="", os_version_id=""))
    assert not (env.data_dir / "sboms" / f"{sid}.json").exists()
    assert "agent" in json.loads(system(env, sid).collection_errors)["packages"]


def test_a_clean_report_clears_earlier_errors(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    agent = env.new_client()
    agent.post("/api/agent/report", headers=bearer, json=report(packages=[], collection_errors={"packages": "x"}))
    agent.post("/api/agent/report", headers=bearer, json=report())
    assert json.loads(system(env, sid).collection_errors) == {}


def test_oversized_agent_requests_are_rejected_before_parsing(tmp_path, caplog):
    env = Env(tmp_path, caplog, max_agent_body=1000)
    r = env.new_client().post("/api/agent/report", headers={"Authorization": "Bearer x"},
                              content=b"{" + b" " * 5000 + b"}", )
    assert r.status_code == 413


def test_unknown_collection_error_keys_are_ignored_not_stored_blindly(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report(
        collection_errors={"packages": "", "evil": "x" * 10, "containers": "y" * 5000}))
    stored = json.loads(system(env, sid).collection_errors)
    assert "evil" not in stored and len(stored.get("containers", "")) <= 300


def test_ip_follows_the_latest_report(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report())
    assert client.get("/api/systems").json()[0]["ip"] == "testclient"   # Adresse des aktuellen Reports


def test_agent_commands_use_the_ip_even_when_the_ui_is_opened_by_name(admin):
    env, client, h = admin
    env.app.state.ctx.settings_agent_version = lambda: "0.12.0"
    d = client.post("/api/systems/enrollment-token", headers={**h, "Host": "lablantern.lan:8443"}).json()
    assert "https://192.0.2.10:8443/api/agent/download/" in d["setup_cmd"]
    assert d["setup_cmd"].endswith(f"setup --master https://192.0.2.10:8443 --ca-fingerprint {d['ca_fingerprint']}")


def test_setup_is_only_offered_with_an_agent_that_pairs_securely(admin):
    # Agenten vor 0.12 nutzen das alte Pairing (Code ohne Zufall des Masters, per MITM erzwingbar)
    env, client, h = admin
    d = client.post("/api/systems/enrollment-token", headers=h).json()
    assert d["setup_cmd"] is None and "--passkeys-sha256" not in d["install_cmd"]


def test_install_commands_pin_the_current_passkey_list(admin):
    import hashlib
    from tests.softauthn import SoftAuthenticator
    from tests.test_passkeys import register
    env, client, h = admin
    env.app.state.ctx.settings_agent_version = lambda: "0.12.0"
    d = client.post("/api/systems/enrollment-token", headers=h).json()
    assert "--passkeys-sha256" not in d["install_cmd"]   # noch kein Passkey: nichts festzulegen
    register(client, h, SoftAuthenticator())
    with env.app.state.ctx.session_factory() as s:
        from app.passkeys import trust_for_agents
        want = hashlib.sha256(trust_for_agents(s)["envelope"].encode()).hexdigest()
    d = client.post("/api/systems/enrollment-token", headers=h).json()
    for key in ("install_cmd", "enroll_cmd", "setup_cmd"):
        assert d[key].endswith(f" --passkeys-sha256 {want}"), key


def test_agent_storage_becomes_the_common_shape(admin):
    """Ab 0.18: Laufwerke und Pools vom Agenten; Zustand und Aufbau rechnet der Master, Unbekanntes bleibt unbekannt."""
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    storage = {"pools": [{"name": "tank", "kind": "ZFS pool", "vdevs": ["MIRROR", "MIRROR"], "status": "DEGRADED",
                          "size": 1000, "alloc": 250, "disks": ["sda", "sdb"]}],
               "disks": [{"name": "sda", "model": "WD Red", "size": 4000, "type": "hdd", "status": "ONLINE", "smart": "PASSED",
                          "temp": 33, "pool": "tank"},
                         {"name": "sdb", "type": "hdd", "status": "ONLINE", "smart": "FAILED", "pool": "tank"},
                         {"name": "sdc", "type": "ssd"}]}
    agent = env.new_client()
    assert agent.post("/api/agent/report", headers=bearer, json=report(storage=storage)).json()["ok"] is True
    st = client.get(f"/api/systems/{sid}").json()["inventory"]["storage"]
    tank = st["pools"][0]
    assert (tank["layout"], tank["state"], tank["percent"]) == ("2× MIRROR", "bad", 25.0)
    disks = {d["name"]: d for d in st["disks"]}
    assert (disks["sda"]["state"], disks["sda"]["temp"]) == ("ok", 33)
    assert disks["sdb"]["state"] == "bad" and disks["sdc"]["state"] == "unknown"
    assert agent.post("/api/agent/report", headers=bearer, json=report()).json()["ok"] is True   # VM: kein Speicher
    assert "storage" not in client.get(f"/api/systems/{sid}").json()["inventory"]


# ---------- Entfernte Pakete: Funde gleich mit dem Bericht erledigt, nicht erst im nächsten Lauf ----------

def findings_by_cve(env, sid):
    from app.models import Finding
    with env.app.state.ctx.session_factory() as s:
        return {f.cve_id: f for f in s.scalars(select(Finding).where(Finding.system_id == sid))}


def add_findings(env, sid, *rows):
    from app.models import Finding
    with env.app.state.ctx.session_factory() as s:
        for cve, component, version, kw in rows:
            s.add(Finding(system_id=sid, cve_id=cve, severity="hoch", component=component, installed_version=version,
                          **{"source": "grype", "status": "open", "target": "host", **kw}))
        s.commit()


def test_a_report_resolves_the_findings_of_packages_that_are_no_longer_installed(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    add_findings(env, sid,
                 ("CVE-PURGED", "linux-modules-6.8.0-44-generic", "6.8.0-44.44", {}),
                 ("CVE-PURGED-ACCEPTED", "linux-modules-6.8.0-44-generic", "6.8.0-44.44", {"status": "accepted"}),
                 ("CVE-UPGRADED", "curl", "8.5.0-2ubuntu10.5", {"source": "both"}),
                 ("CVE-INSTALLED", "curl", "8.5.0-2ubuntu10.6", {"source": "osv"}),
                 ("CVE-IMAGE", "busybox", "1.36.1", {"target": "image:openspeedtest/latest"}),
                 ("LL-EOL", "ubuntu", "24.04", {"source": "eol"}))
    env.new_client().post("/api/agent/report", headers=bearer, json=report())
    found = findings_by_cve(env, sid)
    assert {cve: f.status for cve, f in found.items()} == {
        "CVE-PURGED": "resolved", "CVE-PURGED-ACCEPTED": "resolved", "CVE-UPGRADED": "resolved",
        "CVE-INSTALLED": "open",    # dieselbe Version ist noch installiert
        "CVE-IMAGE": "open",        # Image-Funde hängen nicht an den Host-Paketen
        "LL-EOL": "open"}           # kein Scanner-Fund
    assert found["CVE-PURGED"].resolved_at is not None and found["CVE-INSTALLED"].resolved_at is None


def test_a_report_without_a_usable_package_list_resolves_nothing(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    add_findings(env, sid, ("CVE-1", "linux-modules-6.8.0-44-generic", "6.8.0-44.44", {}))
    env.new_client().post("/api/agent/report", headers=bearer, json=report(
        packages=[], collection_errors={"packages": "dpkg-query failed"}))
    assert findings_by_cve(env, sid)["CVE-1"].status == "open"   # unbekannt ist nicht entfernt
