import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.canary import run_canary_check
from app.scanner import (
    MAX_DB_AGE_HOURS,
    ScanError,
    grype_db_status,
    parse_grype_json,
    scan_sbom_grype,
)

FIXTURES = Path(__file__).parent / "fixtures"
CANARY_DIR = Path(__file__).resolve().parents[2] / "canary"


def real_grype():
    return json.loads((FIXTURES / "grype-log4j.json").read_text())


def by_cve(findings):
    return {f["cve_id"]: f for f in findings}


def test_parser_reads_kev_from_grype_data_not_from_a_hardcoded_list():
    f = by_cve(parse_grype_json(real_grype()))
    assert f["CVE-2021-44228"]["kev"] is True
    assert f["CVE-2021-45046"]["kev"] is True
    assert f["CVE-2021-45105"]["kev"] is False


def test_parser_does_not_flag_kev_when_grype_has_no_kev_entry():
    data = real_grype()
    for m in data["matches"]:
        m["vulnerability"]["knownExploited"] = None
    assert not any(f["kev"] for f in parse_grype_json(data))


def test_parser_extracts_fields_from_real_grype_output():
    f = by_cve(parse_grype_json(real_grype()))["CVE-2021-44228"]
    assert f["component"] == "log4j-core"
    assert f["installed_version"] == "2.14.1"
    assert f["fixed_version"] == "2.15.0"
    assert f["has_fix"] is True
    assert f["cvss_score"] == 10.0
    assert f["epss_score"] == pytest.approx(0.99999)
    assert f["severity_label"] == "Critical"
    assert f["source"] == "grype"


def test_parser_deduplicates_identical_matches():
    data = real_grype()
    data["matches"].append(json.loads(json.dumps(data["matches"][0])))
    ids = [f["cve_id"] for f in parse_grype_json(data)]
    assert ids.count("CVE-2021-44228") == 1


def test_parser_marks_wont_fix_as_no_fix():
    data = real_grype()
    data["matches"][2]["vulnerability"]["fix"] = {"versions": [], "state": "wont-fix"}
    assert by_cve(parse_grype_json(data))["CVE-2021-45105"]["has_fix"] is False


def test_parser_rejects_documents_without_matches_key():
    with pytest.raises(ScanError):
        parse_grype_json({"unexpected": True})


def fake_grype(tmp_path, script):
    path = tmp_path / "grype"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def test_scan_returns_findings_from_the_binary(tmp_path):
    out = tmp_path / "out.json"
    out.write_text(json.dumps(real_grype()))
    grype = fake_grype(tmp_path, f"cat {out}\n")
    findings = scan_sbom_grype(tmp_path / "x.json", grype_bin=grype)
    assert "CVE-2021-44228" in by_cve(findings)


def test_scan_failure_raises_instead_of_returning_no_findings(tmp_path):
    grype = fake_grype(tmp_path, "echo 'boom' >&2\nexit 1\n")
    with pytest.raises(ScanError, match="boom"):
        scan_sbom_grype(tmp_path / "x.json", grype_bin=grype)


def test_scan_garbage_output_raises(tmp_path):
    grype = fake_grype(tmp_path, "echo 'kein json'\n")
    with pytest.raises(ScanError):
        scan_sbom_grype(tmp_path / "x.json", grype_bin=grype)


def test_scan_timeout_raises(tmp_path):
    grype = fake_grype(tmp_path, "sleep 5\n")
    with pytest.raises(ScanError, match="timed out"):
        scan_sbom_grype(tmp_path / "x.json", grype_bin=grype, timeout=0.3)


def test_scan_without_binary_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ScanError, match="not found"):
        scan_sbom_grype(tmp_path / "x.json")


def db_status_script(built, valid=True):
    doc = json.dumps({"schemaVersion": "v6.1.10", "built": built, "valid": valid})
    return f"echo '{doc}'\n"


def iso(hours_ago):
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_fresh_database_passes_the_freshness_gate(tmp_path):
    status = grype_db_status(grype_bin=fake_grype(tmp_path, db_status_script(iso(5))))
    assert status["ok"] is True and 4.9 <= status["age_hours"] <= 5.2


def test_database_older_than_36h_fails_the_gate(tmp_path):
    status = grype_db_status(grype_bin=fake_grype(tmp_path, db_status_script(iso(MAX_DB_AGE_HOURS + 1))))
    assert status["ok"] is False and "36" in status["reason"]


def test_invalid_database_fails_the_gate(tmp_path):
    status = grype_db_status(grype_bin=fake_grype(tmp_path, db_status_script(iso(1), valid=False)))
    assert status["ok"] is False


def test_unreadable_database_status_fails_the_gate(tmp_path):
    status = grype_db_status(grype_bin=fake_grype(tmp_path, "exit 1\n"))
    assert status["ok"] is False and status["reason"]


# --- Kanarien-Test: nutzt die echten (verkleinerten) Grype-Daten, kein Mock der Bewertung ---

def scan_from_fixture(_path):
    return parse_grype_json(real_grype())


def test_canary_passes_with_real_grype_data():
    ok, msg = run_canary_check(CANARY_DIR, scan_fn=scan_from_fixture)
    assert ok is True, msg


def test_canary_fails_when_grype_has_no_kev_data():
    def no_kev(_path):
        data = real_grype()
        for m in data["matches"]:
            m["vulnerability"]["knownExploited"] = None
        return parse_grype_json(data)

    ok, msg = run_canary_check(CANARY_DIR, scan_fn=no_kev)
    assert ok is False and "KEV" in msg


def test_canary_fails_when_log4shell_is_not_detected():
    ok, msg = run_canary_check(CANARY_DIR, scan_fn=lambda _p: [])
    assert ok is False and "CVE-2021-44228" in msg


def test_canary_fails_when_the_scanner_errors():
    def broken(_path):
        raise ScanError("grype kaputt")

    ok, msg = run_canary_check(CANARY_DIR, scan_fn=broken)
    assert ok is False and "grype kaputt" in msg


def test_canary_fails_when_fixture_is_missing(tmp_path):
    ok, msg = run_canary_check(tmp_path, scan_fn=scan_from_fixture)
    assert ok is False and "not found" in msg


def test_osv_db_status_gate(tmp_path):
    import os
    import time

    from app.scanner import osv_db_status

    assert osv_db_status(tmp_path)["ok"] is False
    z = tmp_path / "osv-scalibr" / "Ubuntu" / "all.zip"
    z.parent.mkdir(parents=True)
    z.write_bytes(b"x")
    assert osv_db_status(tmp_path)["ok"] is True
    old = time.time() - 40 * 3600
    os.utime(z, (old, old))
    assert "40.0 h old" in osv_db_status(tmp_path)["reason"]


def test_osv_scan_error_codes(tmp_path):
    import stat

    from app.scanner import ScanError, scan_sboms_osv

    fake = tmp_path / "osv-scanner"
    fake.write_text('#!/bin/sh\necho \'{"results": []}\'\nexit 1\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    assert scan_sboms_osv([tmp_path / "a.cdx.json"], tmp_path, osv_bin=str(fake)) == {}   # 1 = Funde, kein Fehler
    fake.write_text("#!/bin/sh\necho kaputt >&2\nexit 128\n")
    with pytest.raises(ScanError, match="code 128"):
        scan_sboms_osv([tmp_path / "a.cdx.json"], tmp_path, osv_bin=str(fake))


def test_osv_age_counts_from_the_last_check_against_osv_dev(tmp_path):
    """osv-scanner schreibt eine unveränderte Datenbank nicht neu: RubyGems war 40 h alt und doch aktuell."""
    import os
    import stat
    import time

    from app.scanner import osv_db_status, scan_sboms_osv

    z = tmp_path / "osv-scalibr" / "RubyGems" / "all.zip"
    z.parent.mkdir(parents=True)
    z.write_bytes(b"x")
    old = time.time() - 40 * 3600
    os.utime(z, (old, old))
    assert osv_db_status(tmp_path)["ok"] is False
    fake = tmp_path / "osv-scanner"
    fake.write_text('#!/bin/sh\necho \'{"results": []}\'\nexit 0\n')
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    scan_sboms_osv([tmp_path / "a.cdx.json"], tmp_path, osv_bin=str(fake))
    assert osv_db_status(tmp_path)["ok"] is True


def test_osv_database_load_error_is_a_scan_error_and_not_a_check(tmp_path):
    """Ohne Netz meldet osv-scanner den Datenbankfehler nur auf stderr und endet normal, mit unvollständigen Funden."""
    import stat

    from app.scanner import ScanError, scan_sboms_osv

    fake = tmp_path / "osv-scanner"
    fake.write_text("#!/bin/sh\necho '{\"results\": []}'\necho 'Error during extraction: (extracting as "
                    "vulnmatch/osvlocal) unable to fetch OSV database: dial tcp: no such host' >&2\nexit 0\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(ScanError, match="could not be loaded.*no such host"):
        scan_sboms_osv([tmp_path / "a.cdx.json"], tmp_path, osv_bin=str(fake))
    assert not (tmp_path / "checked").exists()


# ---------- Fix-Version passend zur installierten Linie ----------

from app.scanner import next_fix, parse_osv_json  # noqa: E402


def grype_with_fixes(installed, fixes):
    data = real_grype()
    m = data["matches"][0]
    m["artifact"]["version"] = installed
    m["vulnerability"]["fix"] = {"versions": fixes, "state": "fixed"}
    return by_cve(parse_grype_json(data))["CVE-2021-44228"]


@pytest.mark.parametrize("installed,fixes,expected", [
    ("go1.27.0", ["1.26.9", "1.27.2"], "1.27.2"),
    ("3.12.3", ["3.9.23", "3.10.18", "3.11.13", "3.12.11", "3.13.4"], "3.12.11"),
    ("go1.22.2", ["1.21.11", "1.22.4"], "1.22.4"),
    ("3.3.3-r0", ["3.3.6-r0"], "3.3.6-r0"),
    ("2.4.68-1~deb13u1", ["2.4.69-1~deb13u1"], "2.4.69-1~deb13u1"),
    ("1.31.1", ["1.30.6"], ""),
])
def test_grype_fix_is_the_next_fix_above_the_installed_version(installed, fixes, expected):
    f = grype_with_fixes(installed, fixes)
    assert f["fixed_version"] == expected
    assert f["has_fix"] is bool(expected)


def test_next_fix_keeps_the_first_fix_when_the_version_is_unreadable():
    assert next_fix("", ["1.2.3", "1.0.0"]) == "1.2.3"


def osv_doc(pkg, affected):
    return {"results": [{"source": {"path": "/x.cdx.json"}, "packages": [{
        "package": pkg, "groups": [{"ids": ["GHSA-x"], "max_severity": "9.8"}],
        "vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-2026-1"], "affected": affected}]}]}]}


def osv_fix(pkg, affected):
    found = parse_osv_json(osv_doc(pkg, affected))["/x.cdx.json"]
    return found[0]["fixed_version"] if found else None


def test_osv_fix_comes_from_the_range_containing_the_installed_version():
    affected = [{"package": {"ecosystem": "Go", "name": "stdlib"}, "ranges": [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "1.26.9"}, {"introduced": "1.27.0-0"}, {"fixed": "1.27.2"}]}]}]
    assert osv_fix({"name": "stdlib", "version": "1.27.0", "ecosystem": "Go"}, affected) == "1.27.2"
    assert osv_fix({"name": "stdlib", "version": "1.26.4", "ecosystem": "Go"}, affected) == "1.26.9"


def test_osv_fix_ignores_other_distro_releases_and_other_packages():
    affected = [
        {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.29"}]}]},
        {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.13"}]}]},
    ]
    pkg = {"name": "openssl", "version": "3.0.13-0ubuntu3.12", "ecosystem": "Ubuntu:24.04:LTS"}
    assert osv_fix(pkg, affected) == "3.0.13-0ubuntu3.13"
    maven = [
        {"package": {"ecosystem": "Maven", "name": "org.bouncycastle:bcprov-jdk14"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.2.7"}]}]},
        {"package": {"ecosystem": "Maven", "name": "org.bouncycastle:bcprov-jdk18on"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.85"}]}]},
    ]
    assert osv_fix({"name": "org.bouncycastle:bcprov-jdk18on", "version": "1.84", "ecosystem": "Maven"}, maven) == "1.85"


def test_osv_drops_matches_without_an_installed_version():
    affected = [{"package": {"ecosystem": "Go", "name": "github.com/grafana/grafana"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.6.4+incompatible"}]}]}]
    for version in ("", "UNKNOWN", "(devel)"):
        assert osv_fix({"name": "github.com/grafana/grafana", "version": version, "ecosystem": "Go"}, affected) is None
