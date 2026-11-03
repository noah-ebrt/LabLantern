"""Golden-File-Test (PLAN Abschnitt 6): feste Scanner-Ausgaben ergeben immer dieselben bewerteten Funde.
Ändert sich golden/expected.json, hat sich die Bewertung geändert: absichtlich prüfen, dann neu erzeugen mit
`LABLANTERN_UPDATE_GOLDEN=1 pytest tests/test_golden.py`."""
import json
import os
from pathlib import Path

from app.rules import classify_severity
from app.scanner import merge_sources, parse_grype_json, parse_osv_json

HERE = Path(__file__).parent / "golden"


def rate(exposed: bool) -> list[dict]:
    grype = parse_grype_json(json.loads((HERE / "grype.json").read_text()))
    osv = parse_osv_json(json.loads((HERE / "osv.json").read_text()))["/tmp/host.cdx.json"]
    out = []
    for f in merge_sources(grype, osv):
        out.append({k: f[k] for k in ("cve_id", "component", "installed_version", "fixed_version", "has_fix",
                                      "cvss_score", "kev", "source")}
                   | {"severity": classify_severity(f["cvss_score"], f["kev"], f["has_fix"], exposed,
                                                    f["severity_label"])})
    return sorted(out, key=lambda f: (f["cve_id"], f["component"]))


def test_rating_matches_the_golden_file():
    got = {"internal": rate(False), "internet_exposed": rate(True)}
    path = HERE / "expected.json"
    if os.environ.get("LABLANTERN_UPDATE_GOLDEN"):
        path.write_text(json.dumps(got, indent=1, sort_keys=True) + "\n")
    assert got == json.loads(path.read_text())


def test_rating_is_deterministic():
    assert rate(False) == rate(False) and rate(True) == rate(True)
