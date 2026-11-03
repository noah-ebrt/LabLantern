import logging
from pathlib import Path
from typing import Callable

from .rules import classify_severity
from .scanner import ScanError, scan_sbom_grype

log = logging.getLogger("lablantern.canary")

CANARY_CVE = "CVE-2021-44228"


def run_canary_check(
    canary_dir: Path,
    scan_fn: Callable[[Path], list[dict]] = scan_sbom_grype,
) -> tuple[bool, str]:
    """Kanarien-Test (PLAN Abschnitt 6): log4j 2.14.1 muss über die echte Scanner-Kette als
    CVE-2021-44228 und KEV-kritisch erkannt werden. Fehlschlag macht den Lauf ungültig.
    Die Produktstand-Kanarie (Fake-Produkt mit alter Version) folgt mit dem Produktstand-Check in Phase 4."""
    log4j = Path(canary_dir) / "log4j-2.14.1.json"
    if not log4j.is_file():
        return False, f"Canary file not found: {log4j}"
    try:
        findings = scan_fn(log4j)
    except ScanError as e:
        return False, f"Canary test failed: scanner error ({e})"
    hit = next((f for f in findings if f.get("cve_id") == CANARY_CVE), None)
    if hit is None:
        return False, f"Canary test failed: {CANARY_CVE} not found in log4j-2.14.1.json"
    severity = classify_severity(
        hit.get("cvss_score", 0.0), hit.get("kev", False), hit.get("has_fix", False),
        False, hit.get("severity_label", ""),
    )
    if not hit.get("kev") or severity != "kritisch":
        return False, (
            f"Canary test failed: {CANARY_CVE} was not detected as KEV-critical "
            "(is KEV data missing from the scanner database?)"
        )
    return True, f"Canary test passed: {CANARY_CVE} detected as KEV-critical"
