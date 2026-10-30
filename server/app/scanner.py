import json
import os
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("vulnwatch.scanner")

MAX_DB_AGE_HOURS = 36.0


class ScanError(Exception):
    """Der Scan ist fehlgeschlagen. Das ist nie „keine Funde“, sondern ein sichtbarer Fehler."""


def _grype(grype_bin: str | None) -> str:
    found = grype_bin or shutil.which("grype")
    if not found:
        raise ScanError("grype not found")
    return found


# ---------- Fix-Version passend zur installierten Linie ----------
# Advisories nennen Fixes für mehrere Linien (Go 1.26.9 und 1.27.2, Python 3.9.23 … 3.12.11). Angezeigt wird der
# kleinste Fix oberhalb der installierten Version, nicht der erste der Liste.

_PRE = ("a", "b", "c", "rc", "alpha", "beta", "pre", "preview", "dev")


def _vkey(v: str) -> tuple:
    """Grober, schemaübergreifender Vergleich (Semver, Debian, Alpine, PyPI): Zahlen numerisch, Vorabversionen
    und Debians ~ vor dem Ende, sonstige Buchstaben (Revisionen wie -r1, -0ubuntu3) danach."""
    import re

    v = re.sub(r"^(go|v)(?=\d)", "", (v or "").strip())
    out = []
    for t in re.findall(r"\d+|[a-zA-Z]+|~", v):
        if t == "~":
            out.append((-1, ""))
        elif t.isdigit():
            out.append((3, int(t)))
        elif t.lower() in _PRE:
            out.append((0, t.lower()))
        else:
            out.append((2, t.lower()))
    return tuple(out)


def _vcmp(a: str, b: str) -> int:
    ka, kb = _vkey(a), _vkey(b)
    n = max(len(ka), len(kb))
    ka, kb = ka + ((1, ""),) * (n - len(ka)), kb + ((1, ""),) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _semver_cmp(a: str, b: str) -> int:
    """Semver: Build-Metadaten (+incompatible) zählen nicht, eine Vorabversion (1.27.0-0) liegt vor 1.27.0."""
    def split(v: str) -> tuple[str, str]:
        core, _, pre = (v or "").split("+", 1)[0].partition("-")
        return core, pre

    (ca, pa), (cb, pb) = split(a), split(b)
    c = _vcmp(ca, cb)
    if c or pa == pb:
        return c
    if not pa or not pb:
        return 1 if not pa else -1
    return _vcmp(pa, pb)


def next_fix(installed: str, fixes: list[str]) -> str:
    """Kleinster Fix oberhalb der installierten Version; "" wenn alle genannten Fixes darunter liegen (der Fix für
    diese Linie ist unbekannt). Ohne lesbare Version bleibt der erste Fix."""
    fixes = [f for f in fixes if f]
    if not _vkey(installed):
        return fixes[0] if fixes else ""
    above = [f for f in fixes if _vcmp(f, installed) > 0]
    best = ""
    for f in above:
        if not best or _vcmp(f, best) < 0:
            best = f
    return best


def _osv_fixed(pkg: dict, vuln: dict) -> str:
    """Fix aus dem Bereich, der die installierte Version enthält, und nur aus Einträgen für dieses Paket und
    Ökosystem (sonst landet der Fix aus Ubuntu 22.04 oder aus einem anderen Maven-Artefakt in der Liste)."""
    name, eco, installed = pkg.get("name"), pkg.get("ecosystem"), str(pkg.get("version", ""))
    affected = [a for a in vuln.get("affected") or []
                if not (a.get("package") or {}).get("name")
                or ((a["package"]["name"] == name)
                    and (not eco or not a["package"].get("ecosystem") or a["package"]["ecosystem"] == eco))]
    fixes: list[str] = []
    for aff in affected:
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            cmp = _semver_cmp if rng.get("type") == "SEMVER" else _vcmp
            start = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    start = str(ev["introduced"])
                elif ev.get("fixed"):
                    fixed = str(ev["fixed"])
                    fixes.append(fixed)
                    if start is not None and _vkey(installed) and (start == "0" or cmp(installed, start) >= 0) \
                            and cmp(installed, fixed) < 0:
                        return fixed
                    start = None
    return next_fix(installed, fixes)


def parse_grype_json(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Übersetzt die Grype-Ausgabe in Rohfelder. Bewertet wird nicht hier, sondern im Server (rules.py)."""
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        raise ScanError("Grype output without 'matches'")
    found: dict[tuple, dict[str, Any]] = {}
    for m in data["matches"]:
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        fix = vuln.get("fix") or {}
        fixed = next_fix(artifact.get("version", ""), fix.get("versions") or [])
        cvss = max(
            (float((c.get("metrics") or {}).get("baseScore") or 0.0) for c in vuln.get("cvss") or []),
            default=0.0,
        )
        epss = vuln.get("epss") or []
        finding = {
            "cve_id": vuln.get("id", "UNKNOWN"),
            "title": vuln.get("description") or vuln.get("id", ""),
            "component": artifact.get("name", "unknown"),
            "installed_version": artifact.get("version", ""),
            "fixed_version": fixed,
            "has_fix": bool(fixed) and fix.get("state") != "wont-fix",
            "cvss_score": cvss,
            "severity_label": vuln.get("severity", ""),
            "epss_score": float(epss[0].get("epss", 0.0)) if epss else 0.0,
            "kev": bool(vuln.get("knownExploited")),
            "source": "grype",
            "purl": artifact.get("purl", ""),
        }
        key = (finding["cve_id"], finding["component"], finding["installed_version"], finding["purl"])
        if key not in found or finding["cvss_score"] > found[key]["cvss_score"]:
            found[key] = finding
    return list(found.values())


def scan_sbom_grype(
    sbom_path: Path, grype_bin: str | None = None, timeout: float = 900
) -> list[dict[str, Any]]:
    cmd = [_grype(grype_bin), f"sbom:{sbom_path}", "-o", "json", "--by-cve"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(f"Grype scan timed out (>{timeout:g}s)") from None
    except OSError as e:
        raise ScanError(f"grype not executable: {e.strerror}") from None
    if proc.returncode != 0:
        raise ScanError(f"grype exited with code {proc.returncode}: {proc.stderr.strip()[-300:]}")
    try:
        return parse_grype_json(json.loads(proc.stdout))
    except json.JSONDecodeError:
        raise ScanError("Grype output is not valid JSON") from None


def grype_db_status(grype_bin: str | None = None) -> dict[str, Any]:
    """Frische-Gate (PLAN Abschnitt 6): Grype-Datenbank (enthält KEV und EPSS) älter als 36 h ist ein Fehler."""
    try:
        proc = subprocess.run(
            [_grype(grype_bin), "db", "status", "-o", "json"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            return {"ok": False, "reason": f"grype db status failed (code {proc.returncode})"}
        data = json.loads(proc.stdout)
        built = datetime.fromisoformat(str(data["built"]).replace("Z", "+00:00"))
    except ScanError as e:
        return {"ok": False, "reason": str(e)}
    except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, json.JSONDecodeError):
        return {"ok": False, "reason": "database status unreadable"}
    age = round((datetime.now(timezone.utc) - built).total_seconds() / 3600, 1)
    base = {"age_hours": age, "built": data["built"], "schema": data.get("schemaVersion")}
    if data.get("valid") is False:
        return {**base, "ok": False, "reason": "Grype database invalid"}
    if age > MAX_DB_AGE_HOURS:
        return {**base, "ok": False, "reason": f"Grype database {age} h old (limit {MAX_DB_AGE_HOURS:g} h)"}
    return {**base, "ok": True, "reason": ""}


def grype_db_update(grype_bin: str | None = None, timeout: float = 900) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [_grype(grype_bin), "db", "update"], capture_output=True, text=True, timeout=timeout
        )
    except ScanError as e:
        return False, str(e)
    except (subprocess.TimeoutExpired, OSError):
        return False, "database update did not finish"
    if proc.returncode != 0:
        return False, f"database update failed: {proc.stderr.strip()[-200:]}"
    return True, ""


# ---------- zweite Quelle: OSV-Scanner (PLAN Abschnitt 5) ----------

OSV_OK_CODES = (0, 1)   # 1 = Schwachstellen gefunden, kein Fehler
OSV_DB_ERROR = "(extracting as vulnmatch/osvlocal)"   # stderr-Zeile, wenn eine Offline-Datenbank fehlt
OSV_CHECKED_MARKER = "checked"   # Zeitstempel des letzten fehlerfreien Abgleichs mit osv.dev


def _osv(osv_bin: str | None) -> str:
    found = osv_bin or shutil.which("osv-scanner")
    if not found:
        raise ScanError("osv-scanner not found")
    return found


def _osv_finding(pkg: dict, vuln: dict, groups: list[dict]) -> dict[str, Any]:
    ids = [vuln.get("id", "")] + list(vuln.get("aliases") or []) + list(vuln.get("upstream") or [])
    cve = next((i for i in ids if str(i).startswith("CVE-")), vuln.get("id", "UNKNOWN"))
    score = 0.0
    for g in groups:
        if vuln.get("id") in (g.get("ids") or []):
            try:
                score = max(score, float(g.get("max_severity") or 0))
            except ValueError:
                pass
    fixed = _osv_fixed(pkg, vuln)
    return {
        "cve_id": str(cve)[:64], "title": str(vuln.get("summary") or vuln.get("details") or cve)[:500],
        "component": str(pkg.get("name", "unknown")), "installed_version": str(pkg.get("version", "")),
        "fixed_version": fixed, "has_fix": bool(fixed), "cvss_score": min(score, 10.0), "severity_label": "",
        "epss_score": 0.0, "kev": False, "source": "osv", "purl": str(pkg.get("purl", "")),
    }


def parse_osv_json(data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """OSV-Ausgabe je gescannter Datei: {Pfad: [Rohfunde]}. Bewertet wird im Server."""
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        raise ScanError("OSV output without 'results'")
    out: dict[str, list[dict[str, Any]]] = {}
    for res in data.get("results") or []:
        path = str((res.get("source") or {}).get("path", ""))
        found: dict[tuple, dict[str, Any]] = {}
        for p in res.get("packages") or []:
            pkg, groups = p.get("package") or {}, p.get("groups") or []
            # Ohne Version (Go-Binary aus „(devel)“-Build) passt OSV jedes Advisory des Moduls, auch von 2018.
            if str(pkg.get("version", "")).strip().lower() in ("", "unknown", "(devel)"):
                continue
            for v in p.get("vulnerabilities") or []:
                f = _osv_finding(pkg, v, groups)
                key = (f["cve_id"], f["component"], f["installed_version"])
                if key not in found or f["cvss_score"] > found[key]["cvss_score"]:
                    found[key] = f
        out[path] = list(found.values())
    return out


def scan_sboms_osv(paths: list[Path], cache_dir: Path, osv_bin: str | None = None,
                   timeout: float = 2700) -> dict[str, list[dict[str, Any]]]:
    """Alle SBOMs eines Laufs in einem Aufruf: Die Offline-Datenbank (Ubuntu allein ~750 MB) wird nur einmal geladen.
    Offline, damit das Inventar nie an api.osv.dev geht. Dateien müssen auf .cdx.json enden (Erkennung)."""
    if not paths:
        return {}
    cmd = [_osv(osv_bin), "scan", "source", "--format", "json", "--offline-vulnerabilities",
           "--download-offline-databases"]
    for p in paths:
        cmd += ["-L", str(p)]
    env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache_dir)}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise ScanError(f"OSV scan timed out (>{timeout:g}s)") from None
    except OSError as e:
        raise ScanError(f"osv-scanner not executable: {e.strerror}") from None
    if proc.returncode not in OSV_OK_CODES:
        raise ScanError(f"osv-scanner exited with code {proc.returncode}: {proc.stderr.strip()[-300:]}")
    # Kann eine Datenbank nicht geladen werden (z. B. kein Netz), schreibt osv-scanner das nur nach stderr und endet
    # normal, mit unvollständigen Funden. Das ist ein Fehler, sonst gälten die fehlenden Funde als behoben.
    failed = [line for line in proc.stderr.splitlines() if OSV_DB_ERROR in line]
    if failed:
        raise ScanError(f"OSV database could not be loaded: {failed[0].strip()[-300:]}")
    try:
        found = parse_osv_json(json.loads(proc.stdout))
    except json.JSONDecodeError:
        raise ScanError("OSV output is not valid JSON") from None
    # Mit --download-offline-databases prüft osv-scanner jede benutzte Datenbank gegen den Hash auf osv.dev, schreibt
    # die Datei aber nur neu, wenn sie sich geändert hat. Deshalb zählt für die Frische dieser Zeitpunkt.
    try:
        (cache_dir / OSV_CHECKED_MARKER).touch()
    except OSError:
        pass
    return found


def osv_db_status(cache_dir: Path, now: float | None = None) -> dict[str, Any]:
    """Frische-Gate der OSV-Datenbanken: seit dem letzten fehlerfreien Abgleich mit osv.dev, ohne ihn die älteste
    geladene Ökosystem-Datei."""
    import time

    zips = list(cache_dir.glob("**/all.zip"))
    if not zips:
        return {"ok": False, "reason": "no OSV database downloaded yet"}
    marker = cache_dir / OSV_CHECKED_MARKER
    checked = marker.stat().st_mtime if marker.is_file() else min(z.stat().st_mtime for z in zips)
    age = round(((now or time.time()) - checked) / 3600, 1)
    if age > MAX_DB_AGE_HOURS:
        return {"ok": False, "age_hours": age, "reason": f"OSV database {age} h old (limit {MAX_DB_AGE_HOURS:g} h)"}
    return {"ok": True, "age_hours": age, "reason": ""}


def merge_sources(grype: list[dict[str, Any]], osv: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Funde beider Quellen zusammenführen: gleiche CVE in gleichem Paket = `both` (KEV/EPSS von Grype),
    Funde nur einer Quelle bleiben mit ihrer Quelle stehen (markiert, nie verworfen)."""
    out = [dict(f) for f in grype]
    index = {(f["cve_id"], f["component"], f["installed_version"]): f for f in out}
    for f in osv:
        key = (f["cve_id"], f["component"], f["installed_version"])
        if key in index:
            index[key]["source"] = "both"
            if not index[key].get("fixed_version") and f.get("fixed_version"):
                index[key]["fixed_version"], index[key]["has_fix"] = f["fixed_version"], True
        else:
            index[key] = dict(f)
            out.append(index[key])
    return out
