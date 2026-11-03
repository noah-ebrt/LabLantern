"""Worker: scannt SBOMs und liefert Rohdaten an den Server. Er hat keinen Master key, keine Datenbank
und kein Daten-Volume, nur ein Worker-Token und die Server-API. Bewertet wird im Server."""
import hashlib
import json
import logging
import os
import shutil
import signal
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .canary import run_canary_check
from .scanner import (ScanError, grype_db_status, grype_db_update, merge_sources, osv_db_status, scan_sbom_grype,
                      scan_sboms_osv)

log = logging.getLogger("lablantern.worker")
SCANNERS = ("grype+osv", "grype")
# Leichter Modus: nur Grype. OSV lädt dann keine Datenbanken (spart den größten Teil des Arbeitsspeichers)
LIGHT_STATUS = {"ok": True, "disabled": True, "reason": "light mode (LABLANTERN_SCANNERS=grype)"}
OSV_REUSE_HOURS = 20   # ältere OSV-Datenbank: neu laden statt Ergebnisse wiederverwenden (Frische-Gate)


class ServerError(Exception):
    """Der Server hat die Anfrage abgelehnt. Die Meldung enthält seinen Grund (nicht nur den Statuscode)."""


class ServerClient:
    def __init__(self, base_url: str, token: str, timeout: float = 60, retries: int = 6, retry_wait: float = 5):
        self.base_url = base_url.rstrip("/")
        self._rejected: set = set()   # Fortschrittsschritte, die der Server abgelehnt hat (je einmal melden)
        self.token = token
        self.timeout = timeout
        self.retries, self.retry_wait = retries, retry_wait

    def _request(self, method: str, path: str, body: dict | None = None) -> bytes:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        # Ein Neustart des Servers (z. B. ein Update) dauert Sekunden: kurz warten statt den Host als Fehler zu werten
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as e:
                reason = e.read(300).decode("utf-8", "replace").strip()
                raise ServerError(f"HTTP {e.code} from {path}: {reason}") from None
            except (urllib.error.URLError, ConnectionError):
                if attempt == self.retries:
                    raise
                time.sleep(self.retry_wait)
        raise AssertionError("unreachable")

    def claim(self) -> dict | None:
        return json.loads(self._request("POST", "/api/worker/claim", {}))["job"]

    def download_sbom(self, job_id: int, system_id: int, dest: Path) -> None:
        dest.write_bytes(self._request("GET", f"/api/worker/jobs/{job_id}/sbom/{system_id}"))

    def download_image_sbom(self, job_id: int, system_id: int, image_id: str, dest: Path) -> None:
        dest.write_bytes(self._request("GET", f"/api/worker/jobs/{job_id}/image-sbom/{system_id}/{image_id}"))

    def post_result(self, job_id: int, payload: dict) -> None:
        self._request("POST", f"/api/worker/jobs/{job_id}/result", payload)

    def progress(self, job_id: int, **fields) -> None:
        """Zwischenstand für die Anzeige. Darf den Scan nie aufhalten: Fehler werden verschluckt."""
        try:
            data = json.dumps(fields).encode()
            req = urllib.request.Request(f"{self.base_url}/api/worker/jobs/{job_id}/progress", data=data, method="POST",
                                         headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5):
                pass
        except urllib.error.HTTPError as e:   # abgelehnt: nicht still, sonst steht die Anzeige unbemerkt
            if fields.get("step") not in self._rejected:
                self._rejected.add(fields.get("step"))
                log.warning("Progress step %r rejected by the server (HTTP %d)", fields.get("step"), e.code)
        except Exception:  # noqa: BLE001 (Anzeige ist optional)
            pass

    def post_fail(self, job_id: int, error: str) -> None:
        self._request("POST", f"/api/worker/jobs/{job_id}/fail", {"error": error[:500]})


def _clip(finding: dict[str, Any]) -> dict[str, Any]:
    """Überlange Felder kürzen, damit ein einzelner Eintrag nicht das ganze Ergebnis ablehnen lässt."""
    out = dict(finding)
    out["title"] = str(out.get("title", ""))[:200]
    for k in ("component", "installed_version", "fixed_version"):
        out[k] = str(out.get(k, ""))[:300]
    out["purl"] = str(out.get("purl", ""))[:600]
    return out


class Worker:
    def __init__(
        self,
        client: ServerClient,
        canary_dir: Path,
        scan_fn: Callable[[Path], list[dict]] = scan_sbom_grype,
        db_update: Callable[[], tuple[bool, str]] = grype_db_update,
        db_status: Callable[[], dict] = grype_db_status,
        retry_delay: float = 2.0,
        osv_fn: Callable[[list[Path]], dict[str, list[dict]]] | None = None,
        osv_status: Callable[[], dict] = lambda: {"ok": True, "reason": ""},
        parallel: int = 4,
        result_cache: Path | None = None,
        osv_cache_dir: Path | None = None,
        scanners: str = "grype+osv",
    ):
        self.client, self.canary_dir = client, canary_dir
        self.scan_fn, self.db_update, self.db_status = scan_fn, db_update, db_status
        self.osv_fn, self.osv_status = osv_fn, osv_status
        self.retry_delay = retry_delay
        self.parallel = max(1, parallel)
        self.result_cache = result_cache
        self.osv_cache_dir = osv_cache_dir
        self.light = scanners == "grype"

    def run_once(self) -> bool:
        """Holt höchstens einen Auftrag und arbeitet ihn ab. True, wenn ein Auftrag bearbeitet wurde."""
        try:
            job = self.client.claim()
        except (ServerError, urllib.error.URLError, OSError, ValueError) as e:
            log.warning("Server unreachable or token rejected: %s", e if isinstance(e, ServerError) else type(e).__name__)
            return False
        if job is None:
            return False
        log.info("Job #%d claimed (%d systems)", job["id"], len(job["systems"]))
        try:
            result = self._process(job)
            self._deliver(job["id"], result)
        except Exception as e:  # nie still sterben: dem Server das Scheitern melden
            log.exception("Job #%d failed", job["id"])
            try:
                self.client.post_fail(job["id"], f"Worker error: {e}")
            except Exception:
                log.error("Failure could not be reported; the server timeout will raise an alert")
        return True

    def _deliver(self, job_id: int, result: dict) -> None:
        for attempt in range(3):
            try:
                self.client.post_result(job_id, result)
                return
            except ServerError:
                raise  # abgelehnt (Validierung/Zustand): Wiederholen hilft nicht
            except (urllib.error.URLError, OSError):
                if attempt == 2:
                    raise
                time.sleep(self.retry_delay)

    def _cached_scan(self, path: Path, digest: str, db_built: str) -> tuple[list[dict], bool]:
        """(Funde, wiederverwendet). Gleiche SBOM (SHA-256) gegen die gleiche Datenbank (Build-Zeit) ergibt
        dasselbe Ergebnis; nur dann wird ein früheres verwendet. Ohne bekannte Datenbank wird immer gescannt."""
        cached = self.result_cache / f"{digest}.json" if self.result_cache and db_built else None
        if cached is not None and cached.is_file():
            try:
                stored = json.loads(cached.read_text())
                if stored.get("db_built") == db_built:
                    return stored["findings"], True
            except (OSError, ValueError, KeyError):
                pass
        findings = [_clip(f) for f in self.scan_fn(path)]
        if cached is not None:
            try:
                cached.write_text(json.dumps({"db_built": db_built, "findings": findings}))
            except OSError:
                pass   # Zwischenspeicher ist nur eine Abkürzung
        return findings, False

    def _osv_cached(self, files: dict[str, Path], db_key: str) -> tuple[dict[str, list[dict]], dict]:
        """OSV nur für SBOMs, deren Ergebnis zum aktuellen Datenbankstand fehlt; das Laden der Datenbanken (Ubuntu
        allein einige Minuten) entfällt, wenn sich nichts geändert hat."""
        if self.light:
            return {}, dict(LIGHT_STATUS)
        store = self.result_cache / "osv" if self.result_cache and db_key else None
        known: dict[str, list[dict]] = {}
        pre = self.osv_status()   # nur aus einer frischen Datenbank; sonst lädt OSV sie bei diesem Aufruf neu
        if store is not None and pre.get("ok") and (pre.get("age_hours") or 0) < OSV_REUSE_HOURS:
            store.mkdir(exist_ok=True)
            for digest in files:
                try:
                    stored = json.loads((store / f"{digest}.json").read_text())
                    if stored.get("db") == db_key:
                        known[digest] = stored["findings"]
                except (OSError, ValueError, KeyError):
                    pass
        todo = {d: p for d, p in files.items() if d not in known}
        found, status = self._osv(todo) if todo else ({}, self.osv_status())
        after = self.osv_db_key()   # der Aufruf kann die Datenbanken aktualisiert haben
        if store is not None and status.get("ok") and after:
            for digest in todo:
                try:
                    (store / f"{digest}.json").write_text(json.dumps({"db": after, "findings": found.get(digest, [])}))
                except OSError:
                    pass
        return {**known, **found}, {**status, "reused": len(known)}

    def _osv(self, files: dict[str, Path]) -> tuple[dict[str, list[dict]], dict]:
        """Zweite Quelle über alle SBOMs in einem Aufruf. Ein Fehler hier kippt den Lauf nicht (Grype bleibt die
        Hauptquelle), steht aber als Status im Ergebnis und im Report."""
        if self.osv_fn is None:
            return {}, {"ok": False, "reason": "OSV-Scanner not installed in this worker"}
        if not files:   # noch keine SBOMs (z. B. frische Installation ohne Hosts): nichts zu prüfen, kein Fehler
            return {}, {"ok": True, "reason": "no SBOMs in this run"}
        try:
            by_path = self.osv_fn(list(files.values()))
        except ScanError as e:
            return {}, {"ok": False, "reason": str(e)[:300]}
        status = self.osv_status()
        names = {str(p): key for key, p in files.items()}
        return {names[path]: [_clip(f) for f in found] for path, found in by_path.items() if path in names}, status

    def _process(self, job: dict) -> dict:
        report = getattr(self.client, "progress", None) or (lambda *_a, **_k: None)
        report(job["id"], step="database", text="Updating the vulnerability database")
        ok, msg = self.db_update()
        if not ok:
            log.warning("database update failed: %s (Frische-Gate entscheidet)", msg)
        db = self.db_status()
        db_built = str(db.get("built", "")) if db.get("ok") else ""
        report(job["id"], step="canary", text="Canary test: a known Log4Shell SBOM must be detected")
        canary_ok, canary_msg = run_canary_check(self.canary_dir, scan_fn=self.scan_fn)   # nie aus dem Speicher
        hosts = [e for e in job["systems"] if e["sbom"]]
        systems: list[dict] = []
        files: dict[str, Path] = {}   # Inhalts-Hash -> SBOM-Datei (für Grype und den OSV-Durchgang)
        parts: list[tuple[dict, str, list[tuple[str, str]]]] = []   # System, Hash der Host-SBOM, (Image-Ref, Hash)
        with tempfile.TemporaryDirectory(prefix="ll-sbom-") as tmp:
            # 1. Alle SBOMs laden und nach Inhalt zusammenfassen: dasselbe Image auf mehreren Hosts nur einmal
            report(job["id"], step="download", text=f"Downloading the SBOMs of {len(hosts)} hosts")
            for entry in hosts:
                path = Path(tmp) / f"{entry['id']}.cdx.json"
                try:
                    self.client.download_sbom(job["id"], entry["id"], path)
                except urllib.error.URLError as e:
                    systems.append({"system_id": entry["id"], "ok": False, "findings": [],
                                    "error": f"SBOM download failed ({getattr(e, 'reason', e)})"[:500]})
                    continue
                host_digest = self._keep(path, files)
                image_errors, refs = {}, []
                for img in (i for i in entry.get("images", []) if i["sbom"]):   # ohne SBOM: Server zeigt „offen“
                    ipath = Path(tmp) / f"img-{entry['id']}-{img['id'].removeprefix('sha256:')}.cdx.json"
                    try:
                        self.client.download_image_sbom(job["id"], entry["id"], img["id"], ipath)
                        refs.append((img["ref"], self._keep(ipath, files)))
                    except (ServerError, urllib.error.URLError) as e:
                        image_errors[img["id"]] = str(e)[:300]
                parts.append(({"system_id": entry["id"], "ok": True, "error": "", "image_errors": image_errors},
                              host_digest, refs))
            # 2. Grype parallel über jeden Inhalt einmal
            names = {}
            for result, host_digest, refs in parts:
                names.setdefault(host_digest, next(e.get("name", "") for e in hosts if e["id"] == result["system_id"]))
                for ref, digest in refs:
                    names.setdefault(digest, ref)
            found: dict[str, list[dict]] = {}
            failed: dict[str, str] = {}
            done = reused = 0
            report(job["id"], step="scan", text="Scanning hosts and images", done=0, total=len(files), reused=0)
            # OSV läuft gleichzeitig mit Grype: es ist einfädig und lädt minutenlang seine Datenbanken
            osv_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="osv")
            osv_future = osv_pool.submit(self._osv_cached, dict(files), self.osv_db_key())
            with ThreadPoolExecutor(max_workers=self.parallel, thread_name_prefix="grype") as pool:
                futures = {pool.submit(self._cached_scan, path, digest, db_built): digest
                           for digest, path in files.items()}
                for fut in as_completed(futures):
                    digest = futures[fut]
                    try:
                        found[digest], was_cached = fut.result()
                        reused += was_cached
                    except ScanError as e:
                        failed[digest] = str(e)[:500]
                    done += 1
                    report(job["id"], step="scan", text=f"Scanned {names.get(digest, '')}"[:200],
                           done=done, total=len(files), reused=reused)
            if not osv_future.done():
                report(job["id"], step="osv", text=f"Second source: OSV-Scanner over {len(files)} SBOMs")
            try:
                osv, osv_status = osv_future.result()
            finally:
                osv_pool.shutdown()
        for result, host_digest, refs in parts:
            if host_digest in failed:   # Host-Scan gescheitert: das System gilt als nicht geprüft
                systems.append({"system_id": result["system_id"], "ok": False, "error": failed[host_digest],
                                "findings": []})
                continue
            findings = merge_sources(found[host_digest], osv.get(host_digest, []))
            for ref, digest in refs:
                if digest in failed:
                    result["image_errors"][f"ref:{ref}"[:200]] = failed[digest]
                    continue
                merged = merge_sources(found[digest], osv.get(digest, []))
                findings += [{**f, "target": f"image:{ref}"[:300]} for f in merged]
            systems.append({**result, "findings": findings})
        log.info("Job #%d scanned %d SBOMs (%d from the same database, reused), %d failed",
                 job["id"], len(files), reused, len(failed))
        report(job["id"], step="saving", text="Saving and rating findings")
        return {
            "canary": {"ok": canary_ok, "message": canary_msg[:500]},
            "grype_db": {"ok": bool(db.get("ok")), "age_hours": db.get("age_hours"),
                         "built": str(db.get("built", ""))[:64], "reason": str(db.get("reason", ""))[:300]},
            "osv": {"ok": bool(osv_status.get("ok")), "age_hours": osv_status.get("age_hours"),
                    "reason": str(osv_status.get("reason", ""))[:300], "disabled": bool(osv_status.get("disabled"))},
            "systems": systems,
        }

    def osv_db_key(self) -> str:
        """Stand der OSV-Datenbanken (jüngste Ökosystem-Datei); leer ohne Zwischenspeicher oder Datenbank."""
        if not self.result_cache or self.osv_cache_dir is None:
            return ""
        zips = list(self.osv_cache_dir.glob("**/all.zip"))
        return str(max(z.stat().st_mtime for z in zips)) if zips else ""

    @staticmethod
    def _keep(path: Path, files: dict[str, Path]) -> str:
        """Inhalts-Hash der SBOM; doppelte Inhalte werden nur einmal behalten."""
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in files:
            path.unlink(missing_ok=True)
        else:
            files[digest] = path
        return digest


def _noop() -> None:
    pass


def scanners_from_env(env) -> str:
    value = env.get("LABLANTERN_SCANNERS", "grype+osv").strip() or "grype+osv"
    if value not in SCANNERS:
        raise SystemExit(f"LABLANTERN_SCANNERS must be one of {', '.join(SCANNERS)}, not {value!r}")
    return value


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    scanners = scanners_from_env(os.environ)
    token = Path(os.environ.get("LABLANTERN_WORKER_TOKEN_FILE", "/worker_auth/worker.token")).read_text().strip()
    canary_dir = Path(os.environ.get("LABLANTERN_CANARY_DIR", "/canary"))
    osv_cache = Path(os.environ.get("LABLANTERN_OSV_CACHE", str(Path.home() / ".cache" / "osv")))
    have_osv = scanners != "grype" and shutil.which("osv-scanner") is not None
    if scanners == "grype":
        log.info("Light mode: scanning with Grype only, OSV is switched off")
    elif not have_osv:
        log.warning("osv-scanner not found: runs report the second source as missing")
    # Zwischenspeicher im tmpfs: übersteht Läufe, aber keinen neuen Container (neue Grype-Version, frisch)
    result_cache = Path(tempfile.gettempdir()) / "ll-results"
    result_cache.mkdir(exist_ok=True)
    worker = Worker(ServerClient(os.environ.get("LABLANTERN_SERVER_URL", "http://server:8000"), token), canary_dir,
                    osv_fn=(lambda paths: scan_sboms_osv(paths, osv_cache)) if have_osv else None,
                    osv_status=lambda: osv_db_status(osv_cache),
                    parallel=int(os.environ.get("LABLANTERN_SCAN_PARALLEL", "4")), result_cache=result_cache,
                    osv_cache_dir=osv_cache, scanners=scanners)
    running = True

    def stop(sig, _frame):
        nonlocal running
        log.info("Signal %d received, stopping worker", sig)
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("Worker ready, waiting for jobs")
    while running:
        try:
            busy = worker.run_once()
        except Exception:
            log.exception("Unexpected error in worker loop")
            busy = False
        if not busy:
            time.sleep(5)


if __name__ == "__main__":
    main()
