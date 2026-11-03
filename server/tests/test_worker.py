import json
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy import select

from app.config import Settings
from app.main import create_app
from app.models import Finding, ScanJob, ScanRun, SystemScanResult
from app.scanner import ScanError, parse_grype_json
from app.scanrun import enqueue_scan_run
from app.worker import ServerClient, Worker
from tests.test_scan_flow import Notes, make_system

FIXTURES = Path(__file__).parent / "fixtures"
CANARY_DIR = Path(__file__).resolve().parents[2] / "canary"
GOOD_DB = {"ok": True, "age_hours": 2.0, "built": "x", "reason": ""}


@pytest.fixture
def live(tmp_path):
    app = create_app(Settings(data_dir=tmp_path / "data", worker_token_file=tmp_path / "auth" / "worker.token"))
    ctx = app.state.ctx
    ctx.notifier = Notes()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    ctx.base_url = f"http://127.0.0.1:{port}"
    yield ctx
    server.should_exit = True
    t.join(timeout=5)


def real_scan(_path):
    return parse_grype_json(json.loads((FIXTURES / "grype-log4j.json").read_text()))


def worker_for(ctx, scan_fn=real_scan, db_status=lambda: GOOD_DB, token=None, **kwargs):
    client = ServerClient(ctx.base_url, token or ctx.worker_token)
    return Worker(client, CANARY_DIR, scan_fn=scan_fn, db_update=lambda: (True, ""), db_status=db_status, **kwargs)


def runs(ctx):
    with ctx.session_factory() as s:
        return list(s.scalars(select(ScanRun)))


def test_worker_processes_a_queued_job_end_to_end(live):
    sid = make_system(live, "host-c")
    enqueue_scan_run(live, "manual")
    assert worker_for(live).run_once() is True
    [run] = runs(live)
    assert run.status == "success" and run.canary_status == "ok"
    with live.session_factory() as s:
        assert {f.cve_id for f in s.scalars(select(Finding))} >= {"CVE-2021-44228"}
        assert s.scalar(select(SystemScanResult)).status == "ok"


def test_worker_returns_false_when_there_is_no_job(live):
    assert worker_for(live).run_once() is False


def test_scan_error_of_one_system_makes_the_run_partial_not_clean(live):
    make_system(live, "ok-host")
    broken = make_system(live, "kaputt")
    (live.settings.data_dir / "sboms" / f"{broken}.json").write_text('{"host": "kaputt"}')   # eigener Inhalt

    def flaky(path):
        if "log4j" in str(path):
            return real_scan(path)
        if "kaputt" in Path(path).read_text():
            raise ScanError("grype exited with code 1: boom")
        return []

    enqueue_scan_run(live, "manual")
    worker_for(live, scan_fn=flaky).run_once()
    [run] = runs(live)
    assert run.status == "partial"
    with live.session_factory() as s:
        results = sorted((r.status for r in s.scalars(select(SystemScanResult))))
    assert results == ["fehler", "ok"]
    assert "boom" in live.notifier.sent[-1][1]


def test_failed_canary_marks_the_run_failed(live):
    make_system(live)
    enqueue_scan_run(live, "manual")
    worker_for(live, scan_fn=lambda p: []).run_once()
    [run] = runs(live)
    assert run.status == "failed" and run.canary_status == "fehler"
    assert live.notifier.sent[-1][0].startswith("[IMMEDIATE ALERT]")


def test_stale_scanner_database_marks_the_run_failed(live):
    make_system(live)
    enqueue_scan_run(live, "manual")
    stale = {"ok": False, "age_hours": 50.0, "built": "x", "reason": "Grype-Datenbank 50 h alt (Grenze 36 h)"}
    worker_for(live, db_status=lambda: stale).run_once()
    [run] = runs(live)
    assert run.status == "failed" and "50 h" in run.error


def test_system_without_sbom_is_not_downloaded_and_is_reported_as_error(live):
    make_system(live, "ohne", sbom=False)
    enqueue_scan_run(live, "manual")
    worker_for(live).run_once()
    [run] = runs(live)
    assert run.status == "partial"
    with live.session_factory() as s:
        assert "SBOM" in s.scalar(select(SystemScanResult)).error


def test_unexpected_exception_is_reported_as_job_failure(live):
    make_system(live)
    enqueue_scan_run(live, "manual")

    def explode(path):
        if "log4j" in str(path):
            return real_scan(path)
        raise RuntimeError("unerwartet")

    worker_for(live, scan_fn=explode).run_once()
    [run] = runs(live)
    assert run.status == "failed" and "unerwartet" in run.error
    assert live.notifier.sent[-1][0].startswith("[IMMEDIATE ALERT]")


def test_wrong_token_gets_nothing_and_does_not_crash(live):
    make_system(live)
    enqueue_scan_run(live, "manual")
    assert worker_for(live, token="falsch").run_once() is False
    assert runs(live)[0].status == "queued"


def test_unreachable_server_does_not_crash_the_worker():
    w = Worker(ServerClient("http://127.0.0.1:9", "x", retry_wait=0), CANARY_DIR, scan_fn=lambda p: [],
               db_update=lambda: (True, ""), db_status=lambda: GOOD_DB)
    assert w.run_once() is False


def test_worker_never_needs_the_data_directory_or_master_key(live, tmp_path):
    """Der Worker arbeitet nur über HTTP: dieselben Schritte klappen, ohne dass er Pfade des Servers kennt."""
    make_system(live)
    enqueue_scan_run(live, "manual")
    import os
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert worker_for(live).run_once() is True
    finally:
        os.chdir(cwd)
    assert runs(live)[0].status == "success"


def test_a_rejected_result_reports_the_servers_reason_in_the_job_failure(live):
    make_sys = make_system(live)
    enqueue_scan_run(live, "manual")

    def bad_cvss(path):
        if "log4j" in str(path):
            return real_scan(path)
        return [{**real_scan(path)[0], "cvss_score": 11.0}]

    worker_for(live, scan_fn=bad_cvss).run_once()
    [run] = runs(live)
    assert run.status == "failed"
    assert "422" in run.error and "cvss_score" in run.error     # nicht nur „422 Unprocessable Entity“


def test_worker_scans_each_container_image_once_and_tags_findings_with_it(live):
    import json as _json
    from app.models import ImageSbom
    img = "sha256:" + "d" * 64
    containers = [{"id": "c1", "name": "a", "image": "nginx:1.27", "image_id": img}]
    sids = [make_system(live, n) for n in ("h1", "h2")]
    with live.session_factory() as s:
        from app.models import System
        for sid in sids:
            s.get(System, sid).inventory_json = _json.dumps({"containers": containers})
            s.add(ImageSbom(system_id=sid, image_id=img))
        s.commit()
    for sid in sids:   # jede SBOM gehört ihrem System; gleicher Inhalt wird trotzdem nur einmal gescannt
        p = live.settings.data_dir / "images" / str(sid) / ("d" * 64 + ".json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"bomFormat":"CycloneDX","marker":"image"}')
    scanned = []

    def scan(path):
        if "log4j" in str(path):
            return real_scan(path)
        text = Path(path).read_text()
        scanned.append("image" if "marker" in text else "host")
        return real_scan(path)[:1] if "marker" in text else []

    enqueue_scan_run(live, "manual")
    worker_for(live, scan_fn=scan).run_once()
    assert scanned.count("image") == 1 and scanned.count("host") == 1   # beide Host-SBOMs sind hier gleich („{}“)
    with live.session_factory() as s:
        rows = {(f.system_id, f.target) for f in s.scalars(select(Finding))}
    assert rows == {(sids[0], "image:nginx:1.27"), (sids[1], "image:nginx:1.27")}
    assert runs(live)[0].status == "success"


def test_client_waits_out_a_short_server_restart(monkeypatch):
    import urllib.error
    from app.worker import ServerClient
    calls = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"job": null}'

    def fake_urlopen(req, timeout):
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        return Resp()
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert ServerClient("http://x", "t", retry_wait=0).claim() is None and len(calls) == 3


def test_osv_runs_once_over_all_sboms_and_marks_the_source(live):
    import json as _json
    from app.models import ImageSbom, System
    img = "sha256:" + "e" * 64
    sid = make_system(live, "h1")
    with live.session_factory() as s:
        s.get(System, sid).inventory_json = _json.dumps({"containers": [{"name": "a", "image": "nginx:1.27", "image_id": img}]})
        s.add(ImageSbom(system_id=sid, image_id=img))
        s.commit()
    p = live.settings.data_dir / "images" / str(sid) / ("e" * 64 + ".json")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"bomFormat":"CycloneDX","marker":"image"}')
    calls = []

    def osv(paths):
        calls.append([Path(x).name for x in paths])
        assert all(str(x).endswith(".cdx.json") and Path(x).is_file() for x in paths)
        out = {}
        for x in paths:
            image = "marker" in Path(x).read_text()
            base = real_scan(x)[0]
            out[str(x)] = [{**base, "source": "osv"}, {**base, "cve_id": "CVE-2099-0001" if image else "CVE-2099-0002",
                                                      "source": "osv"}]
        return out

    client = ServerClient(live.base_url, live.worker_token)
    w = Worker(client, CANARY_DIR, scan_fn=lambda path: real_scan(path)[:1], db_update=lambda: (True, ""),
               db_status=lambda: GOOD_DB, osv_fn=osv, osv_status=lambda: {"ok": True, "age_hours": 1.0, "reason": ""})
    enqueue_scan_run(live, "manual")
    w.run_once()
    assert len(calls) == 1 and len(calls[0]) == 2   # ein Aufruf: Host und Image
    with live.session_factory() as s:
        got = {(f.target, f.cve_id, f.source) for f in s.scalars(select(Finding))}
        run = s.scalar(select(ScanRun))
    first = real_scan(None)[0]["cve_id"]
    assert got == {("host", first, "both"), ("host", "CVE-2099-0002", "osv"),
                   ("image:nginx:1.27", first, "both"), ("image:nginx:1.27", "CVE-2099-0001", "osv")}
    assert json.loads(run.db_status)["osv"]["ok"] is True and run.status == "success"
    assert "Second source (OSV-Scanner): ok" in live.notifier.sent[-1][1]


def test_osv_failure_keeps_grype_results_and_is_reported(live):
    make_system(live, "h1")

    def broken(paths):
        raise ScanError("osv-scanner exited with code 127")

    client = ServerClient(live.base_url, live.worker_token)
    w = Worker(client, CANARY_DIR, scan_fn=real_scan, db_update=lambda: (True, ""), db_status=lambda: GOOD_DB,
               osv_fn=broken)
    enqueue_scan_run(live, "manual")
    w.run_once()
    [run] = runs(live)
    assert run.status == "success" and json.loads(run.db_status)["osv"]["reason"].startswith("osv-scanner exited")
    assert "Second source (OSV-Scanner): ERROR" in live.notifier.sent[-1][1]
    with live.session_factory() as s:
        assert s.scalar(select(Finding)).source == "grype"


def test_osv_without_sboms_is_not_an_error(live):
    client = ServerClient(live.base_url, live.worker_token)
    w = Worker(client, CANARY_DIR, scan_fn=real_scan, db_update=lambda: (True, ""), db_status=lambda: GOOD_DB,
               osv_fn=lambda paths: (_ for _ in ()).throw(AssertionError("must not run")))
    enqueue_scan_run(live, "manual")
    w.run_once()
    assert json.loads(runs(live)[0].db_status)["osv"]["ok"] is True


def test_unchanged_sboms_reuse_results_from_the_same_database_only(live, tmp_path):
    make_system(live, "a")
    cache = tmp_path / "results"
    cache.mkdir()
    scanned = []

    def scan(path):
        if "log4j" in str(path):
            return real_scan(path)
        scanned.append(path.name)
        return []

    built = {"v": "2026-10-26T01:00:00Z"}
    def status():
        return {"ok": True, "age_hours": 1, "built": built["v"]}

    for _ in range(2):
        enqueue_scan_run(live, "manual")
        worker_for(live, scan_fn=scan, result_cache=cache, db_status=status).run_once()
    assert len(scanned) == 1   # zweiter Lauf: gleiche SBOM, gleiche Datenbank
    built["v"] = "2026-10-27T01:00:00Z"
    enqueue_scan_run(live, "manual")
    worker_for(live, scan_fn=scan, result_cache=cache, db_status=status).run_once()
    assert len(scanned) == 2   # neue Datenbank: neu gescannt
    assert all(r.status == "success" for r in runs(live))


def test_scans_run_in_parallel(live):
    import threading as _t

    for name in ("a", "b", "c"):
        sid = make_system(live, name)
        (live.settings.data_dir / "sboms" / f"{sid}.json").write_text(json.dumps({"host": name}))
    active, peak, lock = [0], [0], _t.Lock()

    def scan(path):
        if "log4j" in str(path):
            return real_scan(path)
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.2)
        with lock:
            active[0] -= 1
        return []

    enqueue_scan_run(live, "manual")
    worker_for(live, scan_fn=scan, parallel=3).run_once()
    assert peak[0] == 3 and runs(live)[0].status == "success"


def test_osv_runs_alongside_grype_and_reuses_unchanged_results(live, tmp_path):
    import threading as _t

    make_system(live, "a")
    osv_db = tmp_path / "osv" / "Ubuntu"
    osv_db.mkdir(parents=True)
    (osv_db / "all.zip").write_text("db")
    calls, overlap, grype_busy = [], [], _t.Event()

    def scan(path):
        if "log4j" in str(path):
            return real_scan(path)
        grype_busy.set()
        time.sleep(0.3)
        grype_busy.clear()
        return []

    def osv(paths):
        overlap.append(grype_busy.wait(1))   # läuft, während Grype noch scannt
        calls.append(len(paths))
        return {}

    cache = tmp_path / "results"
    cache.mkdir()
    kw = dict(scan_fn=scan, result_cache=cache, osv_cache_dir=tmp_path / "osv", osv_fn=osv,
              osv_status=lambda: {"ok": True, "age_hours": 1})
    for _ in range(2):
        enqueue_scan_run(live, "manual")
        worker_for(live, **kw).run_once()
    assert calls == [1] and overlap == [True]   # zweiter Lauf: gleiche SBOM, gleiche OSV-Datenbank
    enqueue_scan_run(live, "manual")
    worker_for(live, **{**kw, "osv_status": lambda: {"ok": True, "age_hours": 30}}).run_once()
    assert calls == [1, 1]   # Datenbank zu alt: OSV läuft (und lädt sie neu)
    assert all(r.status == "success" for r in runs(live))


def test_every_progress_step_the_worker_reports_is_stored(live):
    """Der Worker meldet Fortschritt nebenbei und verwirft Ablehnungen still: jeder Schritt muss angenommen werden."""
    make_system(live, "a")
    enqueue_scan_run(live, "manual")
    job = ServerClient(live.base_url, live.worker_token).claim()
    client = ServerClient(live.base_url, live.worker_token)
    for step, extra in (("database", {}), ("canary", {}), ("download", {}), ("scan", {"done": 3, "total": 9, "reused": 2}),
                        ("osv", {}), ("saving", {})):
        client.progress(job["id"], step=step, text=step, **extra)
        with live.session_factory() as s:
            stored = json.loads(s.scalar(select(ScanJob.progress).where(ScanJob.id == job["id"])))
        assert stored["step"] == step and all(stored[k] == v for k, v in extra.items())


def test_light_mode_skips_osv_and_reports_it_disabled(live):
    make_system(live, "h1")
    client = ServerClient(live.base_url, live.worker_token)
    w = Worker(client, CANARY_DIR, scan_fn=real_scan, db_update=lambda: (True, ""), db_status=lambda: GOOD_DB,
               osv_fn=lambda paths: (_ for _ in ()).throw(AssertionError("must not run")),
               osv_status=lambda: (_ for _ in ()).throw(AssertionError("must not read the OSV cache")),
               scanners="grype")
    enqueue_scan_run(live, "manual")
    w.run_once()
    [run] = runs(live)
    osv = json.loads(run.db_status)["osv"]
    assert osv["disabled"] is True and osv["ok"] is True and run.status == "success"
    assert "Second source (OSV-Scanner): off (light mode)" in live.notifier.sent[-1][1]


def test_scanners_setting_is_validated():
    from app.worker import scanners_from_env
    assert scanners_from_env({}) == "grype+osv"
    assert scanners_from_env({"LABLANTERN_SCANNERS": "grype"}) == "grype"
    with pytest.raises(SystemExit):
        scanners_from_env({"LABLANTERN_SCANNERS": "trivy"})
