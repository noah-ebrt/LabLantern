import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import Finding, ScanJob, ScanRun, System, SystemScanResult
from app.snooze import apply_snoozes, create_snooze
from app.scanrun import (
    JOB_TIMEOUT,
    JobStateError,
    ScanAlreadyActive,
    WorkerResultIn,
    claim_job,
    enqueue_scan_run,
    expire_stale_jobs,
    process_scan_result,
)


class Notes:
    """Aufzeichnender Benachrichtigungskanal statt Netzwerk."""

    def __init__(self, ok=True):
        self.sent = []
        self.html = []
        self.kinds = []
        self.ok = ok

    def __call__(self, title, body, html=None, kind="report"):
        self.sent.append((title, body))
        self.html.append(html)
        self.kinds.append(kind)
        return (self.ok, None if self.ok else "kaputt")


@pytest.fixture
def ctx(env):
    c = env.app.state.ctx
    c.notifier = Notes()
    return c


def make_system(ctx, name="host-c", status="active", sbom=True):
    with ctx.session_factory() as s:
        sys = System(name=name, status=status, last_seen=datetime.now(timezone.utc),
                     sbom_updated_at=datetime.now(timezone.utc) - timedelta(minutes=1) if sbom else None)
        s.add(sys)
        s.commit()
        sid = sys.id
    if sbom:
        d = ctx.settings.data_dir / "sboms"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{sid}.json").write_text("{}")
    return sid


def raw(cve="CVE-2024-1234", component="libtest", installed="1.0", fixed="1.1", cvss=7.8,
        kev=False, has_fix=True, label="High"):
    return {"cve_id": cve, "title": "t", "component": component, "installed_version": installed,
            "fixed_version": fixed, "has_fix": has_fix, "cvss_score": cvss, "severity_label": label,
            "epss_score": 0.1, "kev": kev, "source": "grype", "purl": ""}


def result(systems, canary_ok=True, db_ok=True, osv=None, image_errors=None):
    return WorkerResultIn.model_validate({
        "canary": {"ok": canary_ok, "message": "ok" if canary_ok else "Kanarie rot"},
        "grype_db": {"ok": db_ok, "age_hours": 3.0 if db_ok else 50.0, "built": "x",
                     "reason": "" if db_ok else "Grype-Datenbank 50 h alt"},
        "osv": osv,
        "systems": [{"system_id": sid, "ok": err is None, "error": err or "", "findings": f,
                     "image_errors": image_errors or {}} for sid, f, err in systems],
    })


def run_once(ctx, systems, **kw):
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    return job, process_scan_result(ctx, job["id"], result(systems, **kw))


def findings(ctx, status=None):
    with ctx.session_factory() as s:
        q = select(Finding)
        if status:
            q = q.where(Finding.status == status)
        return list(s.scalars(q))


# ---------- einreihen und abholen ----------

def test_enqueue_creates_queued_run_and_pending_job_for_active_systems_only(ctx):
    a = make_system(ctx, "host-c")
    make_system(ctx, "wartet", status="pending")
    make_system(ctx, "weg", status="revoked")
    run = enqueue_scan_run(ctx, "scheduled")
    assert run.status == "queued" and run.trigger == "scheduled"
    with ctx.session_factory() as s:
        job = s.scalar(select(ScanJob))
    assert job.status == "pending" and job.run_id == run.id
    assert json.loads(job.payload)["systems"] == [{"id": a, "name": "host-c", "sbom": True, "images": []}]


def test_enqueue_flags_systems_without_sbom(ctx):
    a = make_system(ctx, "host-c", sbom=False)
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    assert job["systems"] == [{"id": a, "name": "host-c", "sbom": False, "images": []}]


def test_second_enqueue_while_a_run_is_active_is_refused(ctx):
    make_system(ctx)
    enqueue_scan_run(ctx, "manual")
    with pytest.raises(ScanAlreadyActive):
        enqueue_scan_run(ctx, "manual")


def test_claim_marks_job_and_run_running_and_is_exclusive(ctx):
    make_system(ctx)
    run = enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    assert job["run_id"] == run.id
    assert claim_job(ctx) is None
    with ctx.session_factory() as s:
        assert s.get(ScanRun, run.id).status == "running"
        assert s.scalar(select(ScanJob)).status == "running"


def test_claim_without_pending_job_returns_none(ctx):
    assert claim_job(ctx) is None


# ---------- Ergebnis verarbeiten ----------

def test_result_creates_findings_with_server_side_classification(ctx):
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [raw(kev=True, cvss=10.0, cve="CVE-2021-44228"),
                                    raw(cve="CVE-2024-1", cvss=5.0),
                                    raw(cve="CVE-2024-2", has_fix=False, fixed="")], None)])
    assert run.status == "success"
    sev = {f.cve_id: f.severity for f in findings(ctx)}
    assert sev == {"CVE-2021-44228": "kritisch", "CVE-2024-1": "mittel", "CVE-2024-2": "info"}
    assert json.loads(run.summary_counts) == {"kritisch": 1, "hoch": 0, "mittel": 1, "info": 1}
    with ctx.session_factory() as s:
        assert s.scalar(select(SystemScanResult)).status == "ok"


def test_second_run_with_same_findings_creates_no_duplicates_and_reports_nothing_new(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw()], None)])
    ctx.notifier.sent.clear()
    run_once(ctx, [(sid, [raw()], None)])
    assert len(findings(ctx)) == 1
    assert "New findings" not in ctx.notifier.sent[0][1]


def test_finding_that_disappears_is_resolved(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw()], None)])
    run_once(ctx, [(sid, [], None)])
    [f] = findings(ctx)
    assert f.status == "resolved" and f.resolved_at is not None


def test_findings_of_an_image_that_was_not_scanned_stay_open(ctx):
    """Run 13 auf host-a: Image-SBOMs mit HTTP 404, 15.000 Funde „behoben“ und im nächsten Lauf alle wieder „neu“."""
    sid = make_system(ctx)
    image = {"id": "sha256:aa", "ref": "nginx:latest"}

    def run(items, sbom=True, errors=None):
        enqueue_scan_run(ctx, "manual")
        with ctx.session_factory() as s:
            job = s.scalar(select(ScanJob).where(ScanJob.status == "pending"))
            job.payload = json.dumps({"systems": [{"id": sid, "name": "host-c", "sbom": True,
                                                   "images": [{**image, "sbom": sbom}]}]})
            s.commit()
        job = claim_job(ctx)
        process_scan_result(ctx, job["id"], result([(sid, [{**f, "target": "image:nginx:latest"} for f in items],
                                                     None)], image_errors=errors))

    run([raw()])
    run([], errors={"sha256:aa": "HTTP 404"})        # SBOM nicht abrufbar
    run([], errors={"ref:nginx:latest": "grype"})    # Scan des Images gescheitert
    run([], sbom=False)                              # SBOM noch unterwegs
    assert [f.status for f in findings(ctx)] == ["open"]
    run([])
    assert [f.status for f in findings(ctx)] == ["resolved"]


def test_light_mode_closes_osv_only_findings_quietly(ctx):
    sid = make_system(ctx)
    osv_only = {**raw(cve="CVE-2024-9999"), "source": "osv"}
    run_once(ctx, [(sid, [{**raw(), "source": "both"}, osv_only], None)], osv={"ok": True})
    _, run = run_once(ctx, [(sid, [raw()], None)], osv={"ok": True, "disabled": True, "reason": "light mode"})
    by_cve = {f.cve_id: f for f in findings(ctx)}
    assert by_cve["CVE-2024-9999"].status == "resolved" and by_cve["CVE-2024-1234"].source == "grype"
    body = ctx.notifier.sent[-1][1]
    assert "Resolved since last run" not in body
    assert "1 OSV-only finding(s) closed: OSV is switched off (light mode)" in body
    assert "Second source (OSV-Scanner): off (light mode)" in body
    assert run.status == "success"
    # wieder eingeschaltet: der Fund kommt als neu zurück, das ist richtig, er wurde ja nicht geprüft
    run_once(ctx, [(sid, [raw(), osv_only], None)], osv={"ok": True})
    assert "New findings" in ctx.notifier.sent[-1][1]


def test_osv_only_findings_stay_open_while_osv_fails(ctx):
    sid = make_system(ctx)
    osv_only = {**raw(cve="CVE-2024-9999"), "source": "osv"}
    run_once(ctx, [(sid, [raw(), osv_only], None)], osv={"ok": True})
    ctx.notifier.sent.clear()
    run_once(ctx, [(sid, [raw()], None)], osv={"ok": False, "reason": "OSV database could not be loaded"})
    assert {f.cve_id: f.status for f in findings(ctx)} == {"CVE-2024-1234": "open", "CVE-2024-9999": "open"}
    run_once(ctx, [(sid, [raw(), osv_only], None)], osv={"ok": True})
    assert len(findings(ctx)) == 2 and "New findings" not in ctx.notifier.sent[-1][1]
    run_once(ctx, [(sid, [raw()], None)], osv={"ok": True})
    assert {f.cve_id: f.status for f in findings(ctx)}["CVE-2024-9999"] == "resolved"


def test_accepted_finding_that_disappears_is_resolved_too(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw()], None)])
    with ctx.session_factory() as s:
        f = s.scalar(select(Finding))
        create_snooze(s, f, "occurrence", datetime.now(timezone.utc) + timedelta(days=5), "patch planned", "noah",
                      datetime.now(timezone.utc))
        apply_snoozes(s, datetime.now(timezone.utc))
        s.commit()
    run_once(ctx, [(sid, [], None)])
    assert findings(ctx)[0].status == "resolved"


def test_accepted_finding_reappears_after_expiry(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw()], None)])
    with ctx.session_factory() as s:
        f = s.scalar(select(Finding))
        sn = create_snooze(s, f, "occurrence", datetime.now(timezone.utc) + timedelta(days=1), "patch planned", "noah",
                           datetime.now(timezone.utc))
        apply_snoozes(s, datetime.now(timezone.utc))
        sn.until = datetime.now(timezone.utc) - timedelta(days=1)   # inzwischen abgelaufen
        s.commit()
    run_once(ctx, [(sid, [raw()], None)])
    assert findings(ctx)[0].status == "open"


def test_still_valid_acceptance_stays_accepted(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw()], None)])
    with ctx.session_factory() as s:
        f = s.scalar(select(Finding))
        create_snooze(s, f, "occurrence", datetime.now(timezone.utc) + timedelta(days=5), "patch planned", "noah",
                      datetime.now(timezone.utc))
        apply_snoozes(s, datetime.now(timezone.utc))
        s.commit()
    run_once(ctx, [(sid, [raw()], None)])
    assert findings(ctx)[0].status == "accepted"


def test_same_cve_in_two_components_is_two_findings(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw(component="a"), raw(component="b")], None)])
    assert len(findings(ctx)) == 2


def test_scan_error_of_one_system_is_visible_and_keeps_its_findings(ctx):
    a, b = make_system(ctx, "a"), make_system(ctx, "b")
    run_once(ctx, [(a, [raw()], None), (b, [raw(cve="CVE-2024-9")], None)])
    _, run = run_once(ctx, [(a, [], "grype exited with code 1"), (b, [], None)])
    assert run.status == "partial"
    with ctx.session_factory() as s:
        res = {r.system_id: r.status for r in s.scalars(select(SystemScanResult).where(SystemScanResult.run_id == run.id))}
    assert res == {a: "fehler", b: "ok"}
    by_sys = {(f.system_id, f.cve_id): f.status for f in findings(ctx)}
    assert by_sys[(a, "CVE-2024-1234")] == "open"          # unverändert, nicht still „behoben“
    assert by_sys[(b, "CVE-2024-9")] == "resolved"
    assert "grype exited" in ctx.notifier.sent[-1][1]
    assert ctx.notifier.sent[-1][0].startswith("[ERROR]")


def test_system_without_sbom_is_an_error_not_a_clean_bill(ctx):
    sid = make_system(ctx, sbom=False)
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    run = process_scan_result(ctx, job["id"], result([]))
    assert run.status == "partial"
    with ctx.session_factory() as s:
        r = s.scalar(select(SystemScanResult))
    assert r.system_id == sid and r.status == "fehler" and "SBOM" in r.error


def test_system_missing_from_the_worker_result_is_an_error(ctx):
    sid = make_system(ctx)
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    run = process_scan_result(ctx, job["id"], result([]))
    assert run.status == "partial"
    with ctx.session_factory() as s:
        assert s.scalar(select(SystemScanResult)).status == "fehler"


def test_failed_canary_invalidates_the_run_and_raises_immediate_alarm(ctx):
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw()], None)])
    _, run = run_once(ctx, [(sid, [], None)], canary_ok=False)
    assert run.status == "failed" and run.canary_status == "fehler"
    assert findings(ctx)[0].status == "open"                # Ergebnisse eines ungültigen Laufs zählen nicht
    title, body = ctx.notifier.sent[-1]
    assert title.startswith("[IMMEDIATE ALERT]") and "Kanarie rot" in body


def test_stale_scanner_database_invalidates_the_run(ctx):
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [raw()], None)], db_ok=False)
    assert run.status == "failed" and "50 h" in run.error
    assert findings(ctx) == []
    assert ctx.notifier.sent[-1][0].startswith("[IMMEDIATE ALERT]")


def test_result_for_unknown_system_is_rejected(ctx):
    make_system(ctx)
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    with pytest.raises(ValueError, match="unknown"):
        process_scan_result(ctx, job["id"], result([(999, [], None)]))


def test_result_is_accepted_only_once_and_only_for_running_jobs(ctx):
    sid = make_system(ctx)
    job, _ = run_once(ctx, [(sid, [], None)])
    with pytest.raises(JobStateError):
        process_scan_result(ctx, job["id"], result([(sid, [], None)]))
    with pytest.raises(JobStateError):
        process_scan_result(ctx, 12345, result([]))


def test_report_is_sent_and_status_recorded(ctx):
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [raw(kev=True, cvss=10, cve="CVE-2021-44228")], None)])
    title, body = ctx.notifier.sent[-1]
    assert title.startswith("[ALERT]") and "CVE-2021-44228" in body and "host-c" in body
    assert run.notify_status == "sent"


def test_failed_delivery_is_recorded_not_swallowed(env):
    ctx = env.app.state.ctx
    ctx.notifier = Notes(ok=False)
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [], None)])
    assert run.notify_status.startswith("failed")


def test_no_channel_configured_is_recorded(env):
    ctx = env.app.state.ctx
    ctx.notifier = lambda t, b, h=None, kind="report": (False, "kein Kanal")
    sid = make_system(ctx)
    _, run = run_once(ctx, [(sid, [], None)])
    assert "kein Kanal" in run.notify_status


# ---------- Zeitüberschreitung ----------

def test_running_job_without_result_is_failed_with_alarm(ctx, env):
    make_system(ctx)
    run = enqueue_scan_run(ctx, "manual")
    claim_job(ctx)
    env.clock.advance(JOB_TIMEOUT + 60)
    expire_stale_jobs(ctx)
    with ctx.session_factory() as s:
        assert s.get(ScanRun, run.id).status == "failed"
        assert s.scalar(select(ScanJob)).status == "failed"
    assert ctx.notifier.sent[-1][0].startswith("[IMMEDIATE ALERT]")


def test_pending_job_nobody_claims_is_failed_too(ctx, env):
    make_system(ctx)
    run = enqueue_scan_run(ctx, "manual")
    env.clock.advance(JOB_TIMEOUT + 60)
    expire_stale_jobs(ctx)
    with ctx.session_factory() as s:
        assert s.get(ScanRun, run.id).status == "failed"
    assert "worker" in ctx.notifier.sent[-1][1]


def test_fresh_jobs_are_left_alone(ctx, env):
    make_system(ctx)
    enqueue_scan_run(ctx, "manual")
    claim_job(ctx)
    env.clock.advance(5 * 60)
    expire_stale_jobs(ctx)
    assert ctx.notifier.sent == []


def test_a_new_run_can_start_after_the_previous_one_expired(ctx, env):
    make_system(ctx)
    enqueue_scan_run(ctx, "manual")
    env.clock.advance(JOB_TIMEOUT + 60)
    expire_stale_jobs(ctx)
    assert enqueue_scan_run(ctx, "manual").status == "queued"


def test_a_real_world_sized_result_is_accepted_and_processed_in_reasonable_time(ctx):
    """Ein Ubuntu-Host liefert rund 34.000 Treffer (fast alle ohne Fix). Das darf weder an Limits scheitern
    noch quadratisch langsam werden."""
    import time
    sid = make_system(ctx)
    many = [raw(cve=f"CVE-2024-{i:06d}", component=f"pkg{i % 700}", has_fix=(i % 9 == 0), fixed="1.1" if i % 9 == 0 else "")
            for i in range(35000)]
    t0 = time.time()
    _, run = run_once(ctx, [(sid, many, None)])
    assert run.status == "success"
    assert len(findings(ctx)) == 35000
    assert time.time() - t0 < 60


def test_report_stays_short_even_with_thousands_of_new_findings_and_leads_with_the_dangerous_ones(ctx):
    """Kanäle wie ntfy oder Telegram lehnen lange Nachrichten ab. Die gefährlichsten Funde stehen zuerst,
    der Rest wird gezählt, nicht aufgelistet."""
    sid = make_system(ctx)
    items = [raw(cve=f"CVE-2024-{i:05d}", component=f"p{i}", has_fix=False, fixed="") for i in range(3000)]     # info
    items += [raw(cve=f"CVE-2025-{i:05d}", component=f"m{i}", cvss=5.0) for i in range(500)]                    # mittel
    items += [raw(cve="CVE-2021-44228", component="log4j", kev=True, cvss=10.0)]                                # kritisch
    items += [raw(cve=f"CVE-2026-{i:05d}", component=f"h{i}", cvss=9.0) for i in range(40)]                     # hoch
    run_once(ctx, [(sid, items, None)])
    title, body = ctx.notifier.sent[-1]
    assert len(body) < 6000, len(body)
    assert body.index("CVE-2021-44228") < body.index("CVE-2026-")          # KEV/kritisch vor hoch
    assert "CVE-2024-" not in body and "CVE-2025-" not in body              # mittel/info werden nur gezählt
    assert "and 16 more" in body                                         # 1 kritischer + 40 hohe = 41, 25 gezeigt
    assert "critical 1" in body and "high 40" in body and "medium 500" in body and "info 3000" in body


def test_simultaneous_agent_reports_queue_exactly_one_job(ctx, monkeypatch):
    """Nach „Scan now“ melden alle Agenten fast gleichzeitig; jeder Bericht prüft, ob gescannt werden kann."""
    import threading

    from sqlalchemy import func

    from app import scanrun

    for name in ("a", "b", "c", "d"):
        make_system(ctx, name)
    scanrun.request_scan_run(ctx, "manual")
    monkeypatch.setattr(scanrun, "COLLECT_TIMEOUT", -1)   # Sammeln vorbei: jeder Aufruf darf einreihen
    gate = threading.Barrier(4)

    def report():
        gate.wait()
        scanrun.advance_collecting_runs(ctx)

    threads = [threading.Thread(target=report) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    with ctx.session_factory() as s:
        assert s.scalar(select(func.count(ScanJob.id))) == 1
        assert s.scalar(select(ScanRun.status)) == "queued"


def test_a_duplicate_job_of_a_run_is_dropped_not_scanned_twice(ctx):
    from app.scanrun import claim_job, enqueue_scan_run

    make_system(ctx, "a")
    enqueue_scan_run(ctx, "manual")
    with ctx.session_factory() as s:
        run_id = s.scalar(select(ScanRun.id))
        first = s.scalar(select(ScanJob))
        first.status = "running"
        s.add(ScanJob(target_type="full_scan", run_id=run_id, status="pending", payload="{}"))
        s.commit()
    assert claim_job(ctx) is None
    with ctx.session_factory() as s:
        assert [j.status for j in s.scalars(select(ScanJob).order_by(ScanJob.id))] == ["running", "failed"]
