from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.db import init_db, make_engine
from app.models import AuditLog, Finding, Snooze, System
from app.snooze import (MAX_SNOOZE_DAYS, apply_snoozes, create_snooze, end_reason, matches, target_key,
                        transfer_accepted_findings)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def s(session_factory):
    with session_factory() as session:
        session.add_all([System(id=1, name="host-a"), System(id=2, name="host-b")])
        session.commit()
        yield session


def finding(s, system_id=1, target="host", severity="mittel", kev=False, fixed="", cve="CVE-2026-1", comp="libx"):
    f = Finding(system_id=system_id, cve_id=cve, component=comp, severity=severity, kev=kev, fixed_version=fixed,
                target=target, status="open")
    s.add(f)
    s.flush()
    return f


def test_target_key_strips_tag_and_digest():
    assert target_key("host") == "host"
    assert target_key("image:nginx:1.25@sha256:" + "a" * 64) == target_key("image:docker.io/library/nginx:1.27")
    assert target_key("image:lscr.io/linuxserver/plex:latest") == "image:lscr.io/linuxserver/plex"
    assert target_key("image:nginx:1.25") != target_key("image:redis:7")


def test_occurrence_survives_tag_update(s):
    sn = create_snooze(s, finding(s, target="image:nginx:1.25@sha256:" + "b" * 64), "occurrence",
                       NOW + timedelta(days=30), "not reachable", "noah", NOW)
    assert matches(sn, finding(s, target="image:docker.io/library/nginx:1.27"))


def test_occurrence_not_other_host(s):
    sn = create_snooze(s, finding(s), "occurrence", NOW + timedelta(days=30), "reason", "noah", NOW)
    assert not matches(sn, finding(s, system_id=2))
    assert not matches(sn, finding(s, cve="CVE-2026-2"))


def test_everywhere_covers_new_host(s):
    sn = create_snooze(s, finding(s), "everywhere", NOW + timedelta(days=30), "reason", "noah", NOW)
    assert sn.system_id is None and matches(sn, finding(s, system_id=2, target="image:redis:7"))


def test_max_days_enforced(s):
    with pytest.raises(ValueError):
        create_snooze(s, finding(s), "occurrence", NOW + timedelta(days=MAX_SNOOZE_DAYS + 1), "reason", "noah", NOW)
    with pytest.raises(ValueError):
        create_snooze(s, finding(s), "occurrence", NOW - timedelta(days=1), "reason", "noah", NOW)


def test_end_reasons(s):
    f = finding(s)
    sn = create_snooze(s, f, "occurrence", NOW + timedelta(days=30), "reason", "noah", NOW)
    assert end_reason(sn, f, NOW) is None
    assert end_reason(sn, f, NOW + timedelta(days=31)) == "expired"
    f.kev = True
    assert end_reason(sn, f, NOW) == "now on the KEV list"
    f.kev, f.severity = False, "hoch"
    assert end_reason(sn, f, NOW) == "rating went up to high"
    f.severity, f.fixed_version = "info", "1.2"
    assert end_reason(sn, f, NOW) == "a fix is now available"


def test_lower_rating_does_not_end(s):
    f = finding(s, severity="hoch", fixed="1.2")
    sn = create_snooze(s, f, "occurrence", NOW + timedelta(days=30), "reason", "noah", NOW)
    f.severity = "mittel"
    assert end_reason(sn, f, NOW) is None


def test_apply_snoozes_reopens_and_reports(s):
    f = finding(s)
    other = finding(s, system_id=2)
    create_snooze(s, f, "everywhere", NOW + timedelta(days=30), "vendor says not affected", "noah", NOW)
    assert apply_snoozes(s, NOW) == []
    assert f.status == other.status == "accepted"
    other.kev = True   # KEV gilt für die CVE überall: der Snooze endet für alle Systeme
    ended = apply_snoozes(s, NOW)
    assert ended == [{"cve_id": "CVE-2026-1", "component": "libx", "system_name": "all systems",
                      "reason": "vendor says not affected", "end_reason": "now on the KEV list"}]
    assert f.status == other.status == "open"
    assert s.scalar(select(AuditLog).where(AuditLog.action == "snooze.ended")) is not None
    assert apply_snoozes(s, NOW) == []   # beendet bleibt beendet


def test_apply_snoozes_expires(s):
    f = finding(s)
    create_snooze(s, f, "occurrence", NOW + timedelta(days=1), "reason", "noah", NOW)
    apply_snoozes(s, NOW)
    [ended] = apply_snoozes(s, NOW + timedelta(days=2))
    assert ended["end_reason"] == "expired" and ended["system_name"] == "host-a" and f.status == "open"


def test_migrate_accepted_findings(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite")
    init_db(engine)
    from sqlalchemy.orm import sessionmaker
    factory = sessionmaker(engine)
    until = datetime.now(timezone.utc) + timedelta(days=20)
    with factory() as s:
        s.add(System(id=1, name="host-a"))
        s.commit()
        s.add(Finding(system_id=1, cve_id="CVE-2026-9", component="liby", severity="hoch", target="image:nginx:1.25",
                      status="accepted", accepted_reason="old accept", accepted_until=until))
        s.commit()
    init_db(engine)   # Neustart: überträgt einmal
    init_db(engine)
    with factory() as s:
        [sn] = s.scalars(select(Snooze)).all()
        assert (sn.scope, sn.reason, sn.target_key, sn.baseline_severity) == \
            ("occurrence", "old accept", "image:docker.io/library/nginx", "hoch")
        assert abs((sn.until - until).total_seconds()) < 1
    assert transfer_accepted_findings is not None


# ---------- im Lauf, im Bericht, in der API (Task 2.2) ----------

from test_scan_flow import Notes, make_system, raw, run_once  # noqa: E402


def _snooze_api(client, h, finding_id, days=30, scope="occurrence", reason="isolated VLAN, patch planned"):
    until = (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()
    return client.post(f"/api/findings/{finding_id}/snooze", headers=h,
                       json={"scope": scope, "until": until, "reason": reason})


def _first_finding(ctx):
    with ctx.session_factory() as s:
        return s.scalar(select(Finding))


def test_snoozed_not_in_alert_rating_but_in_report(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    sid = make_system(ctx)
    critical = raw(kev=True, cvss=10, cve="CVE-2021-44228")
    run_once(ctx, [(sid, [critical], None)])
    assert ctx.notifier.sent[-1][0].startswith("[ALERT]")
    assert _snooze_api(client, h, _first_finding(ctx).id).status_code == 200
    run_once(ctx, [(sid, [critical], None)])
    title, body = ctx.notifier.sent[-1]
    assert title.startswith("[OK]")
    assert "Snoozed (1)" in body and "isolated VLAN, patch planned" in body
    assert _first_finding(ctx).status == "accepted"


def test_snooze_ended_in_report(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    sid = make_system(ctx)
    run_once(ctx, [(sid, [raw(cvss=5.0, label="Medium")], None)])
    assert _snooze_api(client, h, _first_finding(ctx).id).status_code == 200
    run_once(ctx, [(sid, [raw(cvss=5.0, label="Medium", kev=True)], None)])
    body = ctx.notifier.sent[-1][1]
    assert "snooze ended: now on the KEV list" in body and _first_finding(ctx).status == "open"


def test_everywhere_snooze_hides_new_host_finding_from_new_findings(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    a = make_system(ctx, "host-a")
    run_once(ctx, [(a, [raw()], None)])
    assert _snooze_api(client, h, _first_finding(ctx).id, scope="everywhere").status_code == 200
    b = make_system(ctx, "host-b")
    run_once(ctx, [(a, [raw()], None), (b, [raw()], None)])
    body = ctx.notifier.sent[-1][1]
    assert "New findings" not in body and "Snoozed (2)" in body


def test_snooze_limits_and_rights(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    run_once(ctx, [(make_system(ctx), [raw()], None)])
    fid = _first_finding(ctx).id
    assert _snooze_api(client, h, fid, days=181).status_code == 422
    assert _snooze_api(client, h, fid, reason="x").status_code == 422
    assert _snooze_api(client, h, 99999).status_code == 404
    assert _snooze_api(env.new_client(), {}, fid).status_code in (401, 403)
    assert client.post(f"/api/findings/{fid}/accept", headers=h, json={"reason": "old", "days": 5}).status_code == 404


def test_list_and_remove_snooze(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    run_once(ctx, [(make_system(ctx), [raw()], None)])
    assert _snooze_api(client, h, _first_finding(ctx).id).status_code == 200
    [sn] = client.get("/api/snoozes").json()["active"]
    assert sn["system_name"] == "host-c" and sn["scope"] == "occurrence"
    assert client.delete(f"/api/snoozes/{sn['id']}", headers=h).status_code == 200
    assert client.get("/api/snoozes").json()["active"] == []
    assert _first_finding(ctx).status == "open"
    with ctx.session_factory() as s:
        assert {a.action for a in s.scalars(select(AuditLog))} >= {"finding.snoozed", "snooze.removed"}


def test_overview_counts_snoozed(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    run_once(ctx, [(make_system(ctx), [raw(kev=True, cvss=10)], None)])
    assert _snooze_api(client, h, _first_finding(ctx).id).status_code == 200
    ov = client.get("/api/overview").json()
    assert ov["snoozed_count"] == 1 and ov["findings"]["kritisch"] == 0
    assert ov["coverage"][0]["snoozed"] == 1


def test_configdoc_roundtrip_snoozes(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    run_once(ctx, [(make_system(ctx), [raw(), raw(cve="CVE-2026-7777")], None)])
    assert _snooze_api(client, h, _first_finding(ctx).id).status_code == 200
    doc = client.get("/api/settings/config").json()
    [sn] = doc["snoozes"]
    assert sn["system"] == "host-c" and sn["cve_id"] == "CVE-2024-1234" and sn["id"]
    until = (datetime.now(timezone.utc) + timedelta(days=10)).date().isoformat()
    doc["snoozes"] = [{"scope": "everywhere", "cve_id": "CVE-2026-7777", "component": "libtest", "system": None,
                       "target": "host", "until": until, "reason": "imported from the backup"}]
    r = client.put("/api/settings/config", headers=h, json=doc).json()
    assert r["ok"], r
    active = client.get("/api/snoozes").json()["active"]
    assert [(x["cve_id"], x["scope"]) for x in active] == [("CVE-2026-7777", "everywhere")]


# ---------- Ausnahmen von der Abdeckung (Task 2.3) ----------

def _exclude(client, h, sid, days=30, reason="stopped test VM"):
    until = (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()
    return client.post("/api/coverage/exclusions", headers=h,
                       json={"subject": f"system:{sid}", "until": until, "reason": reason})


def test_excluded_row_counted_separately(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    a = make_system(ctx, "host-a")
    b = make_system(ctx, "test-vm", sbom=False)   # ohne SBOM: Fehler in der Matrix
    run_once(ctx, [(a, [], None), (b, [], "no SBOM")])
    before = client.get("/api/overview").json()["coverage_percent"]
    assert _exclude(client, h, b).status_code == 200
    ov = client.get("/api/overview").json()
    row = next(r for r in ov["coverage"] if r["system_name"] == "test-vm")
    assert row["excluded"]["reason"] == "stopped test VM"
    assert {c["status"] for c in row["checks"].values()} == {"excluded"}
    assert ov["coverage_percent"] > before and ov["excluded_count"] == 1
    assert not any("test-vm" in st.get("detail", "") for st in ov["next_steps"])
    with ctx.session_factory() as s:
        assert s.scalar(select(AuditLog).where(AuditLog.action == "exclusion.created")) is not None


def test_exclusion_limits_and_removal(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    sid = make_system(ctx)
    assert _exclude(client, h, sid, days=181).status_code == 422
    assert _exclude(client, h, sid, reason="x").status_code == 422
    assert client.post("/api/coverage/exclusions", headers=h,
                       json={"subject": "system:9999", "until": "2026-12-01", "reason": "gone"}).status_code == 422
    r = _exclude(client, h, sid)
    assert r.status_code == 200
    assert _exclude(client, h, sid).status_code == 409   # schon ausgenommen
    assert client.delete(f"/api/coverage/exclusions/{r.json()['id']}", headers=h).status_code == 200
    row = client.get("/api/overview").json()["coverage"][0]
    assert row.get("excluded") is None


def test_exclusion_expires(session_factory):
    from app.models import CoverageExclusion
    from app.snooze import active_exclusions, create_exclusion
    with session_factory() as s:
        s.add(System(id=1, name="host-a"))
        s.commit()
        create_exclusion(s, "system:1", NOW + timedelta(days=2), "rebuild", "noah", NOW)
        assert set(active_exclusions(s, NOW)) == {"system:1"}
        assert active_exclusions(s, NOW + timedelta(days=3)) == {}
        apply_snoozes(s, NOW + timedelta(days=3))   # beendet auch abgelaufene Ausnahmen (mit Audit)
        ex = s.scalar(select(CoverageExclusion))
        assert ex.end_reason == "expired" and ex.ended_at is not None


def test_configdoc_roundtrip_exclusions(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    make_system(ctx, "host-a")
    sid = make_system(ctx, "test-vm")
    assert _exclude(client, h, sid).status_code == 200
    doc = client.get("/api/settings/config").json()
    [ex] = doc["coverage_exclusions"]
    assert ex["system"] == "test-vm" and ex["reason"] == "stopped test VM"
    until = (datetime.now(timezone.utc) + timedelta(days=9)).date().isoformat()
    doc["coverage_exclusions"] = [{"system": "host-a", "until": until, "reason": "being rebuilt"}]
    r = client.put("/api/settings/config", headers=h, json=doc).json()
    assert r["ok"], r
    rows = {x["system_name"]: x.get("excluded") for x in client.get("/api/overview").json()["coverage"]}
    assert rows["test-vm"] is None and rows["host-a"]["reason"] == "being rebuilt"
