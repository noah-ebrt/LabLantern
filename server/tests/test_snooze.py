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
