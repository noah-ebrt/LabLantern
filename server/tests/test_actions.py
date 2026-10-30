"""„What to do“ auf der Übersicht: jeder Grund für Rot/Gelb wird ein konkreter Schritt."""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.actions import next_steps
from app.models import EarlyWarning, Finding, System
from tests.test_scan_flow import ctx, make_system  # noqa: F401 (Fixture)

NOW = datetime(2026, 10, 26, 16, 0, tzinfo=timezone.utc)
RUN = SimpleNamespace(id=17, status="success", canary_status="ok", finished_at=NOW - timedelta(hours=3))
COV = {"systems": []}


def finding(sid, component, target="host", severity="kritisch", fix="", kev=False):
    return Finding(system_id=sid, cve_id="CVE-2026-1", title="t", severity=severity, component=component,
                   installed_version="1", fixed_version=fix, source="grype", target=target, status="open", kev=kev)


def test_critical_findings_become_steps_per_host_and_image_kev_first(ctx):
    sid = make_system(ctx, "host-b")
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps({"os_id": "ubuntu", "kernel": "6.8.0-138-generic", "containers": [
            {"name": "speed", "image": "openspeedtest/latest", "repo_digests": ["x@sha256:1"],
             "labels": {"com.docker.compose.project.working_dir": "/home/user/openspeedtest",
                        "com.docker.compose.project": "openspeedtest", "com.docker.compose.service": "speed"}},
            {"name": "gl", "image": "gitlab/gitlab-ce:19.5.1-ce.0", "repo_digests": ["x@sha256:2"],
             "labels": {"com.docker.compose.project.working_dir": "/data/compose/2", "com.docker.compose.project": "gitlab-light"}},
            {"name": "hub", "image": "traininghub:264211da", "repo_digests": []}]})
        s.add_all([finding(sid, "linux-modules-6.8.0-136-generic", kev=True),
                   finding(sid, "linux-hwe-6.8-tools-6.8.0-136", kev=True),
                   *[finding(sid, "libcurl", target="image:openspeedtest/latest", fix="8.1") for _ in range(3)],
                   finding(sid, "ruby", target="image:gitlab/gitlab-ce:19.5.1-ce.0", fix="3.4"),
                   finding(sid, "node", target="image:traininghub:264211da")])
        s.commit()
        steps = next_steps(s, {"kritisch": 7, "hoch": 0}, COV, RUN, NOW)
    titles = [st["title"] for st in steps]
    assert titles[0] == "host-b · host packages"   # KEV zuerst, obwohl das Image mehr Funde hat
    host, speed = steps[0], steps[1]
    assert "2 actively exploited (CISA KEV), 0 with a fix" in host["detail"]
    assert "2 of these are in 2 packages of kernel 6.8.0-136, which no longer runs" in host["detail"]
    assert host["command"] == "sudo apt-get purge $(dpkg-query -W -f='${Package}\\n' '*6.8.0-136*')"
    assert host["link"] == {"path": "/funde", "query": {"severity": "kritisch", "system_id": str(sid), "q": "host"}}
    assert speed["command"] == "docker compose pull speed && docker compose up -d speed"   # ohne Pfad der Installation
    assert "/home/user" not in json.dumps(steps) and "Compose project openspeedtest" in speed["detail"]
    gitlab = next(st for st in steps if "gitlab" in st["title"])
    assert gitlab["command"] == "" and "Portainer, Stacks → gitlab-light → Editor, change the tag" in gitlab["detail"]
    hub = next(st for st in steps if "traininghub" in st["title"])
    assert "Built locally" in hub["detail"]


def test_run_problems_and_affected_early_warnings_are_red(ctx):
    sid = make_system(ctx, "raspberrypi")
    with ctx.session_factory() as s:
        s.add(EarlyWarning(item_key="k", feed="f", title="Tailworm", status="betroffen", severity="hoch",
                           affected=json.dumps([{"system": "raspberrypi", "system_id": sid}]), created_at=NOW))
        s.commit()
        bad = SimpleNamespace(id=18, status="failed", canary_status="failed", finished_at=NOW - timedelta(hours=50))
        cov = {"systems": [{"system_id": sid, "system_name": "raspberrypi", "checks": {
            "images": {"status": "fehler", "detail": "worker timeout"}, "reboot": {"status": "fund", "detail": ""}}}]}
        steps = next_steps(s, {"kritisch": 0, "hoch": 0}, cov, bad, NOW)
    got = [(st["level"], st["title"]) for st in steps]
    assert got[:5] == [("rot", "Run #18 failed"), ("rot", "Scanner self-test failed"), ("rot", "Results are out of date"),
                       ("rot", "Container images could not be checked"), ("rot", "1 early warning affects your systems")]
    assert ("gelb", "Reboot raspberrypi") in got
    assert next_steps(s, {}, COV, None, NOW)[0]["action"] == "scan"


def test_done_steps_stay_hidden_until_the_next_run(ctx):
    from app.actions import apply_done, mark_done

    steps = [{"title": "mini · host packages", "level": "rot"}, {"title": "22 high findings, 20 with a fix", "level": "gelb"}]
    with ctx.session_factory() as s:
        mark_done(s, RUN, "## high findings, ## with a fix".replace("##", "#"), True)
        s.commit()
        shown = apply_done(s, steps, RUN)
        assert [st["done"] for st in shown] == [False, True]
        assert apply_done(s, [{"title": "25 high findings, 21 with a fix", "level": "gelb"}], RUN)[0]["done"]   # Zahlen egal
        nxt = SimpleNamespace(**{**vars(RUN), "id": RUN.id + 1})
        assert not any(st["done"] for st in apply_done(s, steps, nxt))   # nächster Lauf: wieder sichtbar, falls noch da


def test_a_recreate_command_in_a_check_error_becomes_the_step_command(ctx):
    cov = {"systems": [{"system_id": 1, "system_name": "host-a", "checks": {"versionen": {"status": "fehler", "detail":
           "1 image(s) not checkable: deploy-server-1: runs an image whose tag now points to a newer build; recreate the "
           "container (a restart is not enough): cd /srv/vw/deploy && docker compose up -d --force-recreate server"}}}]}
    with ctx.session_factory() as s:
        [step] = next_steps(s, {"kritisch": 0, "hoch": 0}, cov, RUN, NOW)
    assert step["command"] == "cd /srv/vw/deploy && docker compose up -d --force-recreate server"
    assert step["detail"].endswith("(a restart is not enough)") and "cd /srv" not in step["detail"]
