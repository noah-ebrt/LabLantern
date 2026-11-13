"""Ansicht „By host“: Zahlen je Host und Gruppen mit einer ehrlichen Maßnahme (hilft der Pull wirklich?)."""
import json
from datetime import datetime, timezone

from sqlalchemy import select

from app.models import Finding, ScanRun, System, put_setting
from app.products import STATE_KEY
from tests.test_runs_api import setup_system

INV = {"os_id": "ubuntu", "os_name": "Ubuntu 24.04", "kernel": "6.8.0-147-generic", "containers": [
    {"name": "stirling-pdf", "image": "stirlingtools/stirling-pdf:latest", "repo_digests": ["x@sha256:1"],
     "labels": {"com.docker.compose.project": "stirling-pdf", "com.docker.compose.service": "stirling-pdf",
                "com.docker.compose.project.working_dir": "/home/user/stirling"}},
    {"name": "npm", "image": "jc21/nginx-proxy-manager:latest", "repo_digests": ["x@sha256:2"],
     "labels": {"com.docker.compose.project": "proxy", "com.docker.compose.service": "app",
                "com.docker.compose.project.working_dir": "/data/compose/3"}}]}


def seed(env):
    ctx, sid = setup_system(env)
    with ctx.session_factory() as s:
        s.get(System, sid).inventory_json = json.dumps(INV)

        def add(target, component, sev="hoch", fixed="1.0", cve="CVE-2026-1", kev=False, source="grype"):
            s.add(Finding(system_id=sid, cve_id=cve, severity=sev, component=component, fixed_version=fixed,
                          installed_version="0.9", source=source, target=target, kev=kev))
        add("image:stirlingtools/stirling-pdf:latest", "brotli", "kritisch", kev=True)
        add("image:stirlingtools/stirling-pdf:latest", "openssl", cve="CVE-2026-2")
        add("image:stirlingtools/stirling-pdf:latest", "stirling", "hoch", "3.3.0", "LL-IMAGE-OUTDATED", source="registry")
        add("image:jc21/nginx-proxy-manager:latest", "libcurl", "kritisch")
        add("host", "linux-modules-6.8.0-147-generic", "kritisch", fixed="")
        add("host", "linux-modules-6.8.0-136-generic", "mittel", fixed="", cve="CVE-2026-3")
        add("host", "libwebkit2gtk-4.1-0", "kritisch", fixed="", kev=True, cve="CVE-2026-4")
        add("host", "sqlite3", "mittel", fixed="3.45.1-1ubuntu2.9")
        put_setting(s, STATE_KEY, {"at": 0, "systems": {str(sid): {"rows": [
            {"image": "stirlingtools/stirling-pdf:latest", "status": "outdated"},
            {"image": "jc21/nginx-proxy-manager:latest", "status": "current"}]}}})
        s.commit()
    return sid


def test_by_host_counts_follow_the_filters(admin):
    env, client, _ = admin
    sid = seed(env)
    [row] = client.get("/api/findings/by-host").json()
    assert (row["system_id"], row["kritisch"], row["hoch"], row["mittel"], row["kev"], row["images"]) == (sid, 4, 2, 2, 2, 2)
    assert row["fixable"] == 3   # sqlite3 (Host) und die zwei Scannerfunde im Stirling-Image mit neuerem Build
    [row] = client.get("/api/findings/by-host?severity=kritisch").json()
    assert row["total"] == 4 and row["mittel"] == 0


def test_groups_say_honestly_whether_an_update_helps(admin):
    env, client, _ = admin
    sid = seed(env)
    groups = {g["key"]: g for g in client.get(f"/api/findings/groups?system_id={sid}").json()["groups"]}
    stirling = groups["image:stirlingtools/stirling-pdf:latest"]
    assert stirling["state"] == "update" and stirling["containers"] == ["stirling-pdf"]
    assert stirling["command"] == '(cd "$(docker inspect -f \'{{index .Config.Labels "com.docker.compose.project.working_dir"}}\' stirling-pdf)" && docker compose pull stirling-pdf && docker compose up -d stirling-pdf)'
    assert "Compose project stirling-pdf" in stirling["text"] and "/home/user" not in json.dumps(stirling)
    assert stirling["counts"]["kev"] == 1 and stirling["counts"]["fixable"] == 2

    npm = groups["image:jc21/nginx-proxy-manager:latest"]
    assert npm["state"] == "waiting" and npm["command"] == "" and "pulling changes nothing" in npm["text"]

    assert groups["kernel-nofix"]["state"] == "waiting"
    old = groups["oldkernel"]
    assert "6.8.0-136" in old["command"] and old["state"] == "update"
    nofix = groups["nofix"]
    assert nofix["state"] == "waiting" and "desktop" in nofix["text"]
    pkgs = groups["packages"]
    assert pkgs["command"] == "sudo apt update && sudo apt full-upgrade" and pkgs["packages"][0]["component"] == "sqlite3"
    # KEV-Gruppen zuerst
    assert list(groups)[0] in ("image:stirlingtools/stirling-pdf:latest", "nofix")


def test_an_update_that_left_the_findings_in_place_is_not_promised_again(admin):
    """Images, deren :latest täglich neu gebaut wird: der letzte Pull ließ dieselben Funde zurück."""
    env, client, _ = admin
    sid = seed(env)
    ctx, target = env.app.state.ctx, "image:stirlingtools/stirling-pdf:latest"

    def day(d):
        return datetime(2026, 11, d, tzinfo=timezone.utc)

    def group():
        groups = client.get(f"/api/findings/groups?system_id={sid}").json()["groups"]
        return next(g for g in groups if g["key"] == target)

    def extra(**kw):
        return Finding(system_id=sid, cve_id="CVE-2026-9", severity="hoch", component="curl", fixed_version="2",
                       source="grype", target=target, **kw)

    with ctx.session_factory() as s:
        inv = json.loads(s.get(System, sid).inventory_json)
        inv["containers"][0]["created"] = "2026-11-10T10:00:00Z"   # zuletzt aktualisiert am 10.
        s.get(System, sid).inventory_json = json.dumps(inv)
        run = ScanRun(started_at=day(11), status="success")
        s.add(run)
        s.flush()
        run_id = run.id
        for f in s.scalars(select(Finding).where(Finding.target == target)):
            f.created_at = day(12) if f.cve_id == "LL-IMAGE-OUTDATED" else day(9)   # neueres Image erst seit dem 12.
            f.last_seen_run_id = run_id
        s.commit()
    g = group()
    assert g["state"] == "stuck" and g["counts"]["stayed"] == 2 and "last update (Nov 10) left all 2" in g["text"]
    assert "docker compose pull stirling-pdf" in g["command"]   # der Pull bleibt angeboten

    # ein Fund kam erst nach dem Update dazu: den behebt das neuere Image womöglich
    with ctx.session_factory() as s:
        s.add(extra(installed_version="1.1", created_at=day(11), last_seen_run_id=run_id))
        s.commit()
    g = group()
    assert g["state"] == "update" and g["counts"]["stayed"] == 2 and "2 of the 3 fixable" in g["text"]

    # dieselbe CVE stand vor dem Update schon an der älteren Version der Komponente: auch sie hat es überstanden
    with ctx.session_factory() as s:
        s.add(extra(installed_version="1.0", created_at=day(9), status="resolved"))
        s.commit()
    assert group()["state"] == "stuck"

    # das neuere Image gab es schon, als der Container neu erstellt wurde: das war kein Update, also keine Aussage
    with ctx.session_factory() as s:
        s.scalars(select(Finding).where(Finding.cve_id == "LL-IMAGE-OUTDATED")).one().created_at = day(8)
        s.commit()
    g = group()
    assert g["state"] == "update" and g["counts"]["stayed"] == 0 and "last update" not in g["text"]


def test_finding_advice_does_not_promise_a_pull_on_the_newest_image(admin):
    env, client, _ = admin
    seed(env)
    rows = client.get("/api/findings?target=image:jc21/nginx-proxy-manager:latest").json()
    assert len(rows) == 1 and rows[0]["action"]["command"] == ""
    assert "pulling changes nothing" in rows[0]["action"]["text"]
    stirling = client.get("/api/findings?target=image:stirlingtools/stirling-pdf:latest&q=brotli").json()[0]
    assert "&& docker compose pull stirling-pdf" in stirling["action"]["command"]


def test_groups_need_a_known_system(admin):
    _, client, _ = admin
    assert client.get("/api/findings/groups?system_id=999").status_code == 404
