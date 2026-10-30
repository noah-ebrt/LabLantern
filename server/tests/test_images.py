import json

from sqlalchemy import select

from app.models import Finding, SystemScanResult
from app.scanrun import claim_job, enqueue_scan_run, process_scan_result, WorkerResultIn
from tests.test_agent_api import activate, report
from tests.test_scan_flow import Notes, raw

IMG_A = "sha256:" + "a" * 64
IMG_B = "sha256:" + "b" * 64
CONTAINERS = [{"id": "c1", "name": "web", "image": "nginx:1.27", "image_id": IMG_A},
              {"id": "c2", "name": "web2", "image": "nginx:1.27", "image_id": IMG_A},
              {"id": "c3", "name": "db", "image": "postgres:16", "image_id": IMG_B},
              {"id": "c4", "name": "kaputt", "image": "x", "image_id": "keine-id"}]
SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def agent(env, client, h):
    sid, bearer = activate(env, client, h)
    a = env.new_client()
    r = a.post("/api/agent/report", headers=bearer, json=report(containers=CONTAINERS))
    return sid, bearer, a, r.json()


def test_report_asks_for_each_missing_image_sbom_once(admin):
    env, client, h = admin
    _, _, _, res = agent(env, client, h)
    assert res["needed_sboms"] == [IMG_A, IMG_B]          # sortiert, ohne Doppelte, ohne ungültige IDs


def test_upload_stores_the_sbom_and_it_is_no_longer_requested(admin):
    env, client, h = admin
    sid, bearer, a, _ = agent(env, client, h)
    assert a.post("/api/agent/image-sbom", headers=bearer, json={"image_id": IMG_A, "sbom": SBOM}).status_code == 200
    assert (env.data_dir / "images" / str(sid) / ("a" * 64 + ".json")).is_file()
    again = a.post("/api/agent/report", headers=bearer, json=report(containers=CONTAINERS)).json()
    assert again["needed_sboms"] == [IMG_B]


def test_upload_for_an_image_the_host_does_not_run_is_refused(admin):
    env, client, h = admin
    _, bearer, a, _ = agent(env, client, h)
    other = "sha256:" + "c" * 64
    assert a.post("/api/agent/image-sbom", headers=bearer, json={"image_id": other, "sbom": SBOM}).status_code == 403
    assert a.post("/api/agent/image-sbom", headers=bearer, json={"image_id": "../../etc", "sbom": SBOM}).status_code == 422
    assert a.post("/api/agent/image-sbom", json={"image_id": IMG_A, "sbom": SBOM}).status_code == 401


def test_failed_image_sbom_is_stored_as_error_and_requested_again(admin):
    env, client, h = admin
    _, bearer, a, _ = agent(env, client, h)
    a.post("/api/agent/image-sbom", headers=bearer, json={"image_id": IMG_A, "error": "docker save fehlgeschlagen"})
    again = a.post("/api/agent/report", headers=bearer, json=report(containers=CONTAINERS)).json()
    assert IMG_A in again["needed_sboms"]
    cov = client.get("/api/overview").json()["coverage"][0]["checks"]["images"]
    assert cov["status"] == "fehler" and "docker save" in cov["detail"]


def test_images_without_sbom_yet_are_pending_not_ok(admin):
    env, client, h = admin
    agent(env, client, h)
    cov = client.get("/api/overview").json()["coverage"][0]["checks"]["images"]
    assert cov["status"] == "offen" and "2" in cov["detail"]


def test_host_without_containers_has_nothing_to_check(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report(containers=[]))
    assert client.get("/api/overview").json()["coverage"][0]["checks"]["images"]["status"] == "ok"


def scanned(env, client, h, image_findings, image_errors=None):
    ctx = env.app.state.ctx
    ctx.notifier = Notes()
    sid, bearer, a, _ = agent(env, client, h)
    for img in (IMG_A, IMG_B):
        a.post("/api/agent/image-sbom", headers=bearer, json={"image_id": img, "sbom": SBOM})
    enqueue_scan_run(ctx, "manual")
    job = claim_job(ctx)
    images = job["systems"][0]["images"]
    res = WorkerResultIn.model_validate({
        "canary": {"ok": True, "message": "ok"}, "grype_db": {"ok": True, "age_hours": 1.0},
        "systems": [{"system_id": sid, "ok": True, "findings": [raw()] + image_findings,
                     "image_errors": image_errors or {}}]})
    return ctx, sid, images, process_scan_result(ctx, job["id"], res)


def test_job_payload_lists_each_image_once_with_its_reference(admin):
    env, client, h = admin
    _, _, images, _ = scanned(env, client, h, [])
    assert images == [{"id": IMG_A, "ref": "nginx:1.27", "sbom": True}, {"id": IMG_B, "ref": "postgres:16", "sbom": True}]


def test_image_findings_are_separate_from_host_findings_and_visible_in_the_matrix(admin):
    env, client, h = admin
    img = {**raw(), "target": "image:nginx:1.27"}                     # gleiche CVE/Komponente wie auf dem Host
    crit = {**raw(cve="CVE-2021-44228", component="log4j", kev=True, cvss=10.0), "target": "image:postgres:16"}
    ctx, sid, _, run = scanned(env, client, h, [img, crit])
    with ctx.session_factory() as s:
        targets = sorted((f.target, f.cve_id) for f in s.scalars(select(Finding)))
    assert targets == [("host", "CVE-2024-1234"), ("image:nginx:1.27", "CVE-2024-1234"), ("image:postgres:16", "CVE-2021-44228")]
    assert client.get("/api/findings?severity=kritisch").json()[0]["target"] == "image:postgres:16"
    cov = client.get("/api/overview").json()["coverage"][0]["checks"]
    assert cov["images"]["status"] == "fund" and cov["paket_cve"]["status"] == "ok"
    assert "image:postgres:16" in ctx.notifier.sent[-1][1]


def test_image_scan_errors_are_shown_in_the_matrix(admin):
    env, client, h = admin
    scanned(env, client, h, [], {IMG_B: "grype exited with code 1"})
    cov = client.get("/api/overview").json()["coverage"][0]["checks"]["images"]
    assert cov["status"] == "fehler" and "grype" in cov["detail"]


def test_worker_can_download_an_image_sbom_of_its_job(admin):
    env, client, h = admin
    ctx = env.app.state.ctx
    sid, bearer, a, _ = agent(env, client, h)
    a.post("/api/agent/image-sbom", headers=bearer, json={"image_id": IMG_A, "sbom": SBOM})
    enqueue_scan_run(ctx, "manual")
    w = env.new_client()
    wh = {"Authorization": f"Bearer {ctx.worker_token}"}
    job = w.post("/api/worker/claim", headers=wh).json()["job"]
    r = w.get(f"/api/worker/jobs/{job['id']}/image-sbom/{sid}/{IMG_A}", headers=wh)
    assert r.status_code == 200 and r.json()["bomFormat"] == "CycloneDX"
    assert w.get(f"/api/worker/jobs/{job['id']}/image-sbom/{sid}/{IMG_B}", headers=wh).status_code == 404   # noch keine SBOM
    assert w.get(f"/api/worker/jobs/{job['id']}/image-sbom/{sid}/sha256:{'c'*64}", headers=wh).status_code == 404
    assert w.get(f"/api/worker/jobs/{job['id']}/image-sbom/{sid + 1}/{IMG_A}", headers=wh).status_code == 404


def test_one_agent_cannot_replace_the_image_sbom_of_another_host(admin):
    """Gleiches Image auf zwei Hosts: Host B (übernommen) lädt eine leere SBOM hoch, die von Host A bleibt."""
    env, client, h = admin
    sid_a, bearer_a = activate(env, client, h, hostname="a")
    sid_b, bearer_b = activate(env, client, h, hostname="b")
    a = env.new_client()
    for bearer in (bearer_a, bearer_b):
        a.post("/api/agent/report", headers=bearer, json=report(containers=CONTAINERS))
    real = {**SBOM, "components": [{"type": "library", "name": "openssl", "version": "1.0"}]}
    assert a.post("/api/agent/image-sbom", headers=bearer_a, json={"image_id": IMG_A, "sbom": real}).status_code == 200
    assert a.post("/api/agent/image-sbom", headers=bearer_b, json={"image_id": IMG_A, "sbom": SBOM}).status_code == 200
    stored_a = json.loads((env.data_dir / "images" / str(sid_a) / ("a" * 64 + ".json")).read_text())
    assert stored_a["components"] == real["components"]
    # A wird weiterhin nicht erneut gefragt, B hat seine eigene Datei
    assert IMG_A not in a.post("/api/agent/report", headers=bearer_a, json=report(containers=CONTAINERS)).json()["needed_sboms"]
    assert (env.data_dir / "images" / str(sid_b) / ("a" * 64 + ".json")).is_file()


def test_container_labels_are_reduced_to_harmless_ones(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    labels = {"com.docker.compose.project": "web", "traefik.http.middlewares.auth.basicauth.users": "noah:$apr1$x"}
    env.new_client().post("/api/agent/report", headers=bearer,
                          json=report(containers=[{**CONTAINERS[0], "labels": labels}]))
    stored = client.get(f"/api/systems/{sid}").json()["inventory"]["containers"][0]["labels"]
    assert stored == {"com.docker.compose.project": "web"}


def test_container_without_runtime_defaults_docker(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    podman = {**CONTAINERS[0], "name": "web", "runtime": "podman"}
    r = env.new_client().post("/api/agent/report", headers=bearer, json=report(containers=[CONTAINERS[0], podman]))
    assert r.status_code == 200
    stored = client.get(f"/api/systems/{sid}").json()["inventory"]["containers"]
    assert [c["runtime"] for c in stored] == ["docker", "podman"]
    bad = {**CONTAINERS[0], "runtime": "lxc"}
    assert env.new_client().post("/api/agent/report", headers=bearer, json=report(containers=[bad])).status_code == 422


def test_middleware_label_never_stored(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    labels = {"traefik.enable": "true", "traefik.http.routers.app.rule": "Host(`app.example.org`)",
              "traefik.http.routers.app.entrypoints": "websecure",
              "traefik.http.middlewares.auth.basicauth.users": "noah:$apr1$x",
              "traefik.http.services.app.loadbalancer.server.port": "80", "traefik.enabled": "true"}
    env.new_client().post("/api/agent/report", headers=bearer,
                          json=report(containers=[{**CONTAINERS[0], "labels": labels}]))
    stored = client.get(f"/api/systems/{sid}").json()["inventory"]["containers"][0]["labels"]
    assert stored == {"traefik.enable": "true", "traefik.http.routers.app.rule": "Host(`app.example.org`)",
                      "traefik.http.routers.app.entrypoints": "websecure"}


def test_outdated_agents_are_flagged_and_an_update_command_is_offered(admin):
    env, client, h = admin
    sid, bearer = activate(env, client, h)
    env.new_client().post("/api/agent/report", headers=bearer, json=report(agent_version="0.3.0"))
    s = client.get("/api/systems").json()[0]
    assert s["agent_outdated"] is True and s["needs_reenroll"] is False
    upd = client.get("/api/systems/agent-update").json()
    assert upd["version"] == "0.5.0" and "sha256sum -c" in upd["update_cmd"] and "enroll" not in upd["update_cmd"]
    assert "sudo dpkg -i" in upd["update_cmd"]   # das Paket startet den Daemon neu, der sofort meldet
