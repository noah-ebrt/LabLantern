"""Empfohlene Maßnahme je Fund: allgemein gültige Befehle, keine Pfade der Installation."""
import json
from types import SimpleNamespace

from app.models import Finding
from app.recommend import recommend

UBUNTU = SimpleNamespace(inventory_json=json.dumps({"os_id": "ubuntu", "kernel": "6.8.0-138-generic", "containers": [
    {"name": "speed", "image": "openspeedtest/latest", "repo_digests": ["x@sha256:1"],
     "labels": {"com.docker.compose.project.working_dir": "/home/user/speed", "com.docker.compose.service": "speed"}},
    {"name": "hub", "image": "hub:1", "repo_digests": []}]}))
ALPINE = SimpleNamespace(inventory_json=json.dumps({"os_id": "alpine"}))


def f(**kw):
    base = dict(cve_id="CVE-2026-1", title="t", component="openssl", installed_version="3.0.1", fixed_version="3.0.2",
                source="grype", target="host", kev=False)
    return Finding(**{**base, **kw})


def test_host_packages_get_the_package_manager_command():
    assert recommend(f(), UBUNTU)["command"] == "sudo apt update && sudo apt install --only-upgrade openssl"
    assert recommend(f(), ALPINE)["command"] == "apk upgrade openssl"
    r = recommend(f(fixed_version=""), UBUNTU)
    assert r["command"] == "" and "No fixed openssl" in r["text"]
    assert recommend(f(kev=True), UBUNTU)["text"].startswith("Actively exploited")
    old = recommend(f(component="linux-modules-6.8.0-136-generic"), UBUNTU)
    assert old["command"] == "sudo apt-get purge $(dpkg-query -W -f='${Package}\\n' '*6.8.0-136*')"
    assert "kernel 6.8.0-136, which no longer runs" in old["text"]
    # 6.8.0-14 läuft: 6.8.0-146 ist trotzdem ein anderer Kernel (früher ein Teilstring-Vergleich)
    assert "no longer runs" in recommend(f(component="linux-modules-6.8.0-146-generic"), SimpleNamespace(inventory_json=json.dumps({"os_id": "ubuntu", "kernel": "6.8.0-14-generic"})))["text"]


def test_a_project_started_with_its_own_compose_files_keeps_the_plain_command():
    """cd ins Projektverzeichnis fände eine mit -f übergebene Datei nicht: dann bleibt der Hinweis im Text."""
    labels = {"com.docker.compose.project.working_dir": "/home/user/app", "com.docker.compose.service": "web",
              "com.docker.compose.project.config_files": "/home/user/app/prod.yml"}
    inv = {"os_id": "ubuntu", "containers": [{"name": "web", "image": "nginx:latest", "repo_digests": ["x@sha256:1"],
                                              "labels": labels}]}
    r = recommend(f(target="image:nginx:latest", component="libcurl"), SimpleNamespace(inventory_json=json.dumps(inv)))
    assert r["command"] == "docker compose pull web && docker compose up -d web"
    assert "Run it in the directory of the Compose project web." in r["text"]
    labels["com.docker.compose.project.config_files"] = "/home/user/app/docker-compose.yml"
    r = recommend(f(target="image:nginx:latest", component="libcurl"), SimpleNamespace(inventory_json=json.dumps(inv)))
    assert r["command"].startswith('(cd "$(docker inspect -f ') and r["command"].endswith("up -d web)")
    assert "/home/user" not in json.dumps(r)


def test_images_and_other_sources_never_contain_installation_paths():
    r = recommend(f(target="image:openspeedtest/latest", component="libcurl"), UBUNTU)
    # läuft aus jedem Verzeichnis: der Pfad kommt zur Laufzeit aus dem Label, steht aber nie im Befehl
    assert r["command"] == '(cd "$(docker inspect -f \'{{index .Config.Labels "com.docker.compose.project.working_dir"}}\' speed)" && docker compose pull speed && docker compose up -d speed)'
    assert "/home/user" not in json.dumps(r)
    assert "changes into the directory of the Compose project speed itself." in r["text"]
    assert recommend(f(target="image:hub:1"), UBUNTU)["command"] == "docker compose build --pull"
    assert recommend(f(target="image:other:2", component="x"), UBUNTU)["command"] == "docker pull other:2"
    assert "change the image tag" in recommend(f(target="image:openspeedtest/latest", source="registry",
                                                 cve_id="LL-IMAGE-NEWER", fixed_version="2.0"), UBUNTU)["text"]
    for source, target in (("npm", "certificate:3"), ("truenas", "app:plex"), ("homeassistant", "battery:sensor.x"),
                           ("eol", "host"), ("ai", "host")):
        r = recommend(f(source=source, target=target, cve_id="LL-X"), UBUNTU)
        assert r["text"] and r["command"] == ""


def test_portainer_stacks_and_pinned_tags_get_no_useless_pull():
    """Portainer-Stacks: kein Compose-Verzeichnis auf dem Host; fester Versions-Tag: pull holt dasselbe Image."""
    sys = SimpleNamespace(inventory_json=json.dumps({"os_id": "ubuntu", "containers": [
        {"name": "n8n", "image": "n8nio/n8n:latest", "repo_digests": ["x@sha256:1"],
         "labels": {"com.docker.compose.project.working_dir": "/data/compose/1", "com.docker.compose.project": "n8n",
                    "com.docker.compose.service": "n8n"}},
        {"name": "gitlab", "image": "gitlab/gitlab-ce:19.5.3-ce.0", "repo_digests": ["x@sha256:2"],
         "labels": {"com.docker.compose.project.working_dir": "/srv/gitlab", "com.docker.compose.project": "gitlab",
                    "com.docker.compose.service": "gitlab"}}]}))
    r = recommend(f(target="image:n8nio/n8n:latest", component="libcurl"), sys)
    assert r["command"] == "" and "Portainer: Stacks → n8n → Pull and redeploy" in r["text"]
    r = recommend(f(target="image:gitlab/gitlab-ce:19.5.3-ce.0", component="x/net"), sys)
    assert r["command"] == "" and "19.5.3-ce.0 is pinned" in r["text"] and "/srv/gitlab" not in json.dumps(r)
