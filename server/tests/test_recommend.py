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


def test_images_and_other_sources_never_contain_installation_paths():
    r = recommend(f(target="image:openspeedtest/latest", component="libcurl"), UBUNTU)
    assert r["command"] == "docker compose pull speed && docker compose up -d speed"
    assert "/home/user" not in json.dumps(r)
    assert recommend(f(target="image:hub:1"), UBUNTU)["command"] == "docker compose build --pull"
    assert recommend(f(target="image:other:2", component="x"), UBUNTU)["command"] == "docker pull other:2"
    assert "change the image tag" in recommend(f(target="image:openspeedtest/latest", source="registry",
                                                 cve_id="VW-IMAGE-NEWER", fixed_version="2.0"), UBUNTU)["text"]
    for source, target in (("npm", "certificate:3"), ("truenas", "app:plex"), ("homeassistant", "battery:sensor.x"),
                           ("eol", "host"), ("ai", "host")):
        r = recommend(f(source=source, target=target, cve_id="VW-X"), UBUNTU)
        assert r["text"] and r["command"] == ""
