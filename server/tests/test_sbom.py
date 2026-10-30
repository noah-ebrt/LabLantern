import json
from pathlib import Path

import pytest

from app.sbom import build_cyclonedx, purl_for

SAMPLE = json.loads((Path(__file__).parent / "fixtures" / "dpkg-ubuntu-2404-sample.json").read_text())


@pytest.mark.parametrize("pkg", SAMPLE, ids=lambda p: f"{p['name']}@{p['version']}")
def test_deb_purls_match_what_syft_produces_on_a_real_ubuntu_host(pkg):
    assert purl_for(pkg, "ubuntu", "24.04") == pkg["expected_purl"]


def test_debian_uses_its_own_namespace_and_distro():
    pkg = {"name": "curl", "version": "7.88.1-10+deb12u5", "arch": "amd64", "source": "curl",
           "source_version": "7.88.1-10+deb12u5", "type": "deb"}
    assert purl_for(pkg, "debian", "12") == "pkg:deb/debian/curl@7.88.1-10%2Bdeb12u5?arch=amd64&distro=debian-12"


def test_rpm_purl_carries_arch_distro_and_source_rpm():
    pkg = {"name": "bash", "version": "5.2.26-3.fc40", "arch": "x86_64", "source": "bash-5.2.26-3.fc40.src.rpm",
           "source_version": "", "type": "rpm"}
    assert purl_for(pkg, "fedora", "40") == (
        "pkg:rpm/fedora/bash@5.2.26-3.fc40?arch=x86_64&distro=fedora-40&upstream=bash-5.2.26-3.fc40.src.rpm")


def test_unknown_package_type_has_no_purl():
    assert purl_for({"name": "x", "version": "1", "type": "snap"}, "ubuntu", "24.04") is None


def test_cyclonedx_document_lists_every_package_and_the_os():
    pkgs = SAMPLE[:3]
    doc = build_cyclonedx("host-a", "ubuntu", "24.04", "Ubuntu 24.04.5 LTS", pkgs)
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    libs = [c for c in doc["components"] if c["type"] == "library"]
    assert [c["purl"] for c in libs] == [p["expected_purl"] for p in pkgs]
    os_comp = [c for c in doc["components"] if c["type"] == "operating-system"]
    assert os_comp and os_comp[0]["name"] == "ubuntu" and os_comp[0]["version"] == "24.04"


def test_packages_without_purl_are_skipped_not_invented():
    doc = build_cyclonedx("h", "ubuntu", "24.04", "x", [{"name": "x", "version": "1", "type": "snap"}])
    assert [c for c in doc["components"] if c["type"] == "library"] == []
