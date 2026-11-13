"""collectors/linux.sh: Das Skript baut für deb und rpm dieselben purls wie der Server für Agenten-Pakete (purl_for),
samt Quellpaket. Sonst fände der Abgleich z. B. libssl3 nicht unter openssl und meldete „0 Funde“."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.collector_api import CollectorReport
from app.sbom import collector_purl, purl_for

SCRIPT = Path(__file__).parents[2] / "collectors" / "linux.sh"
TOOLS = ("sh", "sed", "tr", "cat", "mktemp", "rm", "head")
AWKS = [a for a in ("mawk", "gawk", "busybox") if shutil.which(a)] or ["awk"]

DEB = [  # Name, Version, Architektur, Quellpaket, Quellversion, Status
    ("libssl3", "3.0.11-1~deb12u2", "amd64", "openssl", "3.0.11-1~deb12u2", "install ok installed"),
    ("libstdc++6", "12.2.0-14", "amd64", "gcc-12", "12.2.0-14", "install ok installed"),
    ("bash", "5.2.15-2+b2", "amd64", "bash", "5.2.15-2", "install ok installed"),
    ("curl", "7.88.1-10+deb12u5", "amd64", "curl", "7.88.1-10+deb12u5", "install ok installed"),
    ("git", "1:2.39.2-1.1", "amd64", "git", "1:2.39.2-1.1", "hold ok installed"),
    ("removed", "1.0", "all", "removed", "1.0", "deinstall ok config-files"),
]
RPM = [  # Name, Version-Release, Architektur, Quell-RPM
    ("openssl-libs", "3.0.7-27.el9", "x86_64", "openssl-3.0.7-27.el9.src.rpm"),
    ("tzdata", "2024a-1.el9", "noarch", "tzdata-2024a-1.el9.src.rpm"),
    ("local-tool", "1.0-1", "x86_64", "(none)"),
    ("gpg-pubkey", "350d275d-6279464b", "(none)", "(none)"),
]
APK = ["musl-1.2.5-r0 x86_64 {musl} (MIT) [installed]",
       "libcrypto3-3.3.2-r0 x86_64 {openssl} (Apache-2.0) [installed]"]


def fake(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def run(tmp_path: Path, awk: str, os_release: str, tool: str, lines: list[str]) -> dict:
    """Das Skript mit einem PATH, in dem nur die genannte Paketverwaltung liegt; curl schreibt den Report weg."""
    bin_, conf, out = tmp_path / "bin", tmp_path / "conf", tmp_path / "report.json"
    bin_.mkdir()
    conf.mkdir()
    for t in TOOLS:
        (bin_ / t).symlink_to(shutil.which(t))
    (bin_ / "awk").symlink_to(shutil.which(awk))
    fake(bin_ / tool, "cat <<'EOF'\n" + "\n".join(lines) + "\nEOF\n")
    fake(bin_ / "curl", f'printf "%s\\n" "$@" > "{tmp_path}/args"\ncat > "{out}"\n')
    for name, text in (("token", "t0ken"), ("url", "https://192.0.2.10:8443"), ("ca.crt", "")):
        (conf / name).write_text(text + "\n")
    (tmp_path / "os-release").write_text(os_release)
    subprocess.run([str(bin_ / "sh"), str(SCRIPT)], check=True, timeout=30,
                   env={"PATH": str(bin_), "LL_DIR": str(conf), "LL_OS_RELEASE": str(tmp_path / "os-release")})
    args = (tmp_path / "args").read_text().split("\n")
    assert "--cacert" in args and "https://192.0.2.10:8443/api/collector/v1/report" in args
    report = json.loads(out.read_text())
    CollectorReport.model_validate(report)
    return report


@pytest.mark.parametrize("awk", AWKS)
def test_deb_purls_match_the_agents(tmp_path, awk):
    report = run(tmp_path, awk, 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
                 "dpkg-query", ["\t".join(p) for p in DEB])
    assert report["os"] == {"id": "debian", "name": "Debian GNU/Linux 12 (bookworm)", "version": "12"}
    want = [purl_for({"type": "deb", "name": n, "version": v, "arch": a, "source": s, "source_version": sv}, "debian", "12")
            for n, v, a, s, sv, status in DEB if status.endswith(" installed")]
    assert [p["purl"] for p in report["packages"]] == want
    assert "upstream=openssl" in want[0] and "upstream=bash%405.2.15-2" in want[2] and "upstream" not in want[3]
    assert all(collector_purl(p, "debian", "12") == p["purl"] for p in report["packages"])


@pytest.mark.parametrize("awk", AWKS)
def test_rpm_purls_match_the_agents(tmp_path, awk):
    report = run(tmp_path, awk, 'ID="rocky"\nVERSION_ID="9.4"\nPRETTY_NAME="Rocky Linux 9.4"\n',
                 "rpm", ["\t".join(p) for p in RPM])
    want = [purl_for({"type": "rpm", "name": n, "version": v, "arch": a, "source": "" if s == "(none)" else s}, "rocky", "9.4")
            for n, v, a, s in RPM if n != "gpg-pubkey"]
    assert [p["purl"] for p in report["packages"]] == want


def test_apk_and_a_rolling_release_without_version(tmp_path):
    report = run(tmp_path, AWKS[0], 'ID=alpine\nPRETTY_NAME="Alpine Linux edge"\n', "apk", APK)
    assert report["os"]["version"] == "?"
    assert report["packages"] == [{"ecosystem": "apk", "name": "musl", "version": "1.2.5-r0"},
                                  {"ecosystem": "apk", "name": "libcrypto3", "version": "3.3.2-r0"}]
