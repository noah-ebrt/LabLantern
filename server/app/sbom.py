"""SBOM aus den vom Agenten gemeldeten Paketen. Die PURLs folgen Syfts Schema (Distro-Namespace, Architektur,
Quellpaket als `upstream`): Ohne Quellpaket matcht Grype die Binärpakete nicht gegen die Distro-Advisories
und verpasst den Großteil der Funde (gemessen auf einem Ubuntu-24.04-Host: 675 statt 5181 CVEs)."""
from typing import Any
from urllib.parse import quote


def _enc(value: str) -> str:
    return quote(value, safe="")


def purl_for(pkg: dict[str, Any], os_id: str, os_version_id: str) -> str | None:
    kind = pkg.get("type")
    if kind not in ("deb", "rpm") or not pkg.get("name") or not pkg.get("version"):
        return None
    name, version = pkg["name"], pkg["version"]
    qualifiers: dict[str, str] = {}
    if pkg.get("arch"):
        qualifiers["arch"] = pkg["arch"]
    if os_id:
        qualifiers["distro"] = f"{os_id}-{os_version_id}" if os_version_id else os_id
    source = pkg.get("source") or ""
    if kind == "deb":
        source_version = pkg.get("source_version") or ""
        if source and (source != name or (source_version and source_version != version)):
            if source_version and source_version != version:
                qualifiers["upstream"] = f"{source}@{source_version}"
            else:
                qualifiers["upstream"] = source
    elif source and source != "(none)":
        qualifiers["upstream"] = source
    query = "&".join(f"{k}={_enc(v)}" for k, v in sorted(qualifiers.items()))
    namespace = f"{_enc(os_id)}/" if os_id else ""
    return f"pkg:{kind}/{namespace}{_enc(name)}@{_enc(version)}" + (f"?{query}" if query else "")


def build_cyclonedx(system_name: str, os_id: str, os_version_id: str, os_name: str,
                    packages: list[dict[str, Any]]) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    if os_id:
        components.append({"type": "operating-system", "name": os_id, "version": os_version_id,
                           "description": os_name})
    for pkg in packages:
        purl = purl_for(pkg, os_id, os_version_id)
        if purl is None:
            continue
        components.append({"type": "library", "name": pkg["name"], "version": pkg["version"], "purl": purl})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "operating-system", "name": system_name, "version": os_name}},
        "components": components,
    }


# Collector-API (PLAN-extensions C): nur diese PURL-Typen gleichen Grype oder OSV gegen eine Datenbank ab. Pakete
# anderer Ökosysteme (opkg, Slackware, Synology …) landen nicht in der SBOM; die Matrix zeigt sie als n/a mit Grund.
SCANNABLE_PURL_TYPES = ("deb", "rpm", "apk", "npm", "pypi", "golang", "cargo", "gem", "nuget", "composer", "maven")
_LANGUAGE = ("npm", "pypi", "golang", "cargo", "gem", "nuget", "composer")


def collector_purl(pkg: dict[str, Any], os_id: str, os_version: str) -> str | None:
    if pkg.get("purl"):
        kind = pkg["purl"].removeprefix("pkg:").split("/", 1)[0]
        return pkg["purl"] if kind in SCANNABLE_PURL_TYPES else None
    eco, name, version = pkg["ecosystem"], pkg["name"], pkg["version"]
    if eco in ("deb", "rpm"):
        return purl_for({"type": eco, "name": name, "version": version}, os_id, os_version)
    if eco == "apk" and os_id:
        distro = f"{os_id}-{os_version}" if os_version else os_id
        return f"pkg:apk/{_enc(os_id)}/{_enc(name)}@{_enc(version)}?distro={_enc(distro)}"
    if eco in _LANGUAGE:
        return f"pkg:{eco}/{_enc(name)}@{_enc(version)}"
    return None


def packages_to_sbom(system_name: str, os_id: str, os_name: str, os_version: str,
                     packages: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, list[int]]]:
    """CycloneDX wie beim Agenten, dazu je Ökosystem [gemeldet, abgleichbar]. Die SBOM entsteht immer, auch ohne
    abgleichbares Paket: Dann findet der Scan eben nichts, und die Matrix sagt n/a statt eines Fehlers."""
    sbom = build_cyclonedx(system_name, os_id, os_version, os_name, [])
    ecosystems: dict[str, list[int]] = {}
    for pkg in packages:
        purl = collector_purl(pkg, os_id, os_version)
        count = ecosystems.setdefault(pkg["ecosystem"], [0, 0])
        count[0] += 1
        if purl is None:
            continue
        count[1] += 1
        sbom["components"].append({"type": "library", "name": pkg["name"], "version": pkg["version"], "purl": purl})
    return sbom, ecosystems
