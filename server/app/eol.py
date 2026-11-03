"""Release-Linien und EOL aus endoflife.date (PLAN Abschnitt 3a). Eine Datei mit allen Produkten, einmal am Tag
geladen und im Datenverzeichnis zwischengespeichert. Images werden über die Docker-purls der Produkte zugeordnet
(pkg:docker/library/mariadb -> mariadb), Betriebssysteme über die os-release-ID."""
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("lablantern.eol")

URL = "https://endoflife.date/api/v1/products/full"
REFRESH_HOURS = 24
MAX_CACHE_DAYS = 7      # älter: kein Vergleich mehr, sondern ein sichtbarer Fehler
MAX_BYTES = 30_000_000
OS_PRODUCTS = {"ubuntu": "ubuntu", "debian": "debian", "raspbian": "debian", "alpine": "alpine",
               "fedora": "fedora", "rocky": "rocky-linux", "almalinux": "almalinux", "centos": "centos",
               "rhel": "rhel", "opensuse-leap": "opensuse", "linuxmint": "linuxmint"}
# Images ohne Docker-purl bei endoflife.date
EXTRA_DOCKER = {"gitlab/gitlab-ce": "gitlab", "gitlab/gitlab-ee": "gitlab"}
VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)")


def _fetch(url: str = URL) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "lablantern", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (feste URL)
        return r.read(MAX_BYTES)


class EolDb:
    def __init__(self, products: list[dict]):
        self.products = {p["name"]: p for p in products if isinstance(p, dict) and p.get("name")}
        self.docker: dict[str, str] = dict(EXTRA_DOCKER)
        for p in self.products.values():
            for ident in p.get("identifiers") or []:
                pid = str(ident.get("id", ""))
                if pid.startswith("pkg:docker/"):
                    self.docker.setdefault(pid.removeprefix("pkg:docker/").split("?")[0].split("@")[0], p["name"])

    def release(self, product: str, version: str) -> dict | None:
        """Release-Linie zu einer Version: 10.11.18 -> „10.11“; nur „8“ (Tag 8-alpine) -> neueste 8.x-Linie."""
        p = self.products.get(product)
        m = VERSION.match(version or "")
        if not p or not m:
            return None
        v = m.group(1)
        releases = p.get("releases") or []
        exact = [r for r in releases if v == r["name"] or v.startswith(r["name"] + ".")]
        if exact:
            return max(exact, key=lambda r: len(r["name"]))
        wider = [r for r in releases if r["name"].startswith(v + ".")]
        return wider[0] if wider else None   # endoflife.date sortiert neueste zuerst

    def newest_maintained(self, product: str) -> str:
        for r in (self.products.get(product) or {}).get("releases") or []:
            if not r.get("isEol"):
                return (r.get("latest") or {}).get("name") or r["name"]
        return ""

    def label(self, product: str) -> str:
        return (self.products.get(product) or {}).get("label") or product


def load(cache_dir: Path, fetch=_fetch, now: float | None = None) -> tuple[EolDb | None, str]:
    """(Datenbank, Fehler). Frisch laden, wenn der Cache älter als 24 h ist; fällt das aus, gilt der Cache bis 7 Tage."""
    now = now or time.time()
    path = cache_dir / "products.json"
    age = now - path.stat().st_mtime if path.is_file() else None
    error = ""
    if age is None or age > REFRESH_HOURS * 3600:
        try:
            data = fetch()
            products = json.loads(data)["result"]
            cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, path)
            return EolDb(products), ""
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as e:
            error = f"endoflife.date not reachable ({type(e).__name__})"
            log.warning("EOL data: %s", error)
    if age is None or age > MAX_CACHE_DAYS * 86400:
        return None, error or "no EOL data"
    try:
        return EolDb(json.loads(path.read_bytes())["result"]), ""
    except (OSError, ValueError, KeyError) as e:
        return None, f"EOL cache unreadable ({type(e).__name__})"
