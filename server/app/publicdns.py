"""Öffentliche DNS-Prüfung für Proxy-Routen (PLAN-extensions A4): eine Route im Proxy heißt noch nicht, dass sie aus
dem Internet erreichbar ist. Gefragt wird Cloudflare per DNS-over-HTTPS; nur eine öffentliche Adresse zählt.

Sicher im Zweifel: Ist der Resolver nicht erreichbar oder antwortet mit einem Fehler, gilt der Name als erreichbar
und die Quelle steht als Fehler in der Matrix, nie stillschweigend "nur im LAN". Lokale Namen (.lan, .home.arpa,
.local, .internal) werden gar nicht erst gefragt."""
import ipaddress
import json
import urllib.parse
import urllib.request
from typing import Callable, Literal

from .models import setting

DOH = "https://cloudflare-dns.com/dns-query"
OVERRIDES_KEY = "exposure_overrides"
LOCAL_SUFFIXES = (".lan", ".home.arpa", ".local", ".internal")
CHECK_FAILED = "public DNS check failed"
NXDOMAIN, SERVFAIL = 3, 2
Verdict = Literal["public", "lan", "unknown"]


def doh_query(name: str, rtype: str) -> dict:
    url = f"{DOH}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read(100_000))


def classify_hostname(name: str, resolver: Callable[[str, str], dict] | None = None) -> Verdict:
    name = name.strip().rstrip(".").lower()
    if name.endswith(LOCAL_SUFFIXES) or "." not in name:
        return "lan"
    resolver = resolver or doh_query
    failed = False
    for rtype, code in (("A", 1), ("AAAA", 28)):
        try:
            answer = resolver(name, rtype)
        except (OSError, ValueError):
            failed = True
            continue
        status = answer.get("Status")
        if status not in (0, NXDOMAIN):
            failed = True
            continue
        for rec in answer.get("Answer") or []:
            if rec.get("type") != code:
                continue   # CNAME-Kette: zählt nur die Adresse am Ende
            try:
                if ipaddress.ip_address(rec.get("data", "")).is_global:
                    return "public"
            except ValueError:
                failed = True
    return "unknown" if failed else "lan"


def load_overrides(s) -> dict:
    return setting(s, OVERRIDES_KEY) or {"hosts": {}, "entrypoints": {}}


def decide(name: str, entrypoints: list[str], overrides: dict,
           classify: Callable[[str], Verdict] = classify_hostname) -> tuple[bool, str]:
    """(erreichbar?, Grund). Vorrang: Name von Hand > Entrypoint von Hand > öffentliches DNS."""
    by_host = (overrides.get("hosts") or {}).get(name.lower())
    if by_host:
        return by_host == "public", f"marked {'public' if by_host == 'public' else 'LAN only'} by hand"
    marks = [(overrides.get("entrypoints") or {}).get(e) for e in entrypoints]
    if "public" in marks:
        return True, "entrypoint marked public by hand"
    if marks and all(m == "lan" for m in marks):
        return False, "entrypoint marked LAN only by hand"
    verdict = classify(name)
    if verdict == "public":
        return True, "public address in public DNS"
    if verdict == "lan":
        return False, "no public address in public DNS"
    return True, CHECK_FAILED
