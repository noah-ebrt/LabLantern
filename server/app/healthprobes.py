"""Prüfungen der Gesundheitsüberwachung: je Art eine Funktion, die blockierend misst und ein ProbeResult liefert.

Alle Prüfungen laufen im Server-Prozess in einem eigenen Thread-Pool (health.HealthEngine) und haben eine harte
Zeitgrenze. Ping nutzt unprivilegierte ICMP-Sockets (SOCK_DGRAM): Der Container braucht dafür keine Capability,
nur net.ipv4.ping_group_range (in deploy/compose.yaml gesetzt). Antworttexte geprüfter Dienste verlassen den
Server nie; die API meldet nur Status, Latenz und eine kurze Fehlermeldung."""
import http.client
import ipaddress
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from .fritzbox import FritzError, _soap, digest_opener

HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
PATH_RE = re.compile(r"^/[^\s]{0,300}$")
EXPECT_RE = re.compile(r"^(\dxx|\d{3}(-\d{3})?)(,(\dxx|\d{3}(-\d{3})?))*$")
MAX_BODY = 256 * 1024

# Arten, die der Server selbst misst (aktiv) bzw. aus Meldungen ableitet (passiv)
ACTIVE = ("ping", "tcp", "http", "tls", "dns", "fritz_host", "fritz_wan")
PASSIVE = ("agent", "heartbeat")
KINDS = ACTIVE + PASSIVE
FRITZ_KINDS = ("fritz_host", "fritz_wan")


@dataclass
class ProbeResult:
    ok: bool
    latency_ms: float | None = None
    error: str = ""
    warn: str = ""             # erreichbar, aber auffällig (Zertifikat läuft bald ab)
    inconclusive: bool = False  # nicht entscheidbar (FRITZ!Box selbst nicht erreichbar): zählt nicht als Ausfall


@dataclass
class ProbeSpec:
    kind: str
    host: str
    params: dict
    timeout: float
    auth: str | None = None      # HTTP: Authorization-Header
    fritz: dict | None = None    # {url, user, password} aus dem FRITZ!Box-Connector


def clean_params(kind: str, p: dict) -> dict:
    """Erlaubte Felder je Art prüfen und normalisieren; ValueError mit lesbarer Meldung bei Unsinn."""
    p = dict(p or {})

    def port(default):
        v = int(p.get("port") or default)
        if not 1 <= v <= 65535:
            raise ValueError("Port must be 1–65535")
        return v

    def target():
        t = str(p.get("target") or "").strip()
        if t and not HOST_RE.match(t):
            raise ValueError("Target must be an IP address or host name")
        return t

    if kind == "ping":
        return {"target": target()}
    if kind == "tcp":
        return {"target": target(), "port": port(22)}
    if kind == "http":
        scheme = p.get("scheme") or "http"
        if scheme not in ("http", "https"):
            raise ValueError("Scheme must be http or https")
        path = str(p.get("path") or "/")
        if not PATH_RE.match(path):
            raise ValueError("Path must start with / and contain no spaces")
        expect = str(p.get("expect") or "2xx").replace(" ", "")
        if not EXPECT_RE.match(expect):
            raise ValueError("Expected status: e.g. 2xx, 200,301 or 200-399")
        match = str(p.get("match") or "")[:200]
        method = p.get("method") or "GET"
        if method not in ("GET", "HEAD"):
            raise ValueError("Method must be GET or HEAD")
        return {"target": target(), "scheme": scheme, "port": port(443 if scheme == "https" else 80), "path": path,
                "expect": expect, "match": match, "method": method, "verify_tls": bool(p.get("verify_tls", True)),
                "follow_redirects": bool(p.get("follow_redirects", True))}
    if kind == "tls":
        days = int(p.get("warn_days") or 14)
        if not 0 <= days <= 365:
            raise ValueError("Warning days must be 0–365")
        sni = str(p.get("server_name") or "").strip()
        if sni and not HOST_RE.match(sni):
            raise ValueError("Server name must be a host name")
        return {"target": target(), "port": port(443), "warn_days": days, "server_name": sni}
    if kind == "dns":
        name = str(p.get("name") or "example.com").strip().rstrip(".")
        if not re.match(r"^[A-Za-z0-9_.-]{1,253}$", name) or any(len(x) > 63 or not x for x in name.split(".")):
            raise ValueError("Query name must be a valid domain")
        rtype = p.get("rtype") or "A"
        if rtype not in ("A", "AAAA"):
            raise ValueError("Record type must be A or AAAA")
        return {"target": target(), "port": port(53), "name": name, "rtype": rtype}
    if kind == "fritz_host":
        t = str(p.get("target") or "").strip()
        if t and not (MAC_RE.match(t) or _is_ip(t)):
            raise ValueError("FRITZ!Box device: MAC address or IP address")
        return {"target": t.upper().replace("-", ":") if MAC_RE.match(t) else t}
    if kind == "heartbeat":
        grace = int(p.get("grace_s") or 30)
        if not 0 <= grace <= 86400:
            raise ValueError("Grace must be 0–86400 seconds")
        return {"grace_s": grace}
    if kind in ("fritz_wan", "agent"):
        return {}
    raise ValueError(f"Unknown check type: {kind}")


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _resolve(host: str, port: int = 0, kind=socket.SOCK_STREAM):
    infos = socket.getaddrinfo(host, port, type=kind)
    if not infos:
        raise OSError(f"cannot resolve {host}")
    return infos[0][0], infos[0][4]


def _ms(t0: float) -> float:
    return round((time.monotonic() - t0) * 1000, 1)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def probe_ping(spec: ProbeSpec) -> ProbeResult:
    family, addr = _resolve(spec.host, 0, socket.SOCK_DGRAM)
    v6 = family == socket.AF_INET6
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
    except PermissionError:
        return ProbeResult(False, error="ICMP not permitted here (net.ipv4.ping_group_range)", inconclusive=True)
    with sock:
        sock.settimeout(spec.timeout)
        seq = int.from_bytes(os.urandom(2), "big")
        payload = os.urandom(16)
        header = struct.pack("!BBHHH", 128 if v6 else 8, 0, 0, 0, seq)
        packet = header + payload
        if not v6:   # Kennung und (bei IPv6) Prüfsumme setzt der Kernel; für IPv4 rechnen wir sie selbst
            packet = struct.pack("!BBHHH", 8, 0, _checksum(packet), 0, seq) + payload
        t0 = time.monotonic()
        deadline = t0 + spec.timeout
        sock.sendto(packet, addr)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return ProbeResult(False, error="no echo reply")
            sock.settimeout(left)
            try:
                data = sock.recv(2048)
            except socket.timeout:
                return ProbeResult(False, error="no echo reply")
            if len(data) >= 8 and data[0] == (129 if v6 else 0) and struct.unpack("!H", data[6:8])[0] == seq \
                    and data[8:] == payload:
                return ProbeResult(True, _ms(t0))


def probe_tcp(spec: ProbeSpec) -> ProbeResult:
    t0 = time.monotonic()
    with socket.create_connection((spec.host, spec.params["port"]), timeout=spec.timeout):
        return ProbeResult(True, _ms(t0))


def _status_ok(code: int, expect: str) -> bool:
    for part in expect.split(","):
        if part.endswith("xx"):
            if code // 100 == int(part[0]):
                return True
        elif "-" in part:
            lo, hi = part.split("-")
            if int(lo) <= code <= int(hi):
                return True
        elif code == int(part):
            return True
    return False


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def _http_once(scheme: str, host: str, port: int, path: str, method: str, headers: dict, timeout: float, verify: bool):
    if scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request(method, path, headers=headers)
    return conn, conn.getresponse()


def probe_http(spec: ProbeSpec) -> ProbeResult:
    p = spec.params
    scheme, host, port, path = p["scheme"], spec.host, p["port"], p["path"]
    method = p.get("method", "GET")
    headers = {"User-Agent": "vulnwatch-health", "Connection": "close"}
    if spec.auth:
        headers["Authorization"] = spec.auth
    t0 = time.monotonic()
    deadline = t0 + spec.timeout
    for _hop in range(6):
        conn, r = _http_once(scheme, host, port, path, method, headers, max(0.5, deadline - time.monotonic()),
                             p.get("verify_tls", True))
        try:
            location = r.getheader("Location")
            if r.status in (301, 302, 303, 307, 308) and location and p.get("follow_redirects", True):
                nxt = urllib.parse.urljoin(f"{scheme}://{_url_host(host)}:{port}{path}", location)
                u = urllib.parse.urlsplit(nxt)
                if u.scheme not in ("http", "https") or not u.hostname:
                    return ProbeResult(False, _ms(t0), "redirect to an unsupported address")
                if u.hostname != host:
                    headers.pop("Authorization", None)   # Zugangsdaten nie an einen anderen Host weiterreichen
                scheme, host = u.scheme, u.hostname
                port = u.port or (443 if u.scheme == "https" else 80)
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                continue
            latency = _ms(t0)
            expect = p.get("expect") or "2xx"
            if not _status_ok(r.status, expect):
                return ProbeResult(False, latency, f"HTTP {r.status} (expected {expect})")
            if p.get("match") and method == "GET":
                if p["match"].encode() not in r.read(MAX_BODY):
                    return ProbeResult(False, latency, "expected text not found in the response")
            return ProbeResult(True, latency)
        finally:
            conn.close()
    return ProbeResult(False, _ms(t0), "too many redirects")


def probe_tls(spec: ProbeSpec) -> ProbeResult:
    from cryptography import x509

    p = spec.params
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # auch selbst signierte Zertifikate: gemessen wird nur die Laufzeit
    t0 = time.monotonic()
    with socket.create_connection((spec.host, p["port"]), timeout=spec.timeout) as raw:
        server_name = p.get("server_name") or (None if _is_ip(spec.host) else spec.host)
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    latency = _ms(t0)
    if not der:
        return ProbeResult(False, latency, "no certificate presented")
    cert = x509.load_der_x509_certificate(der)
    left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() / 86400
    if left < 0:
        return ProbeResult(False, latency, f"certificate expired {int(-left)} days ago")
    if left < p.get("warn_days", 14):
        return ProbeResult(True, latency, warn=f"certificate expires in {int(left)} days")
    return ProbeResult(True, latency)


def _dns_query(name: str, rtype: str) -> tuple[int, bytes]:
    qid = int.from_bytes(os.urandom(2), "big")
    q = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return qid, struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 28 if rtype == "AAAA" else 1, 1)


RCODES = {1: "format error", 2: "server failure", 3: "name does not exist", 4: "not implemented", 5: "refused"}


def probe_dns(spec: ProbeSpec) -> ProbeResult:
    p = spec.params
    family, addr = _resolve(spec.host, p["port"], socket.SOCK_DGRAM)
    qid, packet = _dns_query(p["name"], p["rtype"])
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(spec.timeout)
        t0 = time.monotonic()
        sock.sendto(packet, addr)
        deadline = t0 + spec.timeout
        while True:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                data = sock.recv(4096)
            except socket.timeout:
                return ProbeResult(False, error="no DNS answer")
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                break
    latency = _ms(t0)
    flags, _qd, answers = struct.unpack("!HHH", data[2:8])
    rcode = flags & 0xF
    if rcode:
        return ProbeResult(False, latency, f"DNS {RCODES.get(rcode, f'error {rcode}')}")
    if not answers:
        return ProbeResult(False, latency, f"no {p['rtype']} record in the answer")
    return ProbeResult(True, latency)


HOSTS = ("urn:dslforum-org:service:Hosts:1", "/upnp/control/hosts")
WAN = (("urn:dslforum-org:service:WANPPPConnection:1", "/upnp/control/wanpppconn1"),
       ("urn:dslforum-org:service:WANIPConnection:1", "/upnp/control/wanipconnection1"))


def _fritz_opener(spec: ProbeSpec):
    if not spec.fritz:
        return None
    return digest_opener(spec.fritz["url"], spec.fritz["user"], spec.fritz["password"])


def probe_fritz_host(spec: ProbeSpec) -> ProbeResult:
    """Kennt die FRITZ!Box das Gerät als aktiv? Erfasst auch Handys im WLAN-Stromsparmodus, die kein Ping beantworten."""
    opener = _fritz_opener(spec)
    if opener is None:
        return ProbeResult(False, error="FRITZ!Box connector not set up", inconclusive=True)
    target = spec.params.get("target") or spec.host
    if MAC_RE.match(target):
        action, args = "GetSpecificHostEntry", {"NewMACAddress": target}
    else:
        action, args = "X_AVM-DE_GetSpecificHostEntryByIP", {"NewIPAddress": target}
    t0 = time.monotonic()
    try:
        out = _soap(opener, spec.fritz["url"], action, args, service=HOSTS[0], control=HOSTS[1], timeout=spec.timeout)
    except FritzError as e:
        if "HTTP 500" in str(e):   # UPnP-Fehler 714: Eintrag unbekannt
            return ProbeResult(False, _ms(t0), "device unknown to the FRITZ!Box")
        return ProbeResult(False, error=str(e), inconclusive=True)
    if out.get("NewActive") == "1":
        return ProbeResult(True, _ms(t0))
    return ProbeResult(False, _ms(t0), "FRITZ!Box reports the device as inactive")


def probe_fritz_wan(spec: ProbeSpec) -> ProbeResult:
    """Ist das Internet tatsächlich verbunden? Erst PPP (DSL), dann IP (Kabel, Glasfaser)."""
    opener = _fritz_opener(spec)
    if opener is None:
        return ProbeResult(False, error="FRITZ!Box connector not set up", inconclusive=True)
    t0 = time.monotonic()
    seen, last_error = [], ""
    for service, control in WAN:
        try:
            out = _soap(opener, spec.fritz["url"], "GetStatusInfo", service=service, control=control, timeout=spec.timeout)
        except FritzError as e:
            last_error = str(e)
            continue
        status = out.get("NewConnectionStatus", "")
        if status == "Connected":
            return ProbeResult(True, _ms(t0))
        seen.append(status or "unknown")
    if seen:
        return ProbeResult(False, _ms(t0), f"internet connection: {', '.join(seen)}")
    return ProbeResult(False, error=last_error, inconclusive=True)


PROBES = {"ping": probe_ping, "tcp": probe_tcp, "http": probe_http, "tls": probe_tls, "dns": probe_dns,
          "fritz_host": probe_fritz_host, "fritz_wan": probe_fritz_wan}


def run_probe(spec: ProbeSpec) -> ProbeResult:
    """Führt eine aktive Prüfung aus; jede Ausnahme wird ein Fehlschlag mit kurzer Meldung."""
    try:
        return PROBES[spec.kind](spec)
    except socket.timeout:
        return ProbeResult(False, error="timed out")
    except ssl.SSLCertVerificationError as e:
        return ProbeResult(False, error=f"certificate not trusted ({e.verify_message}); turn off the certificate check "
                                        "for self-signed services")
    except http.client.HTTPException as e:
        return ProbeResult(False, error=f"invalid HTTP answer ({_short(e)})")
    except ConnectionRefusedError:
        return ProbeResult(False, error="connection refused")
    except socket.gaierror:
        return ProbeResult(False, error=f"cannot resolve {spec.host}")
    except (OSError, ssl.SSLError, ValueError) as e:
        return ProbeResult(False, error=_short(e))


def _short(e: Exception) -> str:
    text = str(e) or type(e).__name__
    return text[:200]
