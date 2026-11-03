"""Woher der Server das Wurzelzertifikat seiner TLS-Schicht kennt. Agenten pinnen genau dieses Zertifikat."""
import logging
import urllib.request
from urllib.parse import urlparse

from cryptography import x509

from .config import Settings
from .pki import fingerprint_pem

log = logging.getLogger("lablantern.trust")


def ca_pem(settings: Settings) -> bytes | None:
    """Mit Caddy: Wurzelzertifikat vom internen Endpunkt des Proxys. Ohne Proxy: die eigene CA des Servers."""
    try:
        if settings.ca_url:
            if urlparse(settings.ca_url).scheme not in ("http", "https"):
                return None
            with urllib.request.urlopen(settings.ca_url, timeout=3) as r:  # noqa: S310 (Schema geprüft)
                return r.read(65536)
        own = settings.data_dir / "pki" / "ca.pem"
        return own.read_bytes() if own.is_file() else None
    except (OSError, ValueError):
        return None


def ca_fingerprint(settings: Settings) -> str | None:
    pem = ca_pem(settings)
    if not pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem)
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not basic.ca:
            return None
        return fingerprint_pem(pem)
    except (ValueError, x509.ExtensionNotFound):
        log.warning("The delivered root certificate is invalid")
        return None
