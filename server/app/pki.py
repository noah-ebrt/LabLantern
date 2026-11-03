import ipaddress
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_VALID_DAYS = 3650
LEAF_VALID_DAYS = 365
RENEW_BEFORE_DAYS = 30


@dataclass(frozen=True)
class Pki:
    ca_cert: Path
    ca_key: Path
    server_cert: Path
    server_key: Path


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _san_entries(hostnames: list[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for h in hostnames:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            entries.append(x509.DNSName(h))
    return entries


def _create_ca(cert_path: Path, key_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("lablantern CA"))
        .issuer_name(_name("lablantern CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private_key(key_path, key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _create_server_cert(pki: Pki, hostnames: list[str]) -> None:
    ca_cert = x509.load_pem_x509_certificate(pki.ca_cert.read_bytes())
    ca_key = serialization.load_pem_private_key(pki.ca_key.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(hostnames[0]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(_san_entries(hostnames)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_private_key(pki.server_key, key)
    pki.server_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _leaf_is_current(cert_path: Path, hostnames: list[str]) -> bool:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    have = {str(v) for v in san.get_values_for_type(x509.DNSName)}
    have |= {str(v) for v in san.get_values_for_type(x509.IPAddress)}
    renew_at = cert.not_valid_after_utc - timedelta(days=RENEW_BEFORE_DAYS)
    return have == set(hostnames) and datetime.now(timezone.utc) < renew_at


def ensure_pki(directory: Path, hostnames: list[str]) -> Pki:
    """Legt CA und Server-Zertifikat an. Die CA bleibt bestehen (Agenten pinnen ihren
    Fingerabdruck), das Server-Zertifikat wird bei geänderten Namen oder kurz vor Ablauf erneuert."""
    if not hostnames:
        raise ValueError("at least one hostname or IP required")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    pki = Pki(
        ca_cert=directory / "ca.pem",
        ca_key=directory / "ca.key",
        server_cert=directory / "server.pem",
        server_key=directory / "server.key",
    )
    if not (pki.ca_cert.exists() and pki.ca_key.exists()):
        _create_ca(pki.ca_cert, pki.ca_key)
    if not (
        pki.server_cert.exists()
        and pki.server_key.exists()
        and _leaf_is_current(pki.server_cert, hostnames)
    ):
        _create_server_cert(pki, hostnames)
    return pki


def fingerprint_pem(pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(pem)
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def fingerprint_sha256(cert_path: Path) -> str:
    return fingerprint_pem(Path(cert_path).read_bytes())
