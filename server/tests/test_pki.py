import os
import stat
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.pki import ensure_pki, fingerprint_sha256


def test_ensure_pki_creates_ca_and_server_cert_signed_by_ca(tmp_path):
    pki = ensure_pki(tmp_path, hostnames=["lablantern.lan", "192.168.1.50"])
    ca = x509.load_pem_x509_certificate(pki.ca_cert.read_bytes())
    leaf = x509.load_pem_x509_certificate(pki.server_cert.read_bytes())
    assert leaf.issuer == ca.subject
    leaf.verify_directly_issued_by(ca)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["lablantern.lan"]
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["192.168.1.50"]
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert leaf.not_valid_after_utc > datetime.now(timezone.utc)


def test_private_keys_are_mode_0600(tmp_path):
    pki = ensure_pki(tmp_path, hostnames=["lablantern.lan"])
    for key in (pki.ca_key, pki.server_key):
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_ensure_pki_is_idempotent_and_keeps_ca(tmp_path):
    first = ensure_pki(tmp_path, hostnames=["lablantern.lan"])
    ca_before = first.ca_cert.read_bytes()
    leaf_before = first.server_cert.read_bytes()
    second = ensure_pki(tmp_path, hostnames=["lablantern.lan"])
    assert second.ca_cert.read_bytes() == ca_before
    assert second.server_cert.read_bytes() == leaf_before


def test_server_cert_is_reissued_when_hostnames_change_but_ca_stays(tmp_path):
    first = ensure_pki(tmp_path, hostnames=["a.lan"])
    ca_before = first.ca_cert.read_bytes()
    leaf_before = first.server_cert.read_bytes()
    second = ensure_pki(tmp_path, hostnames=["a.lan", "b.lan"])
    assert second.ca_cert.read_bytes() == ca_before
    assert second.server_cert.read_bytes() != leaf_before
    leaf = x509.load_pem_x509_certificate(second.server_cert.read_bytes())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["a.lan", "b.lan"]


def test_fingerprint_is_colon_separated_sha256_of_ca(tmp_path):
    pki = ensure_pki(tmp_path, hostnames=["lablantern.lan"])
    fp = fingerprint_sha256(pki.ca_cert)
    parts = fp.split(":")
    assert len(parts) == 32 and all(len(p) == 2 for p in parts)
    assert fp == fp.upper()
