import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session, sessionmaker

from .models import Secret, utcnow

NONCE_LEN = 12


class SecretTampered(Exception):
    """Secret cannot be decrypted: wrong master key or tampered data."""


def load_or_create_master_key(path: Path) -> bytes:
    path = Path(path)
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError(f"Master key {path} has {len(key)} instead of 32 bytes")
        return key
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def migrate_master_key(legacy: Path, target: Path) -> None:
    """Holt den Master key aus dem Daten-Volume (Altbestand) in sein eigenes Volume.
    Der Worker mountet nur das Daten-Volume und darf den Schlüssel nie sehen."""
    legacy, target = Path(legacy), Path(target)
    if legacy == target or not legacy.exists():
        return
    old = legacy.read_bytes()
    if target.exists():
        if target.read_bytes() != old:
            raise ValueError(
                f"two different master keys found ({legacy} und {target}); "
                "resolve manually which one belongs to the database"
            )
    else:
        if len(old) != 32:
            raise ValueError(f"Master key {legacy} has {len(old)} instead of 32 bytes")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(old)
    legacy.unlink()


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as e:
        raise SecretTampered() from e


class SecretStore:
    """Umschlagverschlüsselung: je Geheimnis ein eigener Datenschlüssel, mit dem Master key
    umhüllt. Der Name geht als AAD ein, damit Einträge nicht vertauscht werden können."""

    def __init__(self, session_factory: sessionmaker[Session], master_key: bytes):
        self._sf = session_factory
        self._master = master_key

    def set(self, name: str, value: str) -> None:
        aad = name.encode()
        dek = os.urandom(32)
        row_values = dict(
            wrapped_dek=_seal(self._master, dek, aad),
            ciphertext=_seal(dek, value.encode(), aad),
            updated_at=utcnow(),
        )
        with self._sf() as s:
            row = s.get(Secret, name)
            if row is None:
                s.add(Secret(name=name, **row_values))
            else:
                for k, v in row_values.items():
                    setattr(row, k, v)
            s.commit()

    def get(self, name: str) -> str | None:
        """Nur für interne Nutzung (z. B. SMTP-Versand). Nie über die API ausgeben."""
        with self._sf() as s:
            row = s.get(Secret, name)
        if row is None:
            return None
        aad = name.encode()
        dek = _open(self._master, row.wrapped_dek, aad)
        return _open(dek, row.ciphertext, aad).decode()

    def meta(self, name: str) -> dict:
        with self._sf() as s:
            row = s.get(Secret, name)
        if row is None:
            return {"set": False, "updated_at": None}
        return {"set": True, "updated_at": row.updated_at.isoformat()}

    def delete(self, name: str) -> None:
        with self._sf() as s:
            row = s.get(Secret, name)
            if row is not None:
                s.delete(row)
                s.commit()
