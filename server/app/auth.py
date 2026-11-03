import hashlib
import hmac
import io
import secrets
from collections import defaultdict, deque
from typing import Callable

import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LEN = 12
TOTP_INTERVAL = 30

_hasher = PasswordHasher()
# Wird bei unbekanntem Benutzer geprüft, damit die Antwortzeit nichts über dessen Existenz verrät.
_DUMMY_HASH = _hasher.hash("dummy-passwort-fuer-konstante-zeit")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        _hasher.verify(stored_hash or _DUMMY_HASH, password)
        return stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="LabLantern")


def totp_qr_svg(uri: str) -> str:
    buf = io.BytesIO()
    qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10).save(buf)
    return buf.getvalue().decode()


def match_totp_step(secret: str, code: str, now: float) -> int | None:
    """Zeitschritt, zu dem der Code passt (±1 Schritt Toleranz), sonst None."""
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL)
    current = int(now // TOTP_INTERVAL)
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * TOTP_INTERVAL).encode(), code.encode()):
            return step
    return None


class RateLimiter:
    """Zählt Fehlversuche je Schlüssel im Zeitfenster; ab `max_failures` gesperrt."""

    def __init__(self, clock: Callable[[], float], max_failures: int, window: float):
        self._clock = clock
        self._max = max_failures
        self._window = window
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str) -> deque[float]:
        q = self._failures[key]
        cutoff = self._clock() - self._window
        while q and q[0] <= cutoff:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= self._max

    def retry_after(self, key: str) -> int:
        q = self._prune(key)
        if len(q) < self._max:
            return 0
        return max(1, int(q[0] + self._window - self._clock()))

    def fail(self, key: str) -> None:
        self._prune(key).append(self._clock())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)
