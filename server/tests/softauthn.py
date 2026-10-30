"""Software-Authenticator für Tests: erzeugt echte WebAuthn-Registrierungen ("none") und ES256-Assertions."""
import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str = "vulnwatch.lan", origin: str = "https://vulnwatch.lan:8443"):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.count = 0

    @property
    def id(self) -> str:
        return b64u(self.cred_id)

    def _client_data(self, typ: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def register(self, options: dict) -> dict:
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + self.count.to_bytes(4, "big")
                     + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": self.id, "rawId": self.id, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64u(self._client_data("webauthn.create", options["challenge"], None)),
                             "attestationObject": b64u(att)}}

    def assertion(self, challenge: str, origin: str | None = None, flags: int = 0x05) -> dict:
        self.count += 1
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + self.count.to_bytes(4, "big")
        client_data = self._client_data("webauthn.get", challenge, origin)
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": self.id, "rawId": self.id, "type": "public-key", "clientExtensionResults": {},
                "response": {"authenticatorData": b64u(auth_data), "clientDataJSON": b64u(client_data),
                             "signature": b64u(sig), "userHandle": None}}
