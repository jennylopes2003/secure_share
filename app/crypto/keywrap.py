"""Member 3: wrap a file key for one approved requester."""
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PAYLOAD_LEN = 92


def _require_bytes(name: str, value, length: int | None = None) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} must be bytes")
    value = bytes(value)
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def fingerprint(pub: bytes) -> str:
    """Return a short fingerprint so a public key can be checked by eye."""
    pub = _require_bytes("public key", pub, 32)
    short = hashlib.sha256(pub).hexdigest()[:12].upper()
    return "-".join(short[i:i + 4] for i in range(0, 12, 4))


def wrap_key(dek: bytes, requester_pub: bytes, context: bytes) -> bytes:
    """Wrap a 32-byte file key for the requester."""
    dek = _require_bytes("dek", dek, 32)
    requester_pub = _require_bytes("requester_pub", requester_pub, 32)
    context = _require_bytes("context", context, 72)

    requester_key = X25519PublicKey.from_public_bytes(requester_pub)

    # A new temporary key is used for each wrapped file key.
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    shared_secret = ephemeral_private.exchange(requester_key)

    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared_secret)

    nonce = os.urandom(12)
    encrypted_dek = AESGCM(wrapping_key).encrypt(nonce, dek, context)
    return ephemeral_public + nonce + encrypted_dek


def unwrap_key(payload: bytes, my_priv: X25519PrivateKey, context: bytes) -> bytes:
    """Open a wrapped file key with the requester's private key."""
    payload = _require_bytes("payload", payload, PAYLOAD_LEN)
    context = _require_bytes("context", context, 72)
    if not isinstance(my_priv, X25519PrivateKey):
        raise TypeError("my_priv must be an X25519PrivateKey")

    ephemeral_public = payload[:32]
    nonce = payload[32:44]
    encrypted_dek = payload[44:]

    ephemeral_key = X25519PublicKey.from_public_bytes(ephemeral_public)
    shared_secret = my_priv.exchange(ephemeral_key)

    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared_secret)

    return AESGCM(wrapping_key).decrypt(nonce, encrypted_dek, context)
