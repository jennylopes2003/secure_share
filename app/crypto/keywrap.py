"""Share a file key with a specific requester.

The wrapped key contains a version byte, a temporary public key, a nonce,
and the encrypted file key. The caller must verify who owns the requester's
public key before using it.
"""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION = b"\x01"
DOMAIN = b"SecureShare.KeyWrap.v1"
PAYLOAD_LENGTH = 1 + 32 + 12 + 32 + 16


def _context(file_id: bytes, owner_address: str, requester_address: str) -> bytes:
    from eth_utils import to_canonical_address
    if not isinstance(file_id, bytes) or len(file_id) != 32:
        raise ValueError("file_id must be 32 bytes")
    return DOMAIN + file_id + to_canonical_address(owner_address) + to_canonical_address(requester_address)


def _derive(shared_secret: bytes, context: bytes, ephemeral_public: bytes, recipient_public: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=context + ephemeral_public + recipient_public).derive(shared_secret)


def wrap_key(dek: bytes, recipient_public_key: bytes, file_id: bytes,
             owner_address: str, requester_address: str) -> bytes:
    """Encrypt a file key using the requester's public key."""
    if not isinstance(dek, bytes) or len(dek) != 32:
        raise ValueError("dek must be 32 bytes")
    if not isinstance(recipient_public_key, bytes) or len(recipient_public_key) != 32:
        raise ValueError("recipient_public_key must be 32 bytes")
    context = _context(file_id, owner_address, requester_address)
    recipient = X25519PublicKey.from_public_bytes(recipient_public_key)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = ephemeral.exchange(recipient)
    key = _derive(shared, context, ephemeral_public, recipient_public_key)
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, dek, context + ephemeral_public + recipient_public_key)
    return VERSION + ephemeral_public + nonce + encrypted


def unwrap_key(payload: bytes, recipient_private_key: X25519PrivateKey,
               file_id: bytes, owner_address: str, requester_address: str) -> bytes:
    """Recover the file key using the requester's private key."""
    if not isinstance(payload, bytes) or len(payload) != PAYLOAD_LENGTH:
        raise ValueError("invalid wrapped-key payload length")
    if payload[:1] != VERSION:
        raise ValueError("unsupported wrapped-key version")
    if not isinstance(recipient_private_key, X25519PrivateKey):
        raise TypeError("recipient_private_key must be X25519PrivateKey")
    context = _context(file_id, owner_address, requester_address)
    ephemeral_public = payload[1:33]
    nonce = payload[33:45]
    ciphertext = payload[45:]
    recipient_public = recipient_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = recipient_private_key.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    key = _derive(shared, context, ephemeral_public, recipient_public)
    return AESGCM(key).decrypt(nonce, ciphertext, context + ephemeral_public + recipient_public)
