"""Member 1: AES-256-GCM file encryption.

Blob layout (this is what is stored on the untrusted server):
    version (1 byte) | IV (12 bytes) | ciphertext | GCM tag (16 bytes)

The version byte and the context (file id + owner) are authenticated data,
so changing any of them makes decryption fail.
"""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_utils import to_canonical_address

VERSION = b"\x01"
IV_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
MAX_FILE_BYTES = 100 * 1024 * 1024  # the whole file is processed in memory


def build_aad(file_id: bytes, owner_address: str) -> bytes:
    """Context bound into the GCM tag: which file, and whose file."""
    if not isinstance(file_id, (bytes, bytearray)) or len(file_id) != 32:
        raise ValueError("file_id must be exactly 32 bytes")
    return bytes(file_id) + to_canonical_address(owner_address)


def encrypt_file(data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt data with a new random 256-bit key. Returns (dek, blob)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File is too large (limit is 100 MB)")
    dek = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(IV_LEN)  # fresh random 96-bit IV for every file
    ciphertext = AESGCM(dek).encrypt(iv, bytes(data), VERSION + aad)
    return dek, VERSION + iv + ciphertext


def decrypt_file(dek: bytes, blob: bytes, aad: bytes) -> bytes:
    """Decrypt a blob. Raises cryptography.exceptions.InvalidTag if anything
    was modified, and ValueError if the blob is malformed."""
    if len(dek) != KEY_LEN:
        raise ValueError("File key must be 32 bytes")
    if len(blob) < 1 + IV_LEN + TAG_LEN:
        raise ValueError("Stored file is too short")
    if blob[:1] != VERSION:
        raise ValueError("Unsupported file format version")
    iv = blob[1 : 1 + IV_LEN]
    ciphertext = blob[1 + IV_LEN :]
    return AESGCM(dek).decrypt(iv, ciphertext, VERSION + aad)


def ciphertext_hash(blob: bytes) -> bytes:
    """SHA-256 of the stored blob. This is the value committed on chain."""
    return hashlib.sha256(blob).digest()