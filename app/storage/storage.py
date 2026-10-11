"""Member 1: simulated cloud storage (an untrusted folder of ciphertext blobs).

The server never sees plaintext or keys. Files are named by a random 32-byte
storage id, so a caller can never choose or traverse a path.
"""
import os
import re
from pathlib import Path

from app.config import BLOB_DIR

MAX_BLOB_BYTES = 120 * 1024 * 1024
_HEX64 = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")


def _normalize(storage_id) -> bytes:
    """Accept 32 raw bytes or a 64-character hex string. Anything else is rejected."""
    if isinstance(storage_id, (bytes, bytearray)) and len(storage_id) == 32:
        return bytes(storage_id)
    if isinstance(storage_id, str) and _HEX64.match(storage_id):
        return bytes.fromhex(storage_id[2:] if storage_id.startswith("0x") else storage_id)
    raise ValueError("storage_id must be 32 bytes or a 64-character hex string")


class StorageClient:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else Path(BLOB_DIR)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, storage_id) -> Path:
        return self.directory / f"{_normalize(storage_id).hex()}.bin"

    def put(self, blob: bytes) -> bytes:
        """Store a blob and return its new random 32-byte storage id."""
        if not isinstance(blob, (bytes, bytearray)) or len(blob) == 0:
            raise ValueError("blob must be non-empty bytes")
        if len(blob) > MAX_BLOB_BYTES:
            raise ValueError("blob is too large")
        storage_id = os.urandom(32)
        path = self._path(storage_id)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "xb") as f:
            f.write(bytes(blob))
        os.replace(tmp, path)
        return storage_id

    def get(self, storage_id) -> bytes:
        path = self._path(storage_id)
        if not path.exists():
            raise FileNotFoundError("No stored file for this id")
        return path.read_bytes()

    def exists(self, storage_id) -> bool:
        return self._path(storage_id).exists()

    def tamper(self, storage_id) -> None:
        """DEMO ONLY: flip one bit in the stored file to show that tampering is detected."""
        path = self._path(storage_id)
        data = bytearray(path.read_bytes())
        data[len(data) // 2] ^= 0x01
        path.write_bytes(bytes(data))