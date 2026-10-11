"""Member 1: encrypted per-user key storage and the owner's file-key vault.

One JSON file per user:
  - signing key: standard Web3 keystore (scrypt), written by eth-account
  - X25519 encryption key: AES-GCM under a key derived from the passphrase
  - vault: file keys (DEKs) the owner needs later, AES-GCM under another derived key
Nothing secret is stored in plaintext.
"""
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from eth_account import Account

from app.config import KEYSTORE_DIR

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
MIN_PASSPHRASE_LEN = 8
_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_AAD_ENC = b"SecureShare x25519 key v1"
_AAD_DEK = b"SecureShare dek v1"


class KeystoreError(Exception):
    pass


class WrongPassphrase(KeystoreError):
    pass


def _path(name: str, directory) -> Path:
    # Only simple names are allowed, so a user name can never become a path.
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise KeystoreError("User name must be 1-32 characters: a-z, 0-9, _ or -")
    folder = Path(directory) if directory else Path(KEYSTORE_DIR)
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{name}.json"


def _write_json(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    try:
        os.chmod(tmp, 0o600)  # owner-only; ignored on Windows
    except OSError:
        pass
    os.replace(tmp, path)


def _read(name: str, directory):
    path = _path(name, directory)
    if not path.exists():
        raise KeystoreError(f"No keystore for user '{name}'")
    with open(path, encoding="utf-8") as f:
        return json.load(f), path


def _master_key(passphrase: str, kdf: dict) -> bytes:
    return Scrypt(
        salt=bytes.fromhex(kdf["salt"]),
        length=32,
        n=kdf["n"],
        r=kdf["r"],
        p=kdf["p"],
    ).derive(passphrase.encode("utf-8"))


def _subkey(master: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(master)


def _require32(name: str, value) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return bytes(value)


def _unlock(rec: dict, passphrase: str):
    """Derive the master key and check the passphrase by decrypting the X25519 key.
    Returns (master_key, raw_x25519_private_key)."""
    if not passphrase:
        raise WrongPassphrase("Passphrase required")
    master = _master_key(passphrase, rec["kdf"])
    enc = rec["encryption_key"]
    try:
        raw = AESGCM(_subkey(master, b"x25519-private-key")).decrypt(
            bytes.fromhex(enc["nonce"]),
            bytes.fromhex(enc["ciphertext"]),
            _AAD_ENC + bytes.fromhex(enc["public"]),
        )
    except InvalidTag as exc:
        raise WrongPassphrase("Wrong passphrase") from exc
    return master, raw


def create_user(name: str, passphrase: str, directory=None) -> dict:
    """Create a new user with fresh signing and encryption keys.
    Returns public info only: name, address, enc_public_key (32 bytes)."""
    path = _path(name, directory)
    if path.exists():
        raise KeystoreError(f"User '{name}' already exists")
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LEN:
        raise KeystoreError(f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

    account = Account.create()
    signing_keystore = Account.encrypt(account.key, passphrase)

    enc_private = X25519PrivateKey.generate()
    enc_raw = enc_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    enc_public = enc_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    kdf = {"name": "scrypt", "salt": os.urandom(16).hex(), "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    master = _master_key(passphrase, kdf)
    nonce = os.urandom(12)
    ciphertext = AESGCM(_subkey(master, b"x25519-private-key")).encrypt(
        nonce, enc_raw, _AAD_ENC + enc_public
    )

    _write_json(
        path,
        {
            "version": 1,
            "name": name,
            "address": account.address,
            "signing_keystore": signing_keystore,
            "kdf": kdf,
            "encryption_key": {
                "public": enc_public.hex(),
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            },
            "vault": {},
        },
    )
    return {"name": name, "address": account.address, "enc_public_key": enc_public}


def user_exists(name: str, directory=None) -> bool:
    return _path(name, directory).exists()


def get_public_info(name: str, directory=None) -> dict:
    """Public data only. No passphrase needed."""
    rec, _ = _read(name, directory)
    return {
        "name": rec["name"],
        "address": rec["address"],
        "enc_public_key": bytes.fromhex(rec["encryption_key"]["public"]),
    }


def load_signing_key(name: str, passphrase: str, directory=None) -> bytes:
    """Return the 32-byte Ethereum private key. Keep it in memory only."""
    rec, _ = _read(name, directory)
    try:
        return bytes(Account.decrypt(rec["signing_keystore"], passphrase))
    except ValueError as exc:
        raise WrongPassphrase("Wrong passphrase") from exc


def load_enc_private_key(name: str, passphrase: str, directory=None) -> X25519PrivateKey:
    """Return the X25519 private key object that Member 3's key unwrapping needs."""
    rec, _ = _read(name, directory)
    _, raw = _unlock(rec, passphrase)
    return X25519PrivateKey.from_private_bytes(raw)


def save_dek(name: str, passphrase: str, file_id: bytes, dek: bytes, directory=None) -> None:
    """Store a file key in the owner's vault, encrypted."""
    file_id = _require32("file_id", file_id)
    dek = _require32("dek", dek)
    rec, path = _read(name, directory)
    master, _ = _unlock(rec, passphrase)  # fails before writing if the passphrase is wrong
    nonce = os.urandom(12)
    ciphertext = AESGCM(_subkey(master, b"dek-vault")).encrypt(nonce, dek, _AAD_DEK + file_id)
    rec["vault"][file_id.hex()] = {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
    _write_json(path, rec)


def load_dek(name: str, passphrase: str, file_id: bytes, directory=None) -> bytes:
    file_id = _require32("file_id", file_id)
    rec, _ = _read(name, directory)
    master, _ = _unlock(rec, passphrase)
    entry = rec["vault"].get(file_id.hex())
    if entry is None:
        raise KeystoreError("No key stored for this file")
    try:
        return AESGCM(_subkey(master, b"dek-vault")).decrypt(
            bytes.fromhex(entry["nonce"]), bytes.fromhex(entry["ciphertext"]), _AAD_DEK + file_id
        )
    except InvalidTag as exc:
        raise KeystoreError("Vault entry is corrupted") from exc


def list_files(name: str, directory=None) -> list:
    """File ids (32-byte values) this user has a key for. No passphrase needed."""
    rec, _ = _read(name, directory)
    return [bytes.fromhex(k) for k in rec["vault"]]