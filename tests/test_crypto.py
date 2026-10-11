import os

import pytest
from cryptography.exceptions import InvalidTag
from eth_account import Account

from app.crypto.file_crypto import (
    build_aad,
    ciphertext_hash,
    decrypt_file,
    encrypt_file,
)

OWNER = Account.create()
OTHER = Account.create()
CHAIN = 31337
CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"


def flip(blob: bytes, index: int) -> bytes:
    b = bytearray(blob)
    b[index] ^= 0x01
    return bytes(b)


# ---------- file_crypto ----------

@pytest.fixture
def ctx():
    file_id = os.urandom(32)
    return file_id, build_aad(file_id, OWNER.address)


def test_roundtrip(ctx):
    _, aad = ctx
    data = b"secret report " * 100
    dek, blob = encrypt_file(data, aad)
    assert decrypt_file(dek, blob, aad) == data
    assert data not in blob


def test_empty_file(ctx):
    _, aad = ctx
    dek, blob = encrypt_file(b"", aad)
    assert decrypt_file(dek, blob, aad) == b""


def test_two_encryptions_differ(ctx):
    _, aad = ctx
    dek1, blob1 = encrypt_file(b"same data", aad)
    dek2, blob2 = encrypt_file(b"same data", aad)
    assert dek1 != dek2
    assert blob1 != blob2


def test_wrong_key_fails(ctx):
    _, aad = ctx
    _, blob = encrypt_file(b"data", aad)
    with pytest.raises(InvalidTag):
        decrypt_file(os.urandom(32), blob, aad)


@pytest.mark.parametrize("index", [1, 20, -1])  # IV, ciphertext, tag
def test_modified_blob_fails(ctx, index):
    _, aad = ctx
    dek, blob = encrypt_file(b"x" * 100, aad)
    with pytest.raises(InvalidTag):
        decrypt_file(dek, flip(blob, index), aad)


def test_modified_version_byte_fails(ctx):
    _, aad = ctx
    dek, blob = encrypt_file(b"data", aad)
    with pytest.raises(ValueError):
        decrypt_file(dek, flip(blob, 0), aad)


def test_wrong_context_fails(ctx):
    file_id, aad = ctx
    dek, blob = encrypt_file(b"data", aad)
    other_file = build_aad(os.urandom(32), OWNER.address)
    other_owner = build_aad(file_id, OTHER.address)
    with pytest.raises(InvalidTag):
        decrypt_file(dek, blob, other_file)
    with pytest.raises(InvalidTag):
        decrypt_file(dek, blob, other_owner)


def test_truncated_blob_rejected(ctx):
    _, aad = ctx
    dek, blob = encrypt_file(b"data", aad)
    with pytest.raises(ValueError):
        decrypt_file(dek, blob[:10], aad)


def test_ciphertext_hash_detects_change(ctx):
    _, aad = ctx
    _, blob = encrypt_file(b"data" * 50, aad)
    assert len(ciphertext_hash(blob)) == 32
    assert ciphertext_hash(blob) != ciphertext_hash(flip(blob, 20))


def test_bad_file_id_rejected():
    with pytest.raises(ValueError):
        build_aad(b"short", OWNER.address)