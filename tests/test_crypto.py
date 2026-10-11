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
from app.crypto.signing import file_digest, sign_file, verify_file
from app.storage.storage import StorageClient

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


# ---------- signing ----------

def _sign(file_id, ct_hash, storage_id, key=OWNER.key):
    return sign_file(key, CHAIN, CONTRACT, file_id, ct_hash, storage_id)


@pytest.fixture
def reg():
    return os.urandom(32), os.urandom(32), os.urandom(32)  # file_id, ct_hash, storage_id


def _verify(sig, reg, owner=OWNER.address, chain=CHAIN, contract=CONTRACT):
    file_id, ct_hash, storage_id = reg
    return verify_file(owner, sig, chain, contract, file_id, ct_hash, storage_id)


def test_sign_and_verify(reg):
    sig = _sign(*reg)
    assert len(sig) == 65
    assert _verify(sig, reg)


def test_signature_is_deterministic(reg):
    assert _sign(*reg) == _sign(*reg)  # RFC 6979: no random nonce


def test_wrong_owner_fails(reg):
    assert not _verify(_sign(*reg), reg, owner=OTHER.address)


def test_signature_from_other_key_fails(reg):
    sig = _sign(*reg, key=OTHER.key)
    assert not _verify(sig, reg)  # claimed owner is OWNER


@pytest.mark.parametrize("position", [0, 1, 2])  # file_id, ct_hash, storage_id
def test_altered_field_fails(reg, position):
    sig = _sign(*reg)
    changed = list(reg)
    changed[position] = os.urandom(32)
    assert not _verify(sig, tuple(changed))


def test_other_chain_or_contract_fails(reg):
    sig = _sign(*reg)
    assert not _verify(sig, reg, chain=1)
    assert not _verify(sig, reg, contract="0x70997970C51812dc3A010C7d01b50e0d17dc79C8")


def test_garbage_signature_is_false_not_error(reg):
    assert _verify(b"\x00" * 65, reg) is False
    assert _verify(b"short", reg) is False


def test_digest_depends_on_every_input(reg):
    base = file_digest(CHAIN, CONTRACT, reg[0], OWNER.address, reg[1], reg[2])
    assert base != file_digest(CHAIN, CONTRACT, reg[0], OTHER.address, reg[1], reg[2])


# ---------- storage ----------

def test_storage_roundtrip(tmp_path):
    store = StorageClient(tmp_path)
    storage_id = store.put(b"ciphertext bytes")
    assert len(storage_id) == 32
    assert store.get(storage_id) == b"ciphertext bytes"
    assert store.get(storage_id.hex()) == b"ciphertext bytes"  # hex form also works


def test_storage_ids_are_unique(tmp_path):
    store = StorageClient(tmp_path)
    assert store.put(b"a") != store.put(b"a")


def test_storage_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        StorageClient(tmp_path).get(os.urandom(32))


@pytest.mark.parametrize("bad", ["../../etc/passwd", b"short", "zz" * 32, 123, None])
def test_storage_rejects_bad_ids(tmp_path, bad):
    with pytest.raises(ValueError):
        StorageClient(tmp_path).get(bad)


def test_storage_rejects_empty_or_non_bytes(tmp_path):
    store = StorageClient(tmp_path)
    with pytest.raises(ValueError):
        store.put(b"")
    with pytest.raises(ValueError):
        store.put("text")


def test_tamper_changes_blob_and_is_detected(tmp_path):
    file_id = os.urandom(32)
    aad = build_aad(file_id, OWNER.address)
    dek, blob = encrypt_file(b"important" * 20, aad)
    store = StorageClient(tmp_path)
    storage_id = store.put(blob)
    store.tamper(storage_id)
    stored = store.get(storage_id)
    assert ciphertext_hash(stored) != ciphertext_hash(blob)
    with pytest.raises(InvalidTag):
        decrypt_file(dek, stored, aad)