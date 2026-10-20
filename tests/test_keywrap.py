import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_account import Account
from eth_utils import to_canonical_address

from app.crypto.keywrap import fingerprint, unwrap_key, wrap_key

OWNER = Account.create()
REQUESTER = Account.create()
OTHER = Account.create()


def public_bytes(private_key):
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_context(file_id, owner=OWNER.address, requester=REQUESTER.address):
    """Bind the wrapped key to one file, owner and requester."""
    return (
        file_id
        + to_canonical_address(owner)
        + to_canonical_address(requester)
    )


def test_round_trip():
    private = X25519PrivateKey.generate()
    dek = os.urandom(32)
    context = make_context(os.urandom(32))

    payload = wrap_key(dek, public_bytes(private), context)

    assert len(context) == 72
    assert len(payload) == 92
    assert unwrap_key(payload, private, context) == dek


def test_wrong_private_key_fails():
    private = X25519PrivateKey.generate()
    wrong_private = X25519PrivateKey.generate()
    context = make_context(os.urandom(32))
    payload = wrap_key(os.urandom(32), public_bytes(private), context)

    with pytest.raises(InvalidTag):
        unwrap_key(payload, wrong_private, context)


def test_modified_payload_fails():
    private = X25519PrivateKey.generate()
    context = make_context(os.urandom(32))
    payload = bytearray(wrap_key(os.urandom(32), public_bytes(private), context))
    payload[-1] ^= 0x01

    with pytest.raises(InvalidTag):
        unwrap_key(bytes(payload), private, context)


def test_wrong_context_fails():
    private = X25519PrivateKey.generate()
    file_id = os.urandom(32)
    context = make_context(file_id)
    payload = wrap_key(os.urandom(32), public_bytes(private), context)

    wrong_context = make_context(file_id, requester=OTHER.address)
    with pytest.raises(InvalidTag):
        unwrap_key(payload, private, wrong_context)


def test_short_payload_rejected():
    private = X25519PrivateKey.generate()
    context = make_context(os.urandom(32))

    with pytest.raises(ValueError):
        unwrap_key(b"too short", private, context)


def test_fingerprint_format():
    private = X25519PrivateKey.generate()
    value = fingerprint(public_bytes(private))

    assert len(value) == 14
    assert value[4] == "-" and value[9] == "-"
