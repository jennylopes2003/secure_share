import os
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.crypto.keywrap import wrap_key, unwrap_key

OWNER = '0x' + '11' * 20
REQUESTER = '0x' + '22' * 20

def setup():
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    file_id, dek = os.urandom(32), os.urandom(32)
    payload = wrap_key(dek, public, file_id, OWNER, REQUESTER)
    return private, public, file_id, dek, payload

def test_roundtrip():
    private, _, file_id, dek, payload = setup()
    assert unwrap_key(payload, private, file_id, OWNER, REQUESTER) == dek

def test_wrong_recipient():
    _, _, file_id, _, payload = setup()
    with pytest.raises(InvalidTag):
        unwrap_key(payload, X25519PrivateKey.generate(), file_id, OWNER, REQUESTER)

@pytest.mark.parametrize('changed', ['file', 'owner', 'requester'])
def test_context_binding(changed):
    private, _, file_id, _, payload = setup()
    with pytest.raises(InvalidTag):
        unwrap_key(payload, private, os.urandom(32) if changed == 'file' else file_id,
                   '0x' + '33'*20 if changed == 'owner' else OWNER,
                   '0x' + '44'*20 if changed == 'requester' else REQUESTER)

@pytest.mark.parametrize('index', [1, 33, 45, -1])
def test_tampering(index):
    private, _, file_id, _, payload = setup()
    altered = bytearray(payload)
    altered[index] ^= 1
    with pytest.raises((InvalidTag, ValueError)):
        unwrap_key(bytes(altered), private, file_id, OWNER, REQUESTER)

def test_fresh_ephemeral_keys():
    _, public, file_id, dek, payload = setup()
    assert payload != wrap_key(dek, public, file_id, OWNER, REQUESTER)

def test_bad_input():
    private, public, file_id, dek, payload = setup()
    with pytest.raises(ValueError):
        wrap_key(b'short', public, file_id, OWNER, REQUESTER)
    with pytest.raises(ValueError):
        unwrap_key(payload[:-1], private, file_id, OWNER, REQUESTER)
