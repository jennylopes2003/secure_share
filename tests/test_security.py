"""Security and abuse-case tests for SecureShare.

These tests focus on failure behaviour: tampering, incorrect identities/keys,
wrong key-wrapping context, revocation, repeated decisions and bad passphrases.
"""

import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_tester import EthereumTester, PyEVMBackend
from eth_tester.exceptions import TransactionFailed
from solcx import compile_source, install_solc, set_solc_version
from web3 import EthereumTesterProvider, Web3

import app.crypto.keystore as keystore_module
import app.storage.storage as storage_module
from app.blockchain.contract_client import FileSharingContractClient
from app.crypto.file_crypto import build_aad, ciphertext_hash, encrypt_file
from app.crypto.keystore import (
    WrongPassphrase,
    create_user,
    get_public_info,
    load_signing_key,
)
from app.crypto.keywrap import unwrap_key, wrap_key
from app.crypto.signing import sign_file
from app.storage.storage import StorageClient
from app.workflow import (
    approve,
    fetch_verify_decrypt,
    protect_and_register,
    request_access,
    revoke,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILE = ROOT / "contracts" / "FileSharing.sol"
SOLC_VERSION = "0.8.20"

ALICE_PASS = "alice-test-pass"
BOB_PASS = "bob-test-pass"
MALLORY_PASS = "mallory-test-pass"


@pytest.fixture(scope="session")
def compiled_contract():
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)
    source = CONTRACT_FILE.read_text(encoding="utf-8")
    compiled = compile_source(source, output_values=["abi", "bin"])
    key = next(key for key in compiled if key.endswith(":FileSharing"))
    return compiled[key]


@pytest.fixture
def secure_env(tmp_path, monkeypatch, compiled_contract):
    keystore_dir = tmp_path / "keystores"
    blob_dir = tmp_path / "blobs"
    monkeypatch.setattr(keystore_module, "KEYSTORE_DIR", keystore_dir)
    monkeypatch.setattr(storage_module, "BLOB_DIR", blob_dir)

    backend = PyEVMBackend()
    tester = EthereumTester(backend=backend)
    web3 = Web3(EthereumTesterProvider(tester))

    factory = web3.eth.contract(
        abi=compiled_contract["abi"],
        bytecode=compiled_contract["bin"],
    )
    tx_hash = factory.constructor().transact({"from": web3.eth.accounts[0]})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    contract_data = tmp_path / "contract_data.test.json"
    contract_data.write_text(
        json.dumps(
            {
                "address": receipt.contractAddress,
                "chain_id": web3.eth.chain_id,
                "abi": compiled_contract["abi"],
            }
        ),
        encoding="utf-8",
    )

    client = FileSharingContractClient(
        web3=web3,
        contract_data_file=contract_data,
    )

    create_user("alice", ALICE_PASS)
    create_user("bob", BOB_PASS)
    create_user("mallory", MALLORY_PASS)

    users = {
        "alice": get_public_info("alice"),
        "bob": get_public_info("bob"),
        "mallory": get_public_info("mallory"),
    }

    for info in users.values():
        tx_hash = web3.eth.send_transaction(
            {
                "from": web3.eth.accounts[0],
                "to": info["address"],
                "value": web3.to_wei(5, "ether"),
            }
        )
        web3.eth.wait_for_transaction_receipt(tx_hash)

    return {
        "client": client,
        "web3": web3,
        "users": users,
        "blob_dir": blob_dir,
    }


def approved_file(env, plaintext=b"security test file"):
    client = env["client"]
    bob = env["users"]["bob"]["address"]

    created = protect_and_register(
        client, "alice", ALICE_PASS, plaintext
    )
    assert created.ok, created.error
    file_id = created.data["file_id"]

    requested = request_access(client, "bob", BOB_PASS, file_id)
    assert requested.ok, requested.error

    accepted = approve(
        client, "alice", ALICE_PASS, file_id, bob
    )
    assert accepted.ok, accepted.error

    return file_id, plaintext


def test_modified_stored_file_is_refused(secure_env):
    file_id, _ = approved_file(secure_env)
    client = secure_env["client"]

    storage_id = client.get_file(file_id)[2]
    StorageClient().tamper(storage_id)

    result = fetch_verify_decrypt(
        client, "bob", BOB_PASS, file_id
    )

    assert not result.ok
    assert "hash" in result.error.lower()


def test_wrong_signer_cannot_register_as_another_user(secure_env):
    client = secure_env["client"]
    alice = secure_env["users"]["alice"]["address"]
    mallory_key = load_signing_key("mallory", MALLORY_PASS)

    file_id = os.urandom(32)
    aad = build_aad(file_id, alice)
    _dek, blob = encrypt_file(b"wrong signer", aad)
    ct_hash = ciphertext_hash(blob)
    storage_id = StorageClient().put(blob)

    # Mallory signs metadata that claims Alice's ownership context.
    signature = sign_file(
        mallory_key,
        client.get_chain_id(),
        client.get_contract_address(),
        file_id,
        ct_hash,
        storage_id,
    )

    alice_key = load_signing_key("alice", ALICE_PASS)

    with pytest.raises(TransactionFailed):
        client.register_file(
            file_id,
            ct_hash,
            storage_id,
            signature,
            private_key=alice_key,
        )


def test_wrong_x25519_private_key_cannot_unwrap():
    requester_private = X25519PrivateKey.generate()
    requester_public = requester_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    wrong_private = X25519PrivateKey.generate()

    dek = os.urandom(32)
    context = os.urandom(72)
    payload = wrap_key(dek, requester_public, context)

    with pytest.raises(InvalidTag):
        unwrap_key(payload, wrong_private, context)


def test_wrapped_key_with_wrong_context_is_refused():
    requester_private = X25519PrivateKey.generate()
    requester_public = requester_private.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    dek = os.urandom(32)
    correct_context = os.urandom(72)
    wrong_context = os.urandom(72)
    payload = wrap_key(dek, requester_public, correct_context)

    with pytest.raises(InvalidTag):
        unwrap_key(payload, requester_private, wrong_context)


def test_revoked_user_loses_on_chain_access(secure_env):
    file_id, _ = approved_file(secure_env)
    client = secure_env["client"]
    bob = secure_env["users"]["bob"]["address"]

    revoked = revoke(
        client, "alice", ALICE_PASS, file_id, bob
    )
    assert revoked.ok, revoked.error
    assert client.has_access(file_id, bob) is False

    with pytest.raises(TransactionFailed):
        client.get_wrapped_key(file_id, requester=bob)


def test_double_decision_is_rejected(secure_env):
    client = secure_env["client"]
    bob = secure_env["users"]["bob"]["address"]

    created = protect_and_register(
        client, "alice", ALICE_PASS, b"double decision"
    )
    assert created.ok, created.error
    file_id = created.data["file_id"]

    requested = request_access(client, "bob", BOB_PASS, file_id)
    assert requested.ok, requested.error

    first = approve(
        client, "alice", ALICE_PASS, file_id, bob
    )
    assert first.ok, first.error

    second = approve(
        client, "alice", ALICE_PASS, file_id, bob
    )
    assert not second.ok
    assert (
        "pending" in second.error.lower()
        or "request" in second.error.lower()
    )


def test_wrong_passphrase_fails_cleanly(secure_env):
    client = secure_env["client"]

    result = protect_and_register(
        client,
        "alice",
        "definitely-the-wrong-passphrase",
        b"wrong passphrase test",
    )

    assert not result.ok
    assert "passphrase" in result.error.lower()
