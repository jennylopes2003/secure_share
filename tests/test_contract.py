
"""Local blockchain security tests for FileSharing.sol.

Uses eth-tester and py-evm; no Sepolia RPC or ETH required.
Registration signatures use Member 1's actual sign_file().
"""

from pathlib import Path

import pytest
from eth_tester import EthereumTester, PyEVMBackend
from eth_tester.exceptions import TransactionFailed
from solcx import compile_source, install_solc, set_solc_version
from web3 import EthereumTesterProvider, Web3

from app.crypto.signing import sign_file


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILE = ROOT / "contracts" / "FileSharing.sol"

SOLC_VERSION = "0.8.20"

NONE = 0
PENDING = 1
APPROVED = 2
REJECTED = 3
REVOKED = 4


def value32(number):
    """Produce a distinct bytes32 test value."""
    return number.to_bytes(32, byteorder="big")

BOB_ENC_KEY = value32(4242)

@pytest.fixture(scope="session")
def compiled_contract():
    """Compile the real Solidity source once per test session."""
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)

    source = CONTRACT_FILE.read_text(encoding="utf-8")

    compiled = compile_source(
        source,
        output_values=["abi", "bin"],
    )

    contract_key = next(
        key for key in compiled
        if key.endswith(":FileSharing")
    )

    return compiled[contract_key]


@pytest.fixture
def environment(compiled_contract):
    """Deploy a fresh contract to an isolated local blockchain."""
    backend = PyEVMBackend()
    tester = EthereumTester(backend=backend)
    web3 = Web3(EthereumTesterProvider(tester))

    alice = web3.eth.accounts[0]
    bob = web3.eth.accounts[1]
    mallory = web3.eth.accounts[2]

    factory = web3.eth.contract(
        abi=compiled_contract["abi"],
        bytecode=compiled_contract["bin"],
    )

    tx_hash = factory.constructor().transact({"from": alice})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    assert receipt.status == 1

    contract = web3.eth.contract(
        address=receipt.contractAddress,
        abi=compiled_contract["abi"],
    )

    return {
        "web3": web3,
        "tester": tester,
        "backend": backend,
        "contract": contract,
        "alice": alice,
        "bob": bob,
        "mallory": mallory,
        "alice_key": backend.account_keys[0].to_bytes(),
        "bob_key": backend.account_keys[1].to_bytes(),
        "mallory_key": backend.account_keys[2].to_bytes(),
        "file_id": value32(1),
        "ct_hash": value32(2),
        "storage_id": value32(3),
    }


def register_file(
    env,
    *,
    sender=None,
    private_key=None,
    file_id=None,
    ct_hash=None,
    storage_id=None,
):
    """Register using the real Python sign_file implementation."""
    sender = sender or env["alice"]
    private_key = private_key or env["alice_key"]
    file_id = file_id or env["file_id"]
    ct_hash = ct_hash or env["ct_hash"]
    storage_id = storage_id or env["storage_id"]

    signature = sign_file(
        private_key,
        env["web3"].eth.chain_id,
        env["contract"].address,
        file_id,
        ct_hash,
        storage_id,
    )

    tx_hash = env["contract"].functions.registerFile(
        file_id,
        ct_hash,
        storage_id,
        signature,
    ).transact({"from": sender})

    receipt = env["web3"].eth.wait_for_transaction_receipt(tx_hash)

    assert receipt.status == 1

    return receipt, signature


def request_file(env):
    """Create a pending request from Bob."""
    tx_hash = env["contract"].functions.requestAccess(
        env["file_id"],
        BOB_ENC_KEY,
    ).transact({"from": env["bob"]})

    return env["web3"].eth.wait_for_transaction_receipt(tx_hash)


def approve_file(env, wrapped_key=b"encrypted-key-for-bob"):
    """Approve Bob's request as Alice."""
    tx_hash = env["contract"].functions.approveRequest(
        env["file_id"],
        env["bob"],
        wrapped_key,
    ).transact({"from": env["alice"]})

    return env["web3"].eth.wait_for_transaction_receipt(tx_hash)


def event_args(contract, event_name, receipt):
    """Decode the event from a transaction receipt."""
    event_factory = getattr(contract.events, event_name)
    events = event_factory().process_receipt(receipt)
    assert len(events) == 1
    return events[0]["args"]


# -------------------------------------------------------
# Registration and signature verification
# -------------------------------------------------------


def test_valid_signature_registers_file(environment):
    env = environment
    receipt, signature = register_file(env)

    record = env["contract"].functions.getFile(
        env["file_id"]
    ).call()

    assert record[0] == env["alice"]
    assert record[1] == env["ct_hash"]
    assert record[2] == env["storage_id"]
    assert record[3] == signature
    assert record[4] > 0

    args = event_args(
        env["contract"],
        "FileRegistered",
        receipt,
    )

    assert args["fileId"] == env["file_id"]
    assert args["owner"] == env["alice"]
    assert args["ctHash"] == env["ct_hash"]
    assert args["storageId"] == env["storage_id"]


def test_duplicate_file_id_reverts(environment):
    env = environment
    register_file(env)

    signature = sign_file(
        env["alice_key"],
        env["web3"].eth.chain_id,
        env["contract"].address,
        env["file_id"],
        env["ct_hash"],
        env["storage_id"],
    )

    with pytest.raises(TransactionFailed, match="File already registered"):
        env["contract"].functions.registerFile(
            env["file_id"],
            env["ct_hash"],
            env["storage_id"],
            signature,
        ).transact({"from": env["alice"]})


def test_tampered_signature_reverts(environment):
    env = environment

    signature = bytearray(
        sign_file(
            env["alice_key"],
            env["web3"].eth.chain_id,
            env["contract"].address,
            env["file_id"],
            env["ct_hash"],
            env["storage_id"],
        )
    )

    signature[0] ^= 1

    with pytest.raises(TransactionFailed):
        env["contract"].functions.registerFile(
            env["file_id"],
            env["ct_hash"],
            env["storage_id"],
            bytes(signature),
        ).transact({"from": env["alice"]})


def test_tampered_ciphertext_hash_reverts(environment):
    env = environment

    signature = sign_file(
        env["alice_key"],
        env["web3"].eth.chain_id,
        env["contract"].address,
        env["file_id"],
        env["ct_hash"],
        env["storage_id"],
    )

    with pytest.raises(TransactionFailed, match="Invalid file signature"):
        env["contract"].functions.registerFile(
            env["file_id"],
            value32(999),
            env["storage_id"],
            signature,
        ).transact({"from": env["alice"]})


def test_signature_from_wrong_owner_reverts(environment):
    env = environment

    signature = sign_file(
        env["alice_key"],
        env["web3"].eth.chain_id,
        env["contract"].address,
        env["file_id"],
        env["ct_hash"],
        env["storage_id"],
    )

    with pytest.raises(TransactionFailed, match="Invalid file signature"):
        env["contract"].functions.registerFile(
            env["file_id"],
            env["ct_hash"],
            env["storage_id"],
            signature,
        ).transact({"from": env["mallory"]})


def test_signature_for_wrong_chain_reverts(environment):
    env = environment

    signature = sign_file(
        env["alice_key"],
        env["web3"].eth.chain_id + 1,
        env["contract"].address,
        env["file_id"],
        env["ct_hash"],
        env["storage_id"],
    )

    with pytest.raises(TransactionFailed, match="Invalid file signature"):
        env["contract"].functions.registerFile(
            env["file_id"],
            env["ct_hash"],
            env["storage_id"],
            signature,
        ).transact({"from": env["alice"]})


# -------------------------------------------------------
# Access requests
# -------------------------------------------------------


def test_request_unknown_file_reverts(environment):
    env = environment

    with pytest.raises(TransactionFailed, match="File does not exist"):
        env["contract"].functions.requestAccess(
            value32(777),
            BOB_ENC_KEY,
        ).transact({"from": env["bob"]})


def test_owner_cannot_request_own_file(environment):
    env = environment
    register_file(env)

    with pytest.raises(
        TransactionFailed,
        match="Owner cannot request own file",
    ):
        env["contract"].functions.requestAccess(
            env["file_id"],
            BOB_ENC_KEY,
        ).transact({"from": env["alice"]})


def test_request_succeeds_and_emits_event(environment):
    env = environment
    register_file(env)

    receipt = request_file(env)

    assert env["contract"].functions.getStatus(
        env["file_id"],
        env["bob"],
    ).call() == PENDING

    args = event_args(
        env["contract"],
        "AccessRequested",
        receipt,
    )

    assert args["fileId"] == env["file_id"]
    assert args["requester"] == env["bob"]
    assert args["encPubKey"] == BOB_ENC_KEY


def test_duplicate_pending_request_reverts(environment):
    env = environment
    register_file(env)
    request_file(env)

    with pytest.raises(TransactionFailed, match="Request already exists"):
        env["contract"].functions.requestAccess(
            env["file_id"],
            BOB_ENC_KEY,
        ).transact({"from": env["bob"]})


def test_zero_encryption_key_reverts(environment):
    env = environment
    register_file(env)

    with pytest.raises(TransactionFailed, match="Invalid encryption key"):
        env["contract"].functions.requestAccess(
            env["file_id"],
            b"\x00" * 32,
        ).transact({"from": env["bob"]})


def test_owner_can_read_requester_encryption_key(environment):
    env = environment
    register_file(env)
    request_file(env)

    stored = env["contract"].functions.getEncPubKey(
        env["file_id"],
        env["bob"],
    ).call()

    assert stored == BOB_ENC_KEY


def test_encryption_key_without_request_reverts(environment):
    env = environment
    register_file(env)

    with pytest.raises(TransactionFailed, match="Request does not exist"):
        env["contract"].functions.getEncPubKey(
            env["file_id"],
            env["bob"],
        ).call()
# -------------------------------------------------------
# Owner-only decisions
# -------------------------------------------------------


def test_non_owner_cannot_approve(environment):
    env = environment
    register_file(env)
    request_file(env)

    with pytest.raises(TransactionFailed, match="Not file owner"):
        env["contract"].functions.approveRequest(
            env["file_id"],
            env["bob"],
            b"secret",
        ).transact({"from": env["mallory"]})

    assert env["contract"].functions.getStatus(
        env["file_id"], env["bob"]
    ).call() == PENDING


def test_non_owner_cannot_reject(environment):
    env = environment
    register_file(env)
    request_file(env)

    with pytest.raises(TransactionFailed, match="Not file owner"):
        env["contract"].functions.rejectRequest(
            env["file_id"],
            env["bob"],
        ).transact({"from": env["mallory"]})

    assert env["contract"].functions.getStatus(
        env["file_id"], env["bob"]
    ).call() == PENDING


def test_non_owner_cannot_revoke(environment):
    env = environment
    register_file(env)
    request_file(env)
    approve_file(env)

    with pytest.raises(TransactionFailed, match="Not file owner"):
        env["contract"].functions.revokeAccess(
            env["file_id"],
            env["bob"],
        ).transact({"from": env["mallory"]})

    assert env["contract"].functions.getStatus(
        env["file_id"], env["bob"]
    ).call() == APPROVED


def test_owner_approves_and_stores_payload(environment):
    env = environment
    register_file(env)
    request_file(env)

    wrapped_key = b"encrypted-key-for-bob"
    receipt = approve_file(env, wrapped_key)

    assert env["contract"].functions.getStatus(
        env["file_id"], env["bob"]
    ).call() == APPROVED

    retrieved_key = env["contract"].functions.getWrappedKey(
        env["file_id"]
    ).call({"from": env["bob"]})

    assert retrieved_key == wrapped_key

    args = event_args(
        env["contract"],
        "AccessApproved",
        receipt,
    )

    assert args["fileId"] == env["file_id"]
    assert args["owner"] == env["alice"]
    assert args["requester"] == env["bob"]


def test_unapproved_user_cannot_get_wrapped_key(environment):
    env = environment
    register_file(env)
    request_file(env)
    approve_file(env)

    with pytest.raises(TransactionFailed, match="Access is not approved"):
        env["contract"].functions.getWrappedKey(
            env["file_id"]
        ).call({"from": env["mallory"]})


def test_empty_approval_payload_reverts(environment):
    env = environment
    register_file(env)
    request_file(env)

    with pytest.raises(
        TransactionFailed,
        match="Wrapped key cannot be empty",
    ):
        env["contract"].functions.approveRequest(
            env["file_id"],
            env["bob"],
            b"",
        ).transact({"from": env["alice"]})


def test_owner_rejects_and_emits_event(environment):
    env = environment
    register_file(env)
    request_file(env)

    tx_hash = env["contract"].functions.rejectRequest(
        env["file_id"],
        env["bob"],
    ).transact({"from": env["alice"]})

    receipt = env["web3"].eth.wait_for_transaction_receipt(tx_hash)

    assert env["contract"].functions.getStatus(
        env["file_id"], env["bob"]
    ).call() == REJECTED

    args = event_args(
        env["contract"],
        "AccessRejected",
        receipt,
    )

    assert args["fileId"] == env["file_id"]
    assert args["owner"] == env["alice"]
    assert args["requester"] == env["bob"]


def test_cannot_approve_already_approved_request(environment):
    env = environment
    register_file(env)
    request_file(env)
    approve_file(env)

    with pytest.raises(TransactionFailed, match="Request is not pending"):
        env["contract"].functions.approveRequest(
            env["file_id"],
            env["bob"],
            b"another-key",
        ).transact({"from": env["alice"]})


def test_cannot_reject_already_approved_request(environment):
    env = environment
    register_file(env)
    request_file(env)
    approve_file(env)

    with pytest.raises(TransactionFailed, match="Request is not pending"):
        env["contract"].functions.rejectRequest(
            env["file_id"],
            env["bob"],
        ).transact({"from": env["alice"]})


def test_cannot_approve_already_rejected_request(environment):
    env = environment
    register_file(env)
    request_file(env)

    env["contract"].functions.rejectRequest(
        env["file_id"],
        env["bob"],
    ).transact({"from": env["alice"]})

    with pytest.raises(TransactionFailed, match="Request is not pending"):
        env["contract"].functions.approveRequest(
            env["file_id"],
            env["bob"],
            b"secret",
        ).transact({"from": env["alice"]})


def test_owner_revokes_and_emits_event(environment):
    env = environment
    register_file(env)
    request_file(env)
    approve_file(env)

    tx_hash = env["contract"].functions.revokeAccess(
        env["file_id"],
        env["bob"],
    ).transact({"from": env["alice"]})

    receipt = env["web3"].eth.wait_for_transaction_receipt(tx_hash)

    assert env["contract"].functions.getStatus(
        env["file_id"], env["bob"]
    ).call() == REVOKED

    with pytest.raises(TransactionFailed, match="Access is not approved"):
        env["contract"].functions.getWrappedKey(
            env["file_id"]
        ).call({"from": env["bob"]})

    args = event_args(
        env["contract"],
        "AccessRevoked",
        receipt,
    )

    assert args["fileId"] == env["file_id"]
    assert args["owner"] == env["alice"]
    assert args["requester"] == env["bob"]


def test_cannot_revoke_pending_request(environment):
    env = environment
    register_file(env)
    request_file(env)

    with pytest.raises(TransactionFailed, match="Request is not approved"):
        env["contract"].functions.revokeAccess(
            env["file_id"],
            env["bob"],
        ).transact({"from": env["alice"]})


def test_cannot_revoke_twice(environment):
    env = environment
    register_file(env)
    request_file(env)
    approve_file(env)

    env["contract"].functions.revokeAccess(
        env["file_id"],
        env["bob"],
    ).transact({"from": env["alice"]})

    with pytest.raises(TransactionFailed, match="Request is not approved"):
        env["contract"].functions.revokeAccess(
            env["file_id"],
            env["bob"],
        ).transact({"from": env["alice"]})


def test_request_information_timestamps(environment):
    env = environment
    register_file(env)
    request_file(env)

    status, requested_at, updated_at = (
        env["contract"].functions.getRequest(
            env["file_id"],
            env["bob"],
        ).call()
    )

    assert status == PENDING
    assert requested_at > 0
    assert updated_at >= requested_at

def test_client_signs_transactions_with_different_user_keys(
    environment,
    tmp_path,
):
    """Alice registers and Bob requests using separate private keys."""
    import json

    from app.blockchain.contract_client import (
        FileSharingContractClient,
    )

    env = environment
    web3 = env["web3"]
    contract = env["contract"]

    # Build a temporary deployment configuration for the local chain.
    # Do not modify the real Sepolia contract_data.json.
    config_path = tmp_path / "local_contract_data.json"

    config_path.write_text(
        json.dumps(
            {
                "contractName": "FileSharing",
                "abi": contract.abi,
                "address": contract.address,
                "chain_id": web3.eth.chain_id,
                "network": "local-test",
            }
        ),
        encoding="utf-8",
    )

    client = FileSharingContractClient(
        web3=web3,
        private_key=env["alice_key"],
        contract_data_file=config_path,
    )

    assert client.get_account_address() == env["alice"]

    # Alice signs the file registration using Member 1's sign_file().
    signature = sign_file(
        env["alice_key"],
        web3.eth.chain_id,
        contract.address,
        env["file_id"],
        env["ct_hash"],
        env["storage_id"],
    )

    registration_receipt = client.register_file(
        env["file_id"],
        env["ct_hash"],
        env["storage_id"],
        signature,
    )

    assert registration_receipt.status == 1
    assert client.get_file(env["file_id"])[0] == env["alice"]

    # Bob signs his own request, overriding Alice's default key.
    request_receipt = client.request_access(
        env["file_id"],
        BOB_ENC_KEY,
        private_key=env["bob_key"],
    )

    assert request_receipt.status == 1
    assert client.get_status(env["file_id"], env["bob"]) == PENDING
    assert client.get_enc_pub_key(env["file_id"], env["bob"]) == BOB_ENC_KEY

    # The default account remains Alice.
    assert client.get_account_address() == env["alice"]

    # Mallory cannot approve Bob's request.
    with pytest.raises(TransactionFailed, match="Not file owner"):
        client.approve_request(
            env["file_id"],
            env["bob"],
            b"encrypted-key-for-bob",
            private_key=env["mallory_key"],
        )

    # Alice can approve the request with her own key.
    approval_receipt = client.approve_request(
        env["file_id"],
        env["bob"],
        b"encrypted-key-for-bob",
    )

    assert approval_receipt.status == 1
    assert client.has_access(env["file_id"], env["bob"])

    assert client.get_wrapped_key(
        env["file_id"],
        requester=env["bob"],
    ) == b"encrypted-key-for-bob"

    # Alice can revoke Bob's access.
    revoke_receipt = client.revoke_access(
        env["file_id"],
        env["bob"],
    )

    assert revoke_receipt.status == 1
    assert not client.has_access(env["file_id"], env["bob"])
