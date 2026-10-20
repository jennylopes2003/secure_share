"""Run the main SecureShare flow on an in-process Ethereum test chain.

This is a demonstration script, not a Sepolia deployment. It creates temporary
users and storage, deploys the real FileSharing contract, then runs the expected
Alice/Bob/Mallory flow through app.workflow.
"""

import json
import tempfile
from pathlib import Path

from eth_tester import EthereumTester, PyEVMBackend
from solcx import compile_source, install_solc, set_solc_version
from web3 import EthereumTesterProvider, Web3

import app.crypto.keystore as keystore_module
import app.storage.storage as storage_module
from app.blockchain.contract_client import FileSharingContractClient
from app.crypto.keystore import create_user, get_public_info, load_signing_key
from app.workflow import (
    approve,
    demo_tamper,
    fetch_verify_decrypt,
    protect_and_register,
    request_access,
    revoke,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILE = ROOT / "contracts" / "FileSharing.sol"
SOLC_VERSION = "0.8.20"

ALICE_PASS = "alice-demo-pass"
BOB_PASS = "bob-demo-pass"
MALLORY_PASS = "mallory-demo-pass"


def check(result, label):
    if not result.ok:
        raise RuntimeError(f"{label} failed: {result.error}")
    print(f"[OK] {label}")
    for step in result.steps:
        print(f"     {'OK' if step.ok else 'FAIL'} - {step.name}: {step.detail}")
    return result


def deploy_test_contract(temp_dir):
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)

    source = CONTRACT_FILE.read_text(encoding="utf-8")
    compiled = compile_source(source, output_values=["abi", "bin"])
    contract_key = next(key for key in compiled if key.endswith(":FileSharing"))
    artifact = compiled[contract_key]

    backend = PyEVMBackend()
    tester = EthereumTester(backend=backend)
    web3 = Web3(EthereumTesterProvider(tester))

    factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bin"])
    tx_hash = factory.constructor().transact({"from": web3.eth.accounts[0]})
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    contract_data = Path(temp_dir) / "contract_data.test.json"
    contract_data.write_text(
        json.dumps(
            {
                "address": receipt.contractAddress,
                "chain_id": web3.eth.chain_id,
                "abi": artifact["abi"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    client = FileSharingContractClient(
        web3=web3,
        contract_data_file=contract_data,
    )
    return client, web3


def fund_user(web3, address):
    tx_hash = web3.eth.send_transaction(
        {
            "from": web3.eth.accounts[0],
            "to": address,
            "value": web3.to_wei(5, "ether"),
        }
    )
    web3.eth.wait_for_transaction_receipt(tx_hash)


def main():
    with tempfile.TemporaryDirectory(prefix="secureshare-smoke-") as temp:
        temp = Path(temp)

        # Keep the smoke test separate from normal project data.
        keystore_module.KEYSTORE_DIR = temp / "keystores"
        storage_module.BLOB_DIR = temp / "blobs"

        client, web3 = deploy_test_contract(temp)

        create_user("alice", ALICE_PASS)
        create_user("bob", BOB_PASS)
        create_user("mallory", MALLORY_PASS)

        alice = get_public_info("alice")["address"]
        bob = get_public_info("bob")["address"]
        mallory = get_public_info("mallory")["address"]

        for address in (alice, bob, mallory):
            fund_user(web3, address)

        plaintext = b"SecureShare smoke test: Bob should receive this exact message."

        created = check(
            protect_and_register(client, "alice", ALICE_PASS, plaintext),
            "Alice protects and registers the file",
        )
        file_id = created.data["file_id"]

        check(
            request_access(client, "bob", BOB_PASS, file_id),
            "Bob requests access",
        )

        # Mallory is not the file owner, so approval must fail.
        mallory_attempt = approve(
            client, "mallory", MALLORY_PASS, file_id, bob
        )
        assert not mallory_attempt.ok, "Mallory must not be able to approve Bob"
        print(f"[OK] Mallory approval refused: {mallory_attempt.error}")

        check(
            approve(client, "alice", ALICE_PASS, file_id, bob),
            "Alice approves Bob",
        )

        fetched = check(
            fetch_verify_decrypt(client, "bob", BOB_PASS, file_id),
            "Bob verifies and decrypts the file",
        )
        assert fetched.data["plaintext"] == plaintext
        print("[OK] Bob's plaintext matches the original")

        check(demo_tamper(client, file_id), "Tamper with stored ciphertext")

        tampered = fetch_verify_decrypt(client, "bob", BOB_PASS, file_id)
        assert not tampered.ok
        assert "hash" in tampered.error.lower()
        print(f"[OK] Tampered file refused: {tampered.error}")

        check(
            revoke(client, "alice", ALICE_PASS, file_id, bob),
            "Alice revokes Bob",
        )

        assert not client.has_access(file_id, bob)
        print("[OK] Bob's approved status is gone")

        try:
            client.get_wrapped_key(file_id, requester=bob)
        except Exception:
            print("[OK] Bob can no longer retrieve the wrapped key")
        else:
            raise AssertionError("Revoked Bob unexpectedly retrieved a wrapped key")

        print("\nSmoke test completed successfully.")


if __name__ == "__main__":
    main()
