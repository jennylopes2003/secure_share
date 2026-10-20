"""Application workflows used by the SecureShare GUI.

The GUI should call this module instead of calling crypto, storage, or
blockchain functions directly. Each workflow returns a Result so the GUI
can show which steps passed and where an operation stopped.
"""

import os
from dataclasses import dataclass, field
from typing import Any

from eth_utils import to_canonical_address
from web3.exceptions import ContractLogicError

try:
    from eth_tester.exceptions import TransactionFailed
except ImportError:  # eth_tester is mainly used by the test environment
    TransactionFailed = ()  # type: ignore

from app.crypto.file_crypto import (
    build_aad,
    ciphertext_hash,
    decrypt_file,
    encrypt_file,
)
from app.crypto.keystore import (
    get_public_info,
    list_files,
    load_dek,
    load_enc_private_key,
    load_signing_key,
    save_dek,
)
from app.crypto.keywrap import fingerprint, unwrap_key, wrap_key
from app.crypto.signing import sign_file, verify_file
from app.storage.storage import StorageClient


STATUS_NAMES = {
    0: "None",
    1: "Pending",
    2: "Approved",
    3: "Rejected",
    4: "Revoked",
}


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Result:
    ok: bool
    steps: list[StepResult] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""


def _ok(steps, data=None):
    return Result(True, steps, data or {}, "")


def _fail(steps, name, error):
    message = _friendly_error(error)
    steps.append(StepResult(name, False, message))
    return Result(False, steps, {}, message)


def _friendly_error(error):
    """Turn common backend errors into messages suitable for the GUI."""
    message = str(error).strip() or error.__class__.__name__
    lower = message.lower()

    if "not file owner" in lower:
        return "Not file owner"
    if "wrong passphrase" in lower or "mac mismatch" in lower:
        return "Wrong passphrase"
    if "hash mismatch" in lower:
        return "Ciphertext hash mismatch"
    if "invalidtag" in lower or "authentication" in lower:
        return "Authentication failed"
    if "file does not exist" in lower:
        return "File does not exist"
    if "request is not pending" in lower:
        return "Request is not pending"
    if "request already exists" in lower:
        return "Request already exists"

    return message


def _context(file_id, owner, requester):
    """Bind a wrapped key to one file, owner, and requester."""
    if not isinstance(file_id, (bytes, bytearray)) or len(file_id) != 32:
        raise ValueError("file_id must be exactly 32 bytes")
    return (
        bytes(file_id)
        + to_canonical_address(owner)
        + to_canonical_address(requester)
    )


def _event_args(event):
    """Return event arguments from either a Web3 event object or a dict."""
    if hasattr(event, "get"):
        return event.get("args", event)
    return getattr(event, "args", {})


def _receipt_detail(receipt):
    tx_hash = getattr(receipt, "transactionHash", None)
    if tx_hash is None and hasattr(receipt, "get"):
        tx_hash = receipt.get("transactionHash")
    if tx_hash is not None:
        return f"Transaction confirmed: {tx_hash.hex()}"
    return "Transaction confirmed"


def protect_and_register(client, user, passphrase, file_bytes):
    steps = []

    try:
        public = get_public_info(user)
        owner = public["address"]
        file_id = os.urandom(32)
        aad = build_aad(file_id, owner)
        steps.append(StepResult("Prepare file", True, "File ID and AAD created"))
    except Exception as exc:
        return _fail(steps, "Prepare file", exc)

    try:
        dek, blob = encrypt_file(file_bytes, aad)
        ct_hash = ciphertext_hash(blob)
        steps.append(StepResult("Encrypt file", True, "File encrypted with AES-256-GCM"))
    except Exception as exc:
        return _fail(steps, "Encrypt file", exc)

    try:
        storage = StorageClient()
        storage_id = storage.put(blob)
        steps.append(StepResult("Store ciphertext", True, "Encrypted file stored"))
    except Exception as exc:
        return _fail(steps, "Store ciphertext", exc)

    try:
        private_key = load_signing_key(user, passphrase)
        signature = sign_file(
            private_key,
            client.get_chain_id(),
            client.get_contract_address(),
            file_id,
            ct_hash,
            storage_id,
        )
        steps.append(StepResult("Sign registration", True, "File metadata signed"))
    except Exception as exc:
        return _fail(steps, "Sign registration", exc)

    try:
        # Save before the blockchain transaction. If the transaction fails,
        # the locally generated file key is not lost.
        save_dek(user, passphrase, file_id, dek)
        steps.append(StepResult("Save file key", True, "File key saved in the encrypted vault"))
    except Exception as exc:
        return _fail(steps, "Save file key", exc)

    try:
        receipt = client.register_file(
            file_id,
            ct_hash,
            storage_id,
            signature,
            private_key=private_key,
        )
        steps.append(StepResult("Register file", True, _receipt_detail(receipt)))
    except (ContractLogicError, TransactionFailed, Exception) as exc:
        return _fail(steps, "Register file", exc)

    return _ok(steps, {"file_id": file_id})


def request_access(client, user, passphrase, file_id):
    steps = []

    try:
        public = get_public_info(user)
        enc_pub_key = public["enc_public_key"]
        steps.append(StepResult("Load encryption key", True, "Encryption public key loaded"))
    except Exception as exc:
        return _fail(steps, "Load encryption key", exc)

    try:
        private_key = load_signing_key(user, passphrase)
        receipt = client.request_access(
            file_id,
            enc_pub_key,
            private_key=private_key,
        )
        steps.append(StepResult("Request access", True, _receipt_detail(receipt)))
    except (ContractLogicError, TransactionFailed, Exception) as exc:
        return _fail(steps, "Request access", exc)

    return _ok(steps)


def list_requests(client, file_id):
    steps = []

    if not hasattr(client, "get_events"):
        return _fail(
            steps,
            "Read requests",
            "Blockchain client does not provide get_events(); complete Item 3 event support first.",
        )

    try:
        events = client.get_events("AccessRequested", from_block=0, fileId=file_id)
        requests = []

        for event in events:
            args = _event_args(event)
            requester = args["requester"]
            enc_pub_key = bytes(args["encPubKey"])
            status_value = client.get_status(file_id, requester)

            requests.append(
                {
                    "requester": requester,
                    "status": STATUS_NAMES.get(status_value, str(status_value)),
                    "enc_pub_key": enc_pub_key,
                    "fingerprint": fingerprint(enc_pub_key),
                }
            )

        steps.append(
            StepResult("Read requests", True, f"{len(requests)} request(s) found")
        )
        return _ok(steps, {"requests": requests})
    except Exception as exc:
        return _fail(steps, "Read requests", exc)


def approve(client, user, passphrase, file_id, requester):
    steps = []

    try:
        owner_info = get_public_info(user)
        owner = owner_info["address"]
        dek = load_dek(user, passphrase, file_id)
        steps.append(StepResult("Load file key", True, "File key loaded from the vault"))
    except Exception as exc:
        return _fail(steps, "Load file key", exc)

    try:
        enc_pub_key = bytes(client.get_enc_pub_key(file_id, requester))
        key_fingerprint = fingerprint(enc_pub_key)
        steps.append(
            StepResult(
                "Check requester key",
                True,
                f"Requester key fingerprint: {key_fingerprint}",
            )
        )
    except Exception as exc:
        return _fail(steps, "Check requester key", exc)

    try:
        context = _context(file_id, owner, requester)
        wrapped_key = wrap_key(dek, enc_pub_key, context)
        steps.append(StepResult("Wrap file key", True, "File key wrapped for requester"))
    except Exception as exc:
        return _fail(steps, "Wrap file key", exc)

    try:
        private_key = load_signing_key(user, passphrase)
        receipt = client.approve_request(
            file_id,
            requester,
            wrapped_key,
            private_key=private_key,
        )
        steps.append(StepResult("Approve request", True, _receipt_detail(receipt)))
    except (ContractLogicError, TransactionFailed, Exception) as exc:
        return _fail(steps, "Approve request", exc)

    return _ok(steps, {"fingerprint": key_fingerprint})


def reject(client, user, passphrase, file_id, requester):
    steps = []
    try:
        private_key = load_signing_key(user, passphrase)
        receipt = client.reject_request(
            file_id,
            requester,
            private_key=private_key,
        )
        steps.append(StepResult("Reject request", True, _receipt_detail(receipt)))
        return _ok(steps)
    except (ContractLogicError, TransactionFailed, Exception) as exc:
        return _fail(steps, "Reject request", exc)


def revoke(client, user, passphrase, file_id, requester):
    steps = []
    try:
        private_key = load_signing_key(user, passphrase)
        receipt = client.revoke_access(
            file_id,
            requester,
            private_key=private_key,
        )
        steps.append(StepResult("Revoke access", True, _receipt_detail(receipt)))
        return _ok(steps)
    except (ContractLogicError, TransactionFailed, Exception) as exc:
        return _fail(steps, "Revoke access", exc)


def fetch_verify_decrypt(client, user, passphrase, file_id):
    steps = []

    try:
        record = client.get_file(file_id)
        owner, on_chain_hash, storage_id, signature, _registered_at = record
        steps.append(StepResult("Get file record", True, "On-chain metadata loaded"))
    except Exception as exc:
        return _fail(steps, "Get file record", exc)

    try:
        storage = StorageClient()
        blob = storage.get(storage_id)
        steps.append(StepResult("Fetch ciphertext", True, "Encrypted file loaded from storage"))
    except Exception as exc:
        return _fail(steps, "Fetch ciphertext", exc)

    try:
        actual_hash = ciphertext_hash(blob)
        if actual_hash != bytes(on_chain_hash):
            raise ValueError("Ciphertext hash mismatch")
        steps.append(StepResult("Check ciphertext hash", True, "Ciphertext matches the on-chain hash"))
    except Exception as exc:
        return _fail(steps, "Check ciphertext hash", exc)

    try:
        valid = verify_file(
            owner,
            bytes(signature),
            client.get_chain_id(),
            client.get_contract_address(),
            file_id,
            bytes(on_chain_hash),
            bytes(storage_id),
        )
        if not valid:
            raise ValueError("File signature verification failed")
        steps.append(StepResult("Verify signature", True, "Owner signature is valid"))
    except Exception as exc:
        return _fail(steps, "Verify signature", exc)

    try:
        requester_info = get_public_info(user)
        requester = requester_info["address"]
        wrapped_key = bytes(client.get_wrapped_key(file_id, requester=requester))
        steps.append(StepResult("Get wrapped key", True, "Wrapped file key loaded"))
    except Exception as exc:
        return _fail(steps, "Get wrapped key", exc)

    try:
        enc_private = load_enc_private_key(user, passphrase)
        context = _context(file_id, owner, requester)
        dek = unwrap_key(wrapped_key, enc_private, context)
        steps.append(StepResult("Unwrap file key", True, "File key recovered"))
    except Exception as exc:
        return _fail(steps, "Unwrap file key", exc)

    try:
        aad = build_aad(file_id, owner)
        plaintext = decrypt_file(dek, blob, aad)
        steps.append(StepResult("Decrypt file", True, "File decrypted successfully"))
    except Exception as exc:
        return _fail(steps, "Decrypt file", exc)

    return _ok(steps, {"plaintext": plaintext})


def get_audit_log(client):
    steps = []

    if not hasattr(client, "get_events"):
        return _fail(
            steps,
            "Read audit log",
            "Blockchain client does not provide get_events(); complete Item 3 event support first.",
        )

    try:
        names = [
            "FileRegistered",
            "AccessRequested",
            "AccessApproved",
            "AccessRejected",
            "AccessRevoked",
        ]
        events = []

        for name in names:
            for event in client.get_events(name, from_block=0):
                args = dict(_event_args(event))
                events.append(
                    {
                        "event": name,
                        "args": args,
                        "block_number": (
                            event.get("blockNumber")
                            if hasattr(event, "get")
                            else getattr(event, "blockNumber", None)
                        ),
                        "transaction_hash": (
                            event.get("transactionHash")
                            if hasattr(event, "get")
                            else getattr(event, "transactionHash", None)
                        ),
                    }
                )

        events.sort(key=lambda item: item["block_number"] or 0)
        steps.append(StepResult("Read audit log", True, f"{len(events)} event(s) found"))
        return _ok(steps, {"events": events})
    except Exception as exc:
        return _fail(steps, "Read audit log", exc)


def demo_tamper(client, file_id):
    """DEMO ONLY: modify the stored ciphertext for a registered file."""
    steps = []

    try:
        record = client.get_file(file_id)
        storage_id = record[2]
        StorageClient().tamper(storage_id)
        steps.append(
            StepResult(
                "Tamper stored ciphertext",
                True,
                "One bit was changed for the integrity-check demonstration",
            )
        )
        return _ok(steps)
    except Exception as exc:
        return _fail(steps, "Tamper stored ciphertext", exc)


def list_my_files(client, user):
    steps = []
    try:
        file_ids = list_files(user)
        steps.append(StepResult("List files", True, f"{len(file_ids)} file(s) found"))
        return _ok(steps, {"files": file_ids})
    except Exception as exc:
        return _fail(steps, "List files", exc)


def list_my_requests(client, user):
    steps = []

    if not hasattr(client, "get_events"):
        return _fail(
            steps,
            "List my requests",
            "Blockchain client does not provide get_events(); complete Item 3 event support first.",
        )

    try:
        address = get_public_info(user)["address"]
        events = client.get_events("AccessRequested", from_block=0, requester=address)
        requests = []

        for event in events:
            args = _event_args(event)
            file_id = bytes(args["fileId"])
            status_value = client.get_status(file_id, address)
            requests.append(
                {
                    "file_id": file_id,
                    "status": STATUS_NAMES.get(status_value, str(status_value)),
                }
            )

        steps.append(
            StepResult("List my requests", True, f"{len(requests)} request(s) found")
        )
        return _ok(steps, {"requests": requests})
    except Exception as exc:
        return _fail(steps, "List my requests", exc)
