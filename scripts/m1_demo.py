"""Member 1 demo: runs the full crypto pipeline once and writes a test vector for Member 2."""
import json
import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag

from app.crypto.file_crypto import build_aad, ciphertext_hash, decrypt_file, encrypt_file
from app.crypto.keystore import create_user, load_dek, load_signing_key, save_dek
from app.crypto.signing import file_digest, sign_file, verify_file
from app.storage.storage import StorageClient

CHAIN_ID = 31337
CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
PASSPHRASE = "correct horse battery"
VECTOR_PATH = Path("tests/vectors/sample_vector.json")


def step(ok: bool, text: str) -> None:
    print(("[ok]   " if ok else "[FAIL] ") + text)
    if not ok:
        raise SystemExit(1)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        keys = tmp / "keystores"

        info = create_user("alice", PASSPHRASE, directory=keys)
        owner = info["address"]
        private_key = load_signing_key("alice", PASSPHRASE, directory=keys)
        step(True, f"Created user alice, address {owner}")

        plaintext = b"Hello from the owner. " * 100
        file_id = os.urandom(32)
        aad = build_aad(file_id, owner)
        dek, blob = encrypt_file(plaintext, aad)
        ct_hash = ciphertext_hash(blob)
        step(plaintext not in blob, f"Encrypted {len(plaintext)} bytes into {len(blob)} bytes")

        store = StorageClient(tmp / "blobs")
        storage_id = store.put(blob)
        save_dek("alice", PASSPHRASE, file_id, dek, directory=keys)
        step(True, "Uploaded ciphertext and saved the file key in the vault")

        signature = sign_file(private_key, CHAIN_ID, CONTRACT, file_id, ct_hash, storage_id)
        step(True, "Signed the registration")

        # --- requester side: download, verify, then decrypt ---
        downloaded = store.get(storage_id)
        step(ciphertext_hash(downloaded) == ct_hash, "Ciphertext hash matches")
        step(
            verify_file(owner, signature, CHAIN_ID, CONTRACT, file_id, ct_hash, storage_id),
            "Owner signature is valid",
        )
        recovered = decrypt_file(load_dek("alice", PASSPHRASE, file_id, directory=keys), downloaded, aad)
        step(recovered == plaintext, "Decryption returned the original file")

        # --- attack: the storage provider changes the file ---
        store.tamper(storage_id)
        tampered = store.get(storage_id)
        step(ciphertext_hash(tampered) != ct_hash, "Tampering detected by the hash check")
        try:
            decrypt_file(dek, tampered, aad)
            step(False, "Tampered file should not decrypt")
        except InvalidTag:
            step(True, "Tampered file refused by the GCM tag check")

        VECTOR_PATH.parent.mkdir(parents=True, exist_ok=True)
        VECTOR_PATH.write_text(
            json.dumps(
                {
                    "chain_id": CHAIN_ID,
                    "contract_address": CONTRACT,
                    "owner_address": owner,
                    "file_id": file_id.hex(),
                    "ct_hash": ct_hash.hex(),
                    "storage_id": storage_id.hex(),
                    "digest": file_digest(CHAIN_ID, CONTRACT, file_id, owner, ct_hash, storage_id).hex(),
                    "signature": signature.hex(),
                },
                indent=2,
            )
        )
        step(True, f"Wrote test vector to {VECTOR_PATH}")


if __name__ == "__main__":
    main()