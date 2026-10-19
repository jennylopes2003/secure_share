# Member 3 — Secure Key Sharing

From the repository root, in the project's Python environment:

```bash
pip install -r requirements.txt
pip install -e .
python -m pytest tests/test_keywrap.py -q
python scripts/m3_demo.py
```

`wrap_key(dek, recipient_public_key, file_id, owner_address, requester_address)` returns a bytes payload suitable for the Solidity `approveRequest(fileId, requester, wrappedKey)` parameter. `unwrap_key(payload, recipient_private_key, file_id, owner_address, requester_address)` returns the 32-byte AES key.

**Security integration requirement:** The owner must verify a pending, authorised request on-chain **and authenticate the binding of requester's Ethereum address to their X25519 public key** before calling `wrap_key`. This package intentionally does not invent a public-key registry or modify Member 2's contract/client. The on-chain payload is public even if a Solidity getter restricts reads. Revocation cannot erase a key already retrieved by a requester; re-encrypt with a fresh DEK for future confidentiality.