"""Member 1: owner signatures over a file registration.

The signed digest is:
    keccak256(abi.encode(
        DOMAIN_TAG, chainId, contractAddress, fileId, owner, ctHash, storageId))
and it is signed as an EIP-191 "personal message" with ECDSA (secp256k1).

Because chain id, contract address and owner are inside the digest, a signature
cannot be replayed on another chain, another contract, or for another owner.
Member 2 can check it on chain with ecrecover over
keccak256("\\x19Ethereum Signed Message:\\n32" + digest).
"""
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address

DOMAIN_TAG = keccak(text="SecureShare.FileRegistration.v1")


def _require32(name: str, value) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return bytes(value)


def file_digest(
    chain_id: int,
    contract_address: str,
    file_id: bytes,
    owner: str,
    ct_hash: bytes,
    storage_id: bytes,
) -> bytes:
    """The 32-byte value that the owner signs."""
    if not isinstance(chain_id, int) or chain_id < 0:
        raise ValueError("chain_id must be a non-negative integer")
    return keccak(
        encode(
            ["bytes32", "uint256", "address", "bytes32", "address", "bytes32", "bytes32"],
            [
                DOMAIN_TAG,
                chain_id,
                to_checksum_address(contract_address),
                _require32("file_id", file_id),
                to_checksum_address(owner),
                _require32("ct_hash", ct_hash),
                _require32("storage_id", storage_id),
            ],
        )
    )


def address_from_private_key(private_key: bytes) -> str:
    return Account.from_key(private_key).address


def sign_file(
    private_key: bytes,
    chain_id: int,
    contract_address: str,
    file_id: bytes,
    ct_hash: bytes,
    storage_id: bytes,
) -> bytes:
    """Sign a file registration. Returns a 65-byte signature (r, s, v)."""
    owner = address_from_private_key(private_key)
    digest = file_digest(chain_id, contract_address, file_id, owner, ct_hash, storage_id)
    signed = Account.sign_message(encode_defunct(primitive=digest), private_key)
    return bytes(signed.signature)


def verify_file(
    owner_address: str,
    signature: bytes,
    chain_id: int,
    contract_address: str,
    file_id: bytes,
    ct_hash: bytes,
    storage_id: bytes,
) -> bool:
    """True only if `signature` was made by `owner_address` over exactly these values."""
    digest = file_digest(chain_id, contract_address, file_id, owner_address, ct_hash, storage_id)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 65:
        return False
    try:
        recovered = Account.recover_message(encode_defunct(primitive=digest), signature=bytes(signature))
    except Exception:  # malformed signature: treat as invalid, never crash the GUI
        return False
    return recovered == to_checksum_address(owner_address)