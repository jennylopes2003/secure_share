"""
Blockchain client for Secure Share.

Connects the Secure Share Python application to the
FileSharing smart contract deployed on Ethereum Sepolia.
"""

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3


ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACT_DATA_FILE = ROOT / "app" / "blockchain" / "contract_data.json"

DEFAULT_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
SEPOLIA_CHAIN_ID = 11155111


class FileSharingContractClient:
    def __init__(self, rpc_url=None):
        load_dotenv(ROOT / ".env")

        self.rpc_url = (
            rpc_url
            or os.getenv("SEPOLIA_RPC_URL")
            or DEFAULT_RPC_URL
        )

        self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))

        self.contract = None
        self.account = None
        self.contract_data = None

        self._load_contract_data()
        self._load_account()

    def is_connected(self):
        """Return True when connected to Ethereum."""
        return self.web3.is_connected()

    def _load_contract_data(self):
        """Load ABI and deployed contract information."""
        if not CONTRACT_DATA_FILE.exists():
            raise FileNotFoundError(
                f"Contract data not found: {CONTRACT_DATA_FILE}"
            )

        with open(CONTRACT_DATA_FILE, "r", encoding="utf-8") as file:
            self.contract_data = json.load(file)

        address = self.contract_data.get("address")
        abi = self.contract_data.get("abi")

        if address and abi:
            self.contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=abi,
            )

    def _load_account(self):
        """Load the local Sepolia account from the private key in .env."""
        private_key = os.getenv("PRIVATE_KEY")

        if private_key:
            self.account = self.web3.eth.account.from_key(private_key)

    def get_account_address(self):
        """Return the loaded wallet address."""
        if self.account is None:
            return None

        return self.account.address

    def get_contract_address(self):
        """Return the deployed FileSharing contract address."""
        if self.contract is None:
            return None

        return self.contract.address

    def register_file(self, file_id, ct_hash, storage_id, signature):
        """
        Register encrypted-file metadata on the blockchain.

        Solidity signature:
        registerFile(bytes32, bytes32, bytes32, bytes)
        """
        return self._send_transaction(
            self.contract.functions.registerFile(
                file_id,
                ct_hash,
                storage_id,
                signature,
            )
        )

    def request_access(self, file_id):
        """Request access to a registered file."""
        return self._send_transaction(
            self.contract.functions.requestAccess(file_id)
        )

    def approve_request(self, file_id, requester):
        """Approve a user's access request."""
        requester = Web3.to_checksum_address(requester)

        return self._send_transaction(
            self.contract.functions.approveRequest(
                file_id,
                requester,
            )
        )

    def reject_request(self, file_id, requester):
        """Reject a user's access request."""
        requester = Web3.to_checksum_address(requester)

        return self._send_transaction(
            self.contract.functions.rejectRequest(
                file_id,
                requester,
            )
        )

    def grant_access(self, file_id, user):
        """Directly grant access to a user."""
        user = Web3.to_checksum_address(user)

        return self._send_transaction(
            self.contract.functions.grantAccess(
                file_id,
                user,
            )
        )

    def revoke_access(self, file_id, user):
        """Revoke a user's access."""
        user = Web3.to_checksum_address(user)

        return self._send_transaction(
            self.contract.functions.revokeAccess(
                file_id,
                user,
            )
        )

    def has_access(self, file_id, user):
        """Check whether a user has access to a file."""
        self._require_contract()

        user = Web3.to_checksum_address(user)

        return self.contract.functions.hasAccess(
            file_id,
            user,
        ).call()

    def get_file(self, file_id):
        """Retrieve file metadata from the smart contract."""
        self._require_contract()

        return self.contract.functions.getFile(file_id).call()

    def get_access_request(self, file_id, requester):
        """Retrieve an access request and its current status."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        return self.contract.functions.getRequest(
            file_id,
            requester,
        ).call()

    def _require_contract(self):
        """Ensure Sepolia connection and contract configuration are valid."""
        if not self.is_connected():
            raise ConnectionError("Not connected to Ethereum Sepolia.")

        if self.web3.eth.chain_id != SEPOLIA_CHAIN_ID:
            raise RuntimeError(
                f"Wrong Ethereum network. "
                f"Expected Sepolia ({SEPOLIA_CHAIN_ID}), "
                f"got {self.web3.eth.chain_id}."
            )

        if self.contract is None:
            raise RuntimeError(
                "FileSharing contract is not configured/deployed."
            )

    def _require_account(self):
        """Ensure a signing account is available."""
        if self.account is None:
            raise RuntimeError(
                "PRIVATE_KEY is missing from the local .env file."
            )

    def _send_transaction(self, function):
        """Build, sign and send a Sepolia smart-contract transaction."""
        self._require_contract()
        self._require_account()

        nonce = self.web3.eth.get_transaction_count(
            self.account.address
        )

        transaction = function.build_transaction(
            {
                "from": self.account.address,
                "nonce": nonce,
                "chainId": SEPOLIA_CHAIN_ID,
                "gasPrice": self.web3.eth.gas_price,
            }
        )

        transaction["gas"] = self.web3.eth.estimate_gas(transaction)

        signed_transaction = self.account.sign_transaction(transaction)

        tx_hash = self.web3.eth.send_raw_transaction(
            signed_transaction.raw_transaction
        )

        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        if receipt.status != 1:
            raise RuntimeError(
                f"Transaction failed: {tx_hash.hex()}"
            )

        return receipt