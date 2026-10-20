
"""Blockchain client for Secure Share.

Supports Sepolia and local Ethereum networks, and allows
each user to sign transactions with their own private key.
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
    """Python integration with the FileSharing smart contract."""

    def __init__(
        self,
        rpc_url=None,
        private_key=None,
        contract_address=None,
        web3=None,
        contract_data_file=None,
    ):
        load_dotenv(ROOT / ".env")

        self.rpc_url = (
            rpc_url
            or os.getenv("SEPOLIA_RPC_URL")
            or DEFAULT_RPC_URL
        )

        # A supplied Web3 instance can use a local EthereumTesterProvider.
        self.web3 = web3 or Web3(Web3.HTTPProvider(self.rpc_url))

        self.contract = None
        self.account = None
        self.contract_data = None

        self.contract_data_file = Path(
            contract_data_file or CONTRACT_DATA_FILE
        )

        self._load_contract_data(contract_address)

        initial_key = (
            private_key
            if private_key is not None
            else os.getenv("PRIVATE_KEY")
        )

        if initial_key:
            self.set_account(initial_key)

    def is_connected(self):
        """Return whether the Ethereum provider is connected."""
        return self.web3.is_connected()

    def _load_contract_data(self, contract_address=None):
        """Load contract ABI and deployed address."""
        if not self.contract_data_file.exists():
            raise FileNotFoundError(
                f"Contract data not found: {self.contract_data_file}"
            )

        with self.contract_data_file.open(
            "r", encoding="utf-8"
        ) as file:
            self.contract_data = json.load(file)

        address = (
            contract_address
            or self.contract_data.get("address")
        )
        abi = self.contract_data.get("abi")

        if not abi:
            raise ValueError("Contract ABI is missing")

        if address:
            self.contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=abi,
            )

    def set_account(self, private_key):
        """Select the private key used for subsequent transactions.

        Never print, log, or commit private keys.
        """
        self.account = self.web3.eth.account.from_key(
            private_key
        )
        return self.account.address

    def get_account_address(self):
        """Return the currently selected wallet address."""
        if self.account is None:
            return None
        return self.account.address

    def get_contract_address(self):
        """Return the configured contract address."""
        if self.contract is None:
            return None
        return self.contract.address

    def get_chain_id(self):
        """Return the connected blockchain's chain ID."""
        self._require_contract()
        return self.web3.eth.chain_id

    def register_file(
        self,
        file_id,
        ct_hash,
        storage_id,
        signature,
        private_key=None,
    ):
        """Register metadata with a valid owner signature.

        The signature must be created using sign_file() with
        this chain ID, contract address, and transaction owner.
        """
        self._require_contract()

        function = self.contract.functions.registerFile(
            file_id,
            ct_hash,
            storage_id,
            signature,
        )
        return self._send_transaction(function, private_key)

    def request_access(self, file_id, enc_pub_key, private_key=None):
        """Request access, sending the requester's 32-byte X25519 public key."""
        self._require_contract()

        function = self.contract.functions.requestAccess(
            file_id,
            enc_pub_key,
        )
        return self._send_transaction(function, private_key)

    def approve_request(
        self,
        file_id,
        requester,
        wrapped_key,
        private_key=None,
    ):
        """Approve a pending request with a wrapped-key payload."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        function = self.contract.functions.approveRequest(
            file_id,
            requester,
            wrapped_key,
        )
        return self._send_transaction(function, private_key)

    def reject_request(
        self,
        file_id,
        requester,
        private_key=None,
    ):
        """Reject a pending request as the file owner."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        function = self.contract.functions.rejectRequest(
            file_id,
            requester,
        )
        return self._send_transaction(function, private_key)

    def revoke_access(
        self,
        file_id,
        requester,
        private_key=None,
    ):
        """Revoke previously approved access as the owner."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        function = self.contract.functions.revokeAccess(
            file_id,
            requester,
        )
        return self._send_transaction(function, private_key)

    def get_file(self, file_id):
        """Retrieve registered file metadata."""
        self._require_contract()
        return self.contract.functions.getFile(file_id).call()

    def get_access_request(self, file_id, requester):
        """Retrieve status and timestamps for an access request."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        return self.contract.functions.getRequest(
            file_id,
            requester,
        ).call()

    def get_enc_pub_key(self, file_id, requester):
        """Return the 32-byte encryption public key the requester submitted."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        return self.contract.functions.getEncPubKey(
            file_id,
            requester,
        ).call()

    
    def get_status(self, file_id, requester):
        """Return the numeric RequestStatus enum value."""
        self._require_contract()

        requester = Web3.to_checksum_address(requester)

        return self.contract.functions.getStatus(
            file_id,
            requester,
        ).call()

    def has_access(self, file_id, user):
        """Check whether a request is currently approved."""
        return self.get_status(file_id, user) == 2

    def get_wrapped_key(self, file_id, requester=None):
        """Retrieve a wrapped key for an approved requester.

        On-chain access is checked using msg.sender. This
        method makes an eth_call using the requester address.
        """
        self._require_contract()

        if requester is None:
            self._require_account()
            requester = self.account.address

        requester = Web3.to_checksum_address(requester)

        return self.contract.functions.getWrappedKey(
            file_id
        ).call({"from": requester})

    def _require_contract(self):
        """Check connection, network, and contract configuration."""
        if not self.is_connected():
            raise ConnectionError(
                "Not connected to the Ethereum provider."
            )

        if self.contract is None:
            raise RuntimeError(
                "FileSharing contract address is not configured."
            )

        configured_chain_id = self.contract_data.get("chain_id")

        if (
            configured_chain_id is not None
            and int(configured_chain_id) != self.web3.eth.chain_id
        ):
            raise RuntimeError(
                "Wrong Ethereum network. "
                f"Expected chain ID {configured_chain_id}, "
                f"got {self.web3.eth.chain_id}."
            )

    def _require_account(self):
        """Ensure a signing account is selected."""
        if self.account is None:
            raise RuntimeError(
                "No signing account configured. "
                "Supply private_key or call set_account()."
            )

    def _send_transaction(self, function, private_key=None):
        """Sign and send a transaction with the specified user key."""
        self._require_contract()

        if private_key is not None:
            account = self.web3.eth.account.from_key(private_key)
        else:
            self._require_account()
            account = self.account

        nonce = self.web3.eth.get_transaction_count(
            account.address,
            "pending",
        )

        transaction_options = {
            "from": account.address,
            "nonce": nonce,
            "chainId": self.web3.eth.chain_id,
            "gasPrice": self.web3.eth.gas_price,
        }

        estimated_gas = function.estimate_gas(
            {"from": account.address}
        )

        transaction_options["gas"] = int(
            estimated_gas * 1.2
        )

        transaction = function.build_transaction(
            transaction_options
        )

        signed_transaction = account.sign_transaction(
            transaction
        )

        tx_hash = self.web3.eth.send_raw_transaction(
            signed_transaction.raw_transaction
        )

        receipt = self.web3.eth.wait_for_transaction_receipt(
            tx_hash
        )

        if receipt.status != 1:
            raise RuntimeError(
                f"Transaction failed: {tx_hash.hex()}"
            )

        return receipt
