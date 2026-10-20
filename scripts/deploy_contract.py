import json
import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_DATA_FILE = (
    PROJECT_ROOT / "app" / "blockchain" / "contract_data.json"
)
ENV_FILE = PROJECT_ROOT / ".env"

SEPOLIA_CHAIN_ID = 11155111


def deploy_contract():
    print("Loading deployment configuration...")

    # Load local environment variables
    load_dotenv(ENV_FILE)

    rpc_url = os.getenv("SEPOLIA_RPC_URL")
    private_key = os.getenv("PRIVATE_KEY")

    if not rpc_url:
        raise ValueError("SEPOLIA_RPC_URL is missing from .env")

    if not private_key:
        raise ValueError("PRIVATE_KEY is missing from .env")

    # Connect to Ethereum
    web3 = Web3(Web3.HTTPProvider(rpc_url))

    if not web3.is_connected():
        raise ConnectionError("Could not connect to Ethereum Sepolia")

    print("Connected to Ethereum Sepolia.")
    print("Chain ID:", web3.eth.chain_id)

    if web3.eth.chain_id != SEPOLIA_CHAIN_ID:
        raise ValueError(
            f"Wrong network. Expected chain ID "
            f"{SEPOLIA_CHAIN_ID}, got {web3.eth.chain_id}"
        )

    # Load deployment account
    account = web3.eth.account.from_key(private_key)

    print("Deployment account:", account.address)

    balance = web3.eth.get_balance(account.address)

    print(
        "Account balance:",
        web3.from_wei(balance, "ether"),
        "ETH",
    )

    if balance == 0:
        raise ValueError("Deployment account has no Sepolia ETH")

    # Load compiled contract
    if not CONTRACT_DATA_FILE.exists():
        raise FileNotFoundError(
            "contract_data.json not found. "
            "Run compile_contract.py first."
        )

    with open(
        CONTRACT_DATA_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        contract_data = json.load(file)

    abi = contract_data.get("abi")
    bytecode = contract_data.get("bytecode")

    if not abi:
        raise ValueError("Contract ABI is missing")

    if not bytecode:
        raise ValueError("Contract bytecode is missing")

    # Create contract factory
    contract = web3.eth.contract(
        abi=abi,
        bytecode=bytecode,
    )

    print("Preparing FileSharing deployment...")

    nonce = web3.eth.get_transaction_count(
        account.address,
        "pending",
    )

    latest_block = web3.eth.get_block("latest")
    base_fee = latest_block.get("baseFeePerGas")

    tx_options = {
        "from": account.address,
        "nonce": nonce,
        "chainId": SEPOLIA_CHAIN_ID,
    }

    # Use EIP-1559 fees when available
    if base_fee is not None:
        priority_fee = web3.to_wei(1, "gwei")

        tx_options["maxPriorityFeePerGas"] = priority_fee
        tx_options["maxFeePerGas"] = (
            base_fee * 2 + priority_fee
        )
    else:
        tx_options["gasPrice"] = web3.eth.gas_price

    # Estimate deployment gas
    estimated_gas = contract.constructor().estimate_gas(
        tx_options
    )

    tx_options["gas"] = int(estimated_gas * 1.2)

    print("Estimated gas:", estimated_gas)

    # Build deployment transaction
    transaction = contract.constructor().build_transaction(
        tx_options
    )

    # Sign transaction locally
    signed_transaction = web3.eth.account.sign_transaction(
        transaction,
        private_key=private_key,
    )

    print("Sending deployment transaction...")

    tx_hash = web3.eth.send_raw_transaction(
        signed_transaction.raw_transaction
    )

    print("Transaction hash:", tx_hash.hex())
    print("Waiting for confirmation...")

    receipt = web3.eth.wait_for_transaction_receipt(
        tx_hash,
        timeout=300,
    )

    if receipt.status != 1:
        raise RuntimeError("Contract deployment failed")

    contract_address = receipt.contractAddress

    print("SUCCESS - FileSharing deployed")
    print("Contract address:", contract_address)
    print("Block number:", receipt.blockNumber)

    # Save deployment information
    contract_data["address"] = contract_address
    contract_data["network"] = "sepolia"
    contract_data["chain_id"] = SEPOLIA_CHAIN_ID
    contract_data["deployment_tx"] = tx_hash.hex()

    with open(
        CONTRACT_DATA_FILE,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(contract_data, file, indent=4)

    print("contract_data.json updated successfully.")


if __name__ == "__main__":
    deploy_contract()