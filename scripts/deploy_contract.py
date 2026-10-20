"""Deploy FileSharing to local Anvil or Sepolia using settings from .env."""

import json
import os
from getpass import getpass
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

from app.crypto.keystore import create_user, get_public_info, user_exists

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_SOURCE_DATA = PROJECT_ROOT / "app" / "blockchain" / "contract_data.json"
LOCAL_CHAIN_ID = 31337
SEPOLIA_CHAIN_ID = 11155111
DEMO_USERS = ("alice", "bob", "mallory")


def _resolve_data_file() -> Path:
    configured = os.getenv("CONTRACT_DATA_FILE")
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else PROJECT_ROOT / path

    network = os.getenv("NETWORK", "local").strip().lower()
    return PROJECT_ROOT / "app" / "blockchain" / f"contract_data.{network}.json"


def _load_contract_template(target: Path) -> dict:
    source = target if target.exists() else DEFAULT_SOURCE_DATA
    if not source.exists():
        raise FileNotFoundError(
            "Contract data is missing. Run: python scripts/export_contract_data.py"
        )
    return json.loads(source.read_text(encoding="utf-8"))


def _tx_options(web3: Web3, account) -> dict:
    options = {
        "from": account.address,
        "nonce": web3.eth.get_transaction_count(account.address, "pending"),
        "chainId": web3.eth.chain_id,
    }
    latest = web3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas")
    if base_fee is not None:
        priority = web3.to_wei(1, "gwei")
        options["maxPriorityFeePerGas"] = priority
        options["maxFeePerGas"] = base_fee * 2 + priority
    else:
        options["gasPrice"] = web3.eth.gas_price
    return options


def _send_value(web3: Web3, account, recipient: str, amount_wei: int):
    tx = _tx_options(web3, account)
    tx.update({"to": Web3.to_checksum_address(recipient), "value": amount_wei, "gas": 21_000})
    signed = account.sign_transaction(tx)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"Funding transaction failed: {tx_hash.hex()}")
    return receipt


def _demo_passphrase(name: str) -> str:
    env_name = f"{name.upper()}_PASSPHRASE"
    value = os.getenv(env_name)
    if value:
        return value
    return getpass(f"Passphrase for demo user {name} (min 8 chars): ")


def _create_and_fund_demo_users(web3: Web3, deployer) -> None:
    amount_eth = os.getenv("DEMO_FUND_ETH", "10")
    amount_wei = web3.to_wei(amount_eth, "ether")

    for name in DEMO_USERS:
        if not user_exists(name):
            create_user(name, _demo_passphrase(name))
            print(f"Created demo user: {name}")
        address = get_public_info(name)["address"]
        if web3.eth.get_balance(address) < amount_wei:
            _send_value(web3, deployer, address, amount_wei)
            print(f"Funded {name}: {address}")
        else:
            print(f"{name} already funded: {address}")


def deploy_contract():
    load_dotenv(ENV_FILE)

    rpc_url = os.getenv("RPC_URL") or os.getenv("SEPOLIA_RPC_URL")
    expected_chain_id = int(os.getenv("CHAIN_ID", "0"))
    deployer_key = os.getenv("DEPLOYER_PRIVATE_KEY")
    network = os.getenv("NETWORK", "local").strip().lower()

    if not rpc_url:
        raise ValueError("RPC_URL is missing from .env")
    if not expected_chain_id:
        raise ValueError("CHAIN_ID is missing from .env")
    if not deployer_key:
        raise ValueError("DEPLOYER_PRIVATE_KEY is missing from .env")

    web3 = Web3(Web3.HTTPProvider(rpc_url))
    if not web3.is_connected():
        raise ConnectionError(f"Could not connect to Ethereum RPC: {rpc_url}")
    if web3.eth.chain_id != expected_chain_id:
        raise ValueError(
            f"Wrong network. Expected chain ID {expected_chain_id}, got {web3.eth.chain_id}"
        )

    deployer = web3.eth.account.from_key(deployer_key)
    if web3.eth.get_balance(deployer.address) == 0:
        raise ValueError("Deployment account has no ETH")

    data_file = _resolve_data_file()
    contract_data = _load_contract_template(data_file)
    abi = contract_data.get("abi")
    bytecode = contract_data.get("bytecode")
    if not abi or not bytecode:
        raise ValueError("Contract ABI/bytecode missing. Run export_contract_data.py first.")

    factory = web3.eth.contract(abi=abi, bytecode=bytecode)
    options = _tx_options(web3, deployer)
    options["gas"] = int(factory.constructor().estimate_gas(options) * 1.2)
    transaction = factory.constructor().build_transaction(options)
    signed = deployer.sign_transaction(transaction)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    if receipt.status != 1:
        raise RuntimeError("Contract deployment failed")

    contract_data.update(
        {
            "address": receipt.contractAddress,
            "chain_id": web3.eth.chain_id,
            "network": network,
            "deployment_tx": tx_hash.hex(),
        }
    )
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text(json.dumps(contract_data, indent=2), encoding="utf-8")

    print(f"Deployed FileSharing to {network}")
    print(f"Contract address: {receipt.contractAddress}")
    print(f"Transaction hash: {tx_hash.hex()}")
    print(f"Contract data: {data_file}")

    if network == "local" or web3.eth.chain_id == LOCAL_CHAIN_ID:
        _create_and_fund_demo_users(web3, deployer)

    return receipt.contractAddress


if __name__ == "__main__":
    deploy_contract()
