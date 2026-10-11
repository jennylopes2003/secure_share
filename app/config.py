"""Shared settings. Keep this file small and agree changes with the whole group."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
BLOB_DIR = DATA_DIR / "blobs"
KEYSTORE_DIR = DATA_DIR / "keystores"
DEPLOYED_JSON = DATA_DIR / "deployed.json"

RPC_URL = "http://127.0.0.1:8545"
CHAIN_ID = 31337  # Anvil's default chain id