"""Compile FileSharing.sol and refresh ABI/bytecode without committing an address."""

import json
from pathlib import Path

from solcx import compile_source, install_solc, set_solc_version

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "FileSharing.sol"
DATA_DIR = ROOT / "app" / "blockchain"
BASE_DATA = DATA_DIR / "contract_data.json"
SOLC_VERSION = "0.8.20"


def main():
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)
    compiled = compile_source(SOURCE.read_text(encoding="utf-8"), output_values=["abi", "bin"])
    key = next(k for k in compiled if k.endswith(":FileSharing"))
    abi = compiled[key]["abi"]
    bytecode = compiled[key]["bin"]

    base = json.loads(BASE_DATA.read_text(encoding="utf-8")) if BASE_DATA.exists() else {}
    base.update({"contractName": "FileSharing", "abi": abi, "bytecode": bytecode, "address": None})
    base.pop("chain_id", None)
    base.pop("network", None)
    base.pop("deployment_tx", None)
    BASE_DATA.write_text(json.dumps(base, indent=2), encoding="utf-8")

    # If local/Sepolia deployment files already exist, refresh only code metadata.
    for path in (DATA_DIR / "contract_data.local.json", DATA_DIR / "contract_data.sepolia.json"):
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            data.update({"contractName": "FileSharing", "abi": abi, "bytecode": bytecode})
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    print(f"Updated {BASE_DATA} with {len(abi)} ABI entries; committed address remains null")


if __name__ == "__main__":
    main()
