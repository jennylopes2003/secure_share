import json
from pathlib import Path

from solcx import compile_files, install_solc, set_solc_version


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_FILE = PROJECT_ROOT / "contracts" / "FileSharing.sol"
OUTPUT_FILE = PROJECT_ROOT / "app" / "blockchain" / "contract_data.json"

SOLC_VERSION = "0.8.20"


def compile_contract():
    print("Compiling FileSharing.sol...")

    # Install/select Solidity compiler
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)

    # Compile the smart contract
    compiled = compile_files(
        [str(CONTRACT_FILE)],
        output_values=["abi", "bin"],
    )

    # Find FileSharing contract
    contract_key = next(
        key for key in compiled
        if key.endswith(":FileSharing")
    )

    contract = compiled[contract_key]

    # Save ABI and bytecode for the Python blockchain client
    contract_data = {
        "contractName": "FileSharing",
        "abi": contract["abi"],
        "bytecode": contract["bin"],
        "address": None,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(contract_data, file, indent=4)

    print("SUCCESS - FileSharing.sol compiled")
    print(f"Contract data saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    compile_contract()