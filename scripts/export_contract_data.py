"""Recompile contracts/FileSharing.sol and refresh the ABI and bytecode in contract_data.json."""
import json
from pathlib import Path

from solcx import compile_source, install_solc, set_solc_version

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "FileSharing.sol"
DATA = ROOT / "app" / "blockchain" / "contract_data.json"
SOLC_VERSION = "0.8.20"


def main():
    install_solc(SOLC_VERSION)
    set_solc_version(SOLC_VERSION)

    compiled = compile_source(
        SOURCE.read_text(encoding="utf-8"),
        output_values=["abi", "bin"],
    )
    key = next(k for k in compiled if k.endswith(":FileSharing"))

    data = json.loads(DATA.read_text(encoding="utf-8")) if DATA.exists() else {}
    data["contractName"] = "FileSharing"
    data["abi"] = compiled[key]["abi"]
    data["bytecode"] = compiled[key]["bin"]

    DATA.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Updated {DATA} with {len(data['abi'])} ABI entries")


if __name__ == "__main__":
    main()