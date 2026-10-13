"""
Blockchain client for Secure Share.

This module connects the Secure Share Python application
to the FileSharing smart contract.
"""

from web3 import Web3


class FileSharingContractClient:
    def __init__(
        self,
        rpc_url="https://ethereum-sepolia-rpc.publicnode.com"
    ):
        self.rpc_url = rpc_url
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))

        self.contract = None
        self.account = None

    def is_connected(self):
        """
        Check whether the application is connected
        to the Ethereum network.
        """
        return self.web3.is_connected()