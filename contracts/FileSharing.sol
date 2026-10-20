
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FileSharing
 * @notice Blockchain access-control layer for Secure Share.
 * @dev File registration signatures must match
 *      app/crypto/signing.py::sign_file.
 */
contract FileSharing {
    bytes32 private constant DOMAIN_TAG =
        keccak256("SecureShare.FileRegistration.v1");

    // secp256k1 curve order divided by two.
    uint256 private constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    enum RequestStatus {
        None,
        Pending,
        Approved,
        Rejected,
        Revoked
    }

    struct FileRecord {
        address owner;
        bytes32 ctHash;
        bytes32 storageId;
        bytes signature;
        uint256 registeredAt;
        bool exists;
    }

    struct AccessRequest {
        RequestStatus status;
        bytes wrappedKey;
        uint256 requestedAt;
        uint256 updatedAt;
    }

    mapping(bytes32 => FileRecord) private files;

    mapping(bytes32 => mapping(address => AccessRequest))
        private accessRequests;

    event FileRegistered(
        bytes32 indexed fileId,
        address indexed owner,
        bytes32 ctHash,
        bytes32 storageId
    );

    event AccessRequested(
        bytes32 indexed fileId,
        address indexed requester
    );

    event AccessApproved(
        bytes32 indexed fileId,
        address indexed owner,
        address indexed requester
    );

    event AccessRejected(
        bytes32 indexed fileId,
        address indexed owner,
        address indexed requester
    );

    event AccessRevoked(
        bytes32 indexed fileId,
        address indexed owner,
        address indexed requester
    );

    modifier fileExists(bytes32 fileId) {
        require(files[fileId].exists, "File does not exist");
        _;
    }

    modifier onlyOwner(bytes32 fileId) {
        require(files[fileId].owner == msg.sender, "Not file owner");
        _;
    }

    /**
     * @dev Reconstruct the digest from signing.py:
     *
     * keccak256(abi.encode(
     *   DOMAIN_TAG,
     *   chainId,
     *   contractAddress,
     *   fileId,
     *   owner,
     *   ctHash,
     *   storageId
     * ))
     *
     * Then apply the EIP-191 personal-message prefix.
     */
    function _registrationMessageHash(
        bytes32 fileId,
        address owner,
        bytes32 ctHash,
        bytes32 storageId
    ) private view returns (bytes32) {
        bytes32 digest = keccak256(
            abi.encode(
                DOMAIN_TAG,
                block.chainid,
                address(this),
                fileId,
                owner,
                ctHash,
                storageId
            )
        );

        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                digest
            )
        );
    }

    /**
     * @dev Recover the signer from a standard 65-byte
     * ECDSA signature in r || s || v format.
     */
    function _recoverSigner(
        bytes32 messageHash,
        bytes calldata signature
    ) private pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        require(
            uint256(s) > 0 &&
                uint256(s) <= SECP256K1_HALF_N,
            "Invalid signature s value"
        );

        require(v == 27 || v == 28, "Invalid signature v value");

        address signer = ecrecover(messageHash, v, r, s);

        require(signer != address(0), "Invalid signature");

        return signer;
    }

    /**
     * Register encrypted-file metadata.
     * The signature must be produced by the transaction sender.
     */
    function registerFile(
        bytes32 fileId,
        bytes32 ctHash,
        bytes32 storageId,
        bytes calldata signature
    ) external {
        require(fileId != bytes32(0), "Invalid file ID");
        require(ctHash != bytes32(0), "Invalid ciphertext hash");
        require(storageId != bytes32(0), "Invalid storage ID");
        require(!files[fileId].exists, "File already registered");

        bytes32 messageHash = _registrationMessageHash(
            fileId,
            msg.sender,
            ctHash,
            storageId
        );

        address signer = _recoverSigner(messageHash, signature);

        require(signer == msg.sender, "Invalid file signature");

        files[fileId] = FileRecord({
            owner: msg.sender,
            ctHash: ctHash,
            storageId: storageId,
            signature: signature,
            registeredAt: block.timestamp,
            exists: true
        });

        emit FileRegistered(
            fileId,
            msg.sender,
            ctHash,
            storageId
        );
    }

    /**
     * Request access to a registered file.
     */
    function requestAccess(
        bytes32 fileId
    ) external fileExists(fileId) {
        require(
            msg.sender != files[fileId].owner,
            "Owner cannot request own file"
        );

        RequestStatus current =
            accessRequests[fileId][msg.sender].status;

        require(
            current == RequestStatus.None,
            "Request already exists"
        );

        accessRequests[fileId][msg.sender] = AccessRequest({
            status: RequestStatus.Pending,
            wrappedKey: "",
            requestedAt: block.timestamp,
            updatedAt: block.timestamp
        });

        emit AccessRequested(fileId, msg.sender);
    }

    /**
     * Approve a pending request and store a wrapped key.
     */
    function approveRequest(
        bytes32 fileId,
        address requester,
        bytes calldata wrappedKey
    )
        external
        fileExists(fileId)
        onlyOwner(fileId)
    {
        require(requester != address(0), "Invalid requester");

        AccessRequest storage request =
            accessRequests[fileId][requester];

        require(
            request.status == RequestStatus.Pending,
            "Request is not pending"
        );

        require(
            wrappedKey.length > 0,
            "Wrapped key cannot be empty"
        );

        request.status = RequestStatus.Approved;
        request.wrappedKey = wrappedKey;
        request.updatedAt = block.timestamp;

        emit AccessApproved(fileId, msg.sender, requester);
    }

    /**
     * Reject a pending request.
     */
    function rejectRequest(
        bytes32 fileId,
        address requester
    )
        external
        fileExists(fileId)
        onlyOwner(fileId)
    {
        AccessRequest storage request =
            accessRequests[fileId][requester];

        require(
            request.status == RequestStatus.Pending,
            "Request is not pending"
        );

        request.status = RequestStatus.Rejected;
        request.updatedAt = block.timestamp;

        emit AccessRejected(fileId, msg.sender, requester);
    }

    /**
     * Revoke an approved request.
     *
     * Revocation changes the on-chain status and deletes
     * the current wrapped-key payload. It cannot recover
     * a key already obtained by a requester.
     */
    function revokeAccess(
        bytes32 fileId,
        address requester
    )
        external
        fileExists(fileId)
        onlyOwner(fileId)
    {
        AccessRequest storage request =
            accessRequests[fileId][requester];

        require(
            request.status == RequestStatus.Approved,
            "Request is not approved"
        );

        request.status = RequestStatus.Revoked;
        delete request.wrappedKey;
        request.updatedAt = block.timestamp;

        emit AccessRevoked(fileId, msg.sender, requester);
    }

    /**
     * Return the current request status.
     */
    function getStatus(
        bytes32 fileId,
        address requester
    )
        external
        view
        fileExists(fileId)
        returns (RequestStatus)
    {
        return accessRequests[fileId][requester].status;
    }

    /**
     * Return the wrapped key to an approved requester.
     */
    function getWrappedKey(
        bytes32 fileId
    )
        external
        view
        fileExists(fileId)
        returns (bytes memory)
    {
        AccessRequest storage request =
            accessRequests[fileId][msg.sender];

        require(
            request.status == RequestStatus.Approved,
            "Access is not approved"
        );

        return request.wrappedKey;
    }

    /**
     * Return registered file metadata.
     */
    function getFile(
        bytes32 fileId
    )
        external
        view
        fileExists(fileId)
        returns (
            address owner,
            bytes32 ctHash,
            bytes32 storageId,
            bytes memory signature,
            uint256 registeredAt
        )
    {
        FileRecord storage record = files[fileId];

        return (
            record.owner,
            record.ctHash,
            record.storageId,
            record.signature,
            record.registeredAt
        );
    }

    /**
     * Return request information.
     */
    function getRequest(
        bytes32 fileId,
        address requester
    )
        external
        view
        fileExists(fileId)
        returns (
            RequestStatus status,
            uint256 requestedAt,
            uint256 updatedAt
        )
    {
        AccessRequest storage request =
            accessRequests[fileId][requester];

        return (
            request.status,
            request.requestedAt,
            request.updatedAt
        );
    }
}
