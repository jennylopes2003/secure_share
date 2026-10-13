// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FileSharing
 * @notice Blockchain access-control layer for Secure Share.
 * @dev Stores metadata, request state and wrapped-key payloads.
 *      Plaintext files and raw encryption keys must never be stored on-chain.
 */
contract FileSharing {

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
     * Register encrypted-file metadata.
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
     * Approve a pending request and store the wrapped key
     * intended only for that requester.
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
        require(
            requester != address(0),
            "Invalid requester"
        );

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

        emit AccessApproved(
            fileId,
            msg.sender,
            requester
        );
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

        emit AccessRejected(
            fileId,
            msg.sender,
            requester
        );
    }

    /**
     * Revoke previously approved access.
     *
     * Revocation prevents the contract from treating the
     * requester as currently approved. It cannot recover
     * a key that the requester already obtained.
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

        // Remove the on-chain wrapped-key payload from current state.
        delete request.wrappedKey;

        request.updatedAt = block.timestamp;

        emit AccessRevoked(
            fileId,
            msg.sender,
            requester
        );
    }

    /**
     * Return the current request state.
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
     * Return the wrapped key only when access is approved.
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
     * Return request information for integration/testing.
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