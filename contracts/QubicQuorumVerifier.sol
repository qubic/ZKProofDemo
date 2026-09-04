// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// RISC Zero verifier router (https://dev.risczero.com/api/blockchain-integration/contracts/verifier).
interface IRiscZeroVerifier {
    /// Reverts unless `seal` proves that `imageId` committed a journal with sha256 `journalDigest`.
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}

/// @title QubicQuorumVerifier — demo consumer of the zkq-quorum proof.
/// @notice Journal (44 bytes): `epoch u32 LE | queryId u64 LE | K12(reply) 32B`.
///         A recorded (digest, epoch) means >= 451 distinct computors of the arbitrator-signed
///         `epoch` list committed to an oracle reply with `K12(reply) == digest` for `queryId`.
/// @dev Consumers know the reply bytes (revealed on Qubic) and must hash them with K12 themselves.
contract QubicQuorumVerifier {
    IRiscZeroVerifier public immutable ROUTER;
    /// Guest IMAGE_ID; bakes in the arbitrator pubkey. Changing the guest = new contract.
    bytes32 public immutable IMAGE_ID;

    /// digest => epoch => attested.
    mapping(bytes32 digest => mapping(uint32 epoch => bool)) public isAttested;
    /// digest => epoch => oracle queryId the quorum committed for (valid only if attested).
    mapping(bytes32 digest => mapping(uint32 epoch => uint64)) public attestedQueryId;

    event QuorumAttested(bytes32 indexed digest, uint32 indexed epoch, uint64 queryId);

    error BadJournalLength(uint256 length);
    error ZeroEpoch();

    constructor(IRiscZeroVerifier router, bytes32 imageId) {
        ROUTER = router;
        IMAGE_ID = imageId;
    }

    /// @notice Verifies `seal` for `journal` under IMAGE_ID and records (digest, epoch, queryId).
    /// @dev Idempotent: an already attested (digest, epoch) returns without calling the router.
    function attest(bytes calldata journal, bytes calldata seal) external {
        if (journal.length != 44) revert BadJournalLength(journal.length);
        uint32 epoch = uint32(uint8(journal[0])) | (uint32(uint8(journal[1])) << 8)
            | (uint32(uint8(journal[2])) << 16) | (uint32(uint8(journal[3])) << 24);
        uint64 queryId;
        for (uint256 i = 0; i < 8; ++i) {
            queryId |= uint64(uint8(journal[4 + i])) << uint64(8 * i);
        }
        bytes32 digest = bytes32(journal[12:44]);
        if (epoch == 0) revert ZeroEpoch();
        if (isAttested[digest][epoch]) return;

        ROUTER.verify(seal, IMAGE_ID, sha256(journal));

        isAttested[digest][epoch] = true;
        attestedQueryId[digest][epoch] = queryId;
        emit QuorumAttested(digest, epoch, queryId);
    }
}
