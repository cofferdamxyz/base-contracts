// SPDX-License-Identifier: Apache-2.0
// Copyright © 2026 ZKPassport
//
// Ported from ZKPassport's registry contracts (zkpassport-packages at 97576ab,
// packages/registry-contracts/src/SubVerifier.sol and lib/DateUtils.sol),
// licensed under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0). Modified by Cofferdam Inc. in
// 2026, as listed in the NatSpec below. Distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

pragma solidity 0.8.28;

/// @title ZKPassportSubVerifierChecks
/// @notice The checks of ZKPassport's `SubVerifier.verify` that
///         `CofferdamZKPassportPepperAdapter` repeats, ported as pure helpers
///         so the adapter can call ZKPassport's outer-proof verifier directly
///         (decision 0080, the pepper). Only this file carries ZKPassport's
///         code; the adapter around it is Cofferdam's (MIT).
/// @dev    Changes from the original:
///         - `isDateValid` is `DateUtils.isDateValid`, unchanged.
///         - `scopeHash` is the hash `SubVerifier._verifyScopes` compares each
///           scope with, taken out so the adapter computes it once, at
///           deployment.
///         - `committedInputsMatch` is `SubVerifier._verifyCommittedInputs`
///           over `bytes memory` with the commitments given as a range of the
///           public inputs; it returns false where the original reverts (a
///           mismatch, a section running past the end, a count that differs).
library ZKPassportSubVerifierChecks {
    /// @notice `DateUtils.isDateValid`: the proof's date is not in the future
    ///         and `validityPeriodInSeconds` has not run out since it.
    function isDateValid(uint256 timestamp, uint256 validityPeriodInSeconds) internal view returns (bool) {
        uint256 validityPeriodTimestamp = timestamp + validityPeriodInSeconds;
        return block.timestamp >= timestamp && validityPeriodTimestamp > timestamp
            && validityPeriodTimestamp > block.timestamp;
    }

    /// @notice The public input a scope (the domain) or subscope (the service
    ///         scope) must equal: its SHA-256 with one byte dropped, or 0 when
    ///         empty (`SubVerifier._verifyScopes`).
    function scopeHash(string memory s) internal pure returns (bytes32) {
        // One byte is dropped at the end
        return bytes(s).length == 0 ? bytes32(0) : sha256(abi.encodePacked(s)) >> 8;
    }

    /// @notice `SubVerifier._verifyCommittedInputs`: each committed-input
    ///         section `[type:1][length:2][data:length]`, hashed whole with
    ///         SHA-256 and one byte dropped, equals the next parameter
    ///         commitment `publicInputs[from..to)`, and sections and
    ///         commitments run out together.
    function committedInputsMatch(bytes32[] memory publicInputs, uint256 from, uint256 to, bytes memory committedInputs)
        internal
        view
        returns (bool)
    {
        uint256 offset = 0;
        uint256 index = from;
        while (offset < committedInputs.length && index < to) {
            if (offset + 3 > committedInputs.length) return false;
            uint256 length = (uint256(uint8(committedInputs[offset + 1])) << 8) | uint256(uint8(committedInputs[offset + 2]));
            if (offset + 3 + length > committedInputs.length) return false;
            // One byte is dropped inside the circuit as BN254 is limited to 254 bits
            // We also add 3 bytes to take into account the proof type and length
            bytes32 calculatedCommitment = _sha256(committedInputs, offset, length + 3) >> 8;
            if (calculatedCommitment != publicInputs[index]) return false;
            offset += length + 3;
            index++;
        }
        // Check that all the committed inputs have been covered, otherwise something is wrong
        return offset == committedInputs.length && index == to;
    }

    /// @dev SHA-256 of `data[start:start + len]`, through the precompile, without a copy.
    function _sha256(bytes memory data, uint256 start, uint256 len) private view returns (bytes32 digest) {
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 0x02, add(add(data, 0x20), start), len, 0x00, 0x20)
            digest := mload(0x00)
        }
        require(ok);
    }
}
