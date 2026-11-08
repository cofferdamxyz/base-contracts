// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IZKPassportHelper, IZKPassportRootVerifier} from "../identity/zkpassport/IZKPassportRootVerifier.sol";

/// @notice Test double of ZKPassport's `RootVerifier`. A proof is "valid" when
///         its bytes are `MOCK_PROOF`, its fifth public input commits to the
///         committed inputs (`keccak256`, standing in for the real parameter
///         commitments), its date plus the caller's validity has not passed,
///         and the caller's version and service configuration are the ones
///         set with `setExpected`. Like the real verifier it returns the
///         identifier at `publicInputs[n-2]` and the version's helper.
contract MockZKPassportRootVerifier is IZKPassportRootVerifier {
    bytes32 public constant MOCK_PROOF = keccak256("mock-zkpassport-proof");

    mapping(bytes32 => address) public helpers;
    bytes32 public expectedConfig;

    function setHelper(bytes32 version, address helper) external {
        helpers[version] = helper;
    }

    function setExpected(bytes32 version, uint256 validity, string calldata domain, string calldata scope, bool devMode)
        external
    {
        expectedConfig = keccak256(abi.encode(version, validity, domain, scope, devMode));
    }

    function getHelper(bytes32 version) external view returns (address) {
        return helpers[version];
    }

    function verify(ProofVerificationParams calldata params)
        external
        view
        returns (bool valid, bytes32 uniqueIdentifier, address helper)
    {
        bytes32[] calldata pi = params.proofVerificationData.publicInputs;
        ServiceConfig calldata sc = params.serviceConfig;
        bytes32 config = keccak256(abi.encode(params.version, sc.validityPeriodInSeconds, sc.domain, sc.scope, sc.devMode));
        valid = pi.length >= 8 && keccak256(params.proofVerificationData.proof) == MOCK_PROOF
            && pi[5] == keccak256(params.committedInputs) && config == expectedConfig
            && block.timestamp <= uint256(pi[2]) + sc.validityPeriodInSeconds;
        uniqueIdentifier = pi.length >= 8 ? pi[pi.length - 2] : bytes32(0);
        helper = helpers[params.version];
    }
}

/// @notice Test double of ZKPassport's helper: parses the bind (type 8) and
///         age (type 1) sections of the committed inputs in the layout the
///         SDK writes, `[type:1][length:2][data:length]`. Bound data is
///         `[1][len:2][address]`, `[2][0][len][chain id, big-endian]`,
///         `[3][len:2][utf-8]`, zero-padded.
contract MockZKPassportHelper is IZKPassportHelper {
    function getBoundData(bytes calldata ci) external pure returns (BoundData memory bd) {
        (bool found, uint256 start, uint256 len) = _section(ci, 8);
        require(found, "Bind data proof inputs not found");
        bytes calldata d = ci[start:start + len];
        uint256 i = 0;
        while (i + 3 <= d.length && d[i] != 0) {
            uint8 tag = uint8(d[i]);
            uint256 l = (uint256(uint8(d[i + 1])) << 8) | uint256(uint8(d[i + 2]));
            bytes calldata v = d[i + 3:i + 3 + l];
            if (tag == 1) bd.senderAddress = address(bytes20(v));
            else if (tag == 2) bd.chainId = _uint(v);
            else if (tag == 3) bd.customData = string(v);
            i += 3 + l;
        }
    }

    function isAgeAboveOrEqual(uint8 minAge, bytes calldata ci) external pure returns (bool) {
        (bool found, uint256 start,) = _section(ci, 1);
        return found && uint8(ci[start]) >= minAge;
    }

    function _section(bytes calldata ci, uint8 wanted) private pure returns (bool, uint256, uint256) {
        uint256 i = 0;
        while (i + 3 <= ci.length) {
            uint256 len = (uint256(uint8(ci[i + 1])) << 8) | uint256(uint8(ci[i + 2]));
            if (uint8(ci[i]) == wanted) return (true, i + 3, len);
            i += 3 + len;
        }
        return (false, 0, 0);
    }

    function _uint(bytes calldata v) private pure returns (uint256 x) {
        for (uint256 i = 0; i < v.length; i++) x = (x << 8) | uint8(v[i]);
    }
}
